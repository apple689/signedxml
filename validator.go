package signedxml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/beevik/etree"
)

// Validator provides options for verifying a signed XML document
type Validator struct {
	Certificates   []x509.Certificate
	idpMetaDataUrl string
	signatureData
}

// NewValidator returns a *Validator for the XML provided
func NewValidator(xml string, idpMetaDataUrl string) (*Validator, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(xml)
	if err != nil {
		return nil, err
	}
	v := &Validator{signatureData: signatureData{xml: doc}, idpMetaDataUrl: idpMetaDataUrl}
	return v, nil
}

// SetReferenceIDAttribute set the referenceIDAttribute
func (v *Validator) SetReferenceIDAttribute(refIDAttribute string) {
	v.signatureData.refIDAttribute = refIDAttribute
}

// SetXML is used to assign the XML document that the Validator will verify
func (v *Validator) SetXML(xml string) error {
	doc := etree.NewDocument()
	err := doc.ReadFromString(xml)
	v.xml = doc
	return err
}

// Validate validates the Reference digest values, and the signature value
// over the SignedInfo.
//
// Deprecated: Use ValidateReferences instead
func (v *Validator) Validate() error {
	_, err := v.ValidateResponse()
	return err
}

// ValidateResponse validates the Reference digest values, and the signature value
// over the SignedInfo.
//
// If the signature is enveloped in the XML, then it will be used.
// Otherwise, an external signature should be assigned using
// Validator.SetSignature.
//
// The references returned by this method can be used to verify what was signed.
func (v *Validator) ValidateResponse() ([]string, error) {
	if err := v.loadValuesFromXML(); err != nil {
		return nil, err
	}

	if err := v.validateTimeAndStatus(); err != nil {
		return nil, err
	}

	referenced, err := v.validateReferences()
	if err != nil {
		return nil, err
	}

	var ref []string
	for _, doc := range referenced {
		docStr, err := doc.WriteToString()
		if err != nil {
			return nil, err
		}
		ref = append(ref, docStr)
	}

	err = v.validateSignature()
	return ref, err
}

func (v *Validator) loadValuesFromXML() error {
	if v.signature == nil {
		if err := v.parseEnvelopedSignature(); err != nil {
			return err
		}
	}
	if err := v.parseSignedInfo(); err != nil {
		return err
	}
	if err := v.parseSigValue(); err != nil {
		return err
	}
	if err := v.parseSigAlgorithm(); err != nil {
		return err
	}
	if err := v.parseCanonAlgorithm(); err != nil {
		return err
	}
	if err := v.loadCertificate(); err != nil {
		return err
	}
	return nil
}

func containCert(roots []x509.Certificate, cert *x509.Certificate) bool {
	for _, root := range roots {
		if root.Equal(cert) {
			return true
		}
	}
	return false
}

const (
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	MaxDelay      = time.Second * 90
)

func (v *Validator) validateTimeAndStatus() error {
	// First check whether the IdpCert contains the current certificate
	// if not, go to get the certificate in the metadata to update the value of IdpCert
	// then compare again
	if !containCert(IdpCert, &v.certificate) {
		err := v.SetIdpCertAndValidatorCerts()
		if err != nil {
			return fmt.Errorf("signedxml: validateTimeAndStatus error %v", err)
		}
		if !containCert(IdpCert, &v.certificate) {
			return fmt.Errorf("signedxml: validateTimeAndStatus cert not trusted")
		}
	}

	now := time.Now()
	// check whether the certificate has expired
	if now.Before(v.certificate.NotBefore) || now.After(v.certificate.NotAfter) {
		return fmt.Errorf("signedxml: validateTimeAndStatus certificate expired")
	}

	// check whether Response has expired
	resElement := v.xml.FindElement(".//Response")
	if resElement != nil{
		resIssueInstant := resElement.SelectAttrValue("IssueInstant","")
		if resIssueInstant != ""{
			resTime, _ := time.Parse(time.RFC3339, resIssueInstant)
			if resTime.Add(MaxDelay).Before(now) {
				return fmt.Errorf("signedxml: validateTimeAndStatus response IssueInstant expired")
			}
		}
	}

	// check whether SubjectConfirmationData has expired
	subConfDataElement := v.xml.FindElement(".//SubjectConfirmationData")
	if subConfDataElement != nil{
		subNotOnOrAfter := subConfDataElement.SelectAttrValue("NotOnOrAfter","")
		if subNotOnOrAfter != ""{
			subTime, _ := time.Parse(time.RFC3339, subNotOnOrAfter)
			if subTime.Add(MaxDelay).Before(now) {
				return fmt.Errorf("signedxml: validateTimeAndStatus SubjectConfirmationData expired")
			}
		}
	}

	// check whether AuthnStatement has expired
	authnStateElement := v.xml.FindElement(".//AuthnStatement")
	if authnStateElement != nil{
		sessionNotOnOrAfter := authnStateElement.SelectAttrValue("SessionNotOnOrAfter","")
		if sessionNotOnOrAfter != ""{
			sessionTime, _ := time.Parse(time.RFC3339, sessionNotOnOrAfter)
			if sessionTime.Add(MaxDelay).Before(now) {
				return fmt.Errorf("signedxml: validateTimeAndStatus AuthnStatement expired")
			}
		}
	}

	// check whether the StatusCode is success
	statusCodeElement := v.xml.FindElement(".//StatusCode")
	if statusCodeElement != nil{
		statusCode := statusCodeElement.SelectAttrValue("Value", "")
		if statusCode != StatusSuccess {
			return fmt.Errorf("signedxml: validateTimeAndStatus saml response StatusCode not success")
		}
	}

	return nil
}

func (v *Validator) validateReferences() (referenced []*etree.Document, err error) {
	references := v.signedInfo.FindElements("./Reference")
	for _, ref := range references {
		doc := v.xml.Copy()
		transforms := ref.SelectElement("Transforms")
		for _, transform := range transforms.SelectElements("Transform") {
			doc, err = processTransform(transform, doc)
			if err != nil {
				return nil, err
			}
		}

		doc, err = v.getReferencedXML(ref, doc)
		if err != nil {
			return nil, err
		}

		referenced = append(referenced, doc)

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return nil, errors.New("signedxml: unable to find DigestValue")
		}
		digestValue := digestValueElement.Text()

		calculatedValue, err := calculateHash(ref, doc)
		if err != nil {
			return nil, err
		}

		if calculatedValue != digestValue {
			return nil, fmt.Errorf("signedxml: Calculated digest does not match the"+
				" expected digestvalue of %s", digestValue)
		}
	}
	return referenced, nil
}

func (v *Validator) validateSignature() error {
	doc := etree.NewDocument()
	doc.SetRoot(v.signedInfo.Copy())
	signedInfo, err := doc.WriteToString()
	if err != nil {
		return err
	}

	canonSignedInfo, err := v.canonAlgorithm.Process(signedInfo, "")
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(v.sigValue)
	if err != nil {
		return err
	}

	err = v.certificate.CheckSignature(v.sigAlgorithm, []byte(canonSignedInfo), sig)
	if err != nil {
		return fmt.Errorf("signedxml: check signature error :%v", err)
	}
	return nil
}

func (v *Validator) loadCertificate() error {
	// load the cert in Signature
	cert := v.xml.FindElement(".//X509Certificate")
	if cert != nil {
		cert, err := getCertFromPEMString(cert.Text())
		if err != nil {
			return fmt.Errorf("signedxml: load certificate parse cert error :%v", err)
		}
		v.certificate = *cert
	} else {
		return errors.New("signedxml: response without certificate")
	}
	return nil
}

var IdpCert []x509.Certificate

// If v.Certificates is already populated, then the client has already set it to the desired cert.
// Otherwise, let's pull the public keys from the metadata
// set IdpCert equal to v.Certificates
func (v *Validator) SetIdpCertAndValidatorCerts() error {
	if v.idpMetaDataUrl == "" {
		IdpCert = v.Certificates
		return nil
	}
	// get metadata
	res, err := http.Get(v.idpMetaDataUrl)
	if err != nil {
		return fmt.Errorf("signedxml: GetIdpCert get metadata http error :%v", err)
	}

	bytesMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("signedxml: GetIdpCert read metadata error :%v", err)
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes(bytesMetadata)
	if err != nil {
		return fmt.Errorf("signedxml: GetIdpCert read from bytes error :%v", err)
	}

	idpCerts := doc.FindElements(".//X509Certificate")

	for _, certElement := range idpCerts {
		cert, err := getCertFromPEMString(certElement.Text())
		if err != nil {
			log.Printf("signedxml: Unable to load certificate: (%s). "+"Looking for another cert.", err)
		} else {
			v.Certificates = append(v.Certificates, *cert)
		}

		IdpCert = append(IdpCert, *cert)
	}
	return nil
}
