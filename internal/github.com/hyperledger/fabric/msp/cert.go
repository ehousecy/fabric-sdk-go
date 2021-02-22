/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package msp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	sm2 "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/pkg/common"
	"math/big"
	"reflect"
	"time"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
)

type ICertificate interface {
	IsCA() bool
	Raw() []byte
	ExpiresAt() time.Time
	Subject() pkix.Name
	Equal(other ICertificate) bool
	Verify(opts interface{}) ([][]ICertificate, error)
	SerialNumber() *big.Int
	SKI() ([]byte, error)
	CheckCRLSignature(crl *pkix.CertificateList) error
	Get() interface{}
}

type Certificate struct {
	cert interface{}
}

func (c *Certificate) IsCA() bool {
	if c.cert == nil {
		return false
	}
	switch c.cert.(type) {
	case *x509.Certificate:
		return c.cert.(*x509.Certificate).IsCA
	case *sm2.Certificate:
		return c.cert.(*sm2.Certificate).IsCA
	default:
		panic("UnSupport certificate type")
	}
}

func (c *Certificate) Raw() []byte {
	if c.cert == nil {
		return nil
	}
	switch c.cert.(type) {
	case *x509.Certificate:
		return c.cert.(*x509.Certificate).Raw
	case *sm2.Certificate:
		return c.cert.(*sm2.Certificate).Raw
	default:
		panic("UnSupport certificate type")
	}
}

func (c *Certificate) ExpiresAt() time.Time {

	switch c.cert.(type) {
	case *x509.Certificate:
		return c.cert.(*x509.Certificate).NotAfter
	case *sm2.Certificate:
		return c.cert.(*sm2.Certificate).NotAfter
	default:
		panic("UnSupport certificate type")
	}
}

func (c *Certificate) Subject() pkix.Name {

	switch c.cert.(type) {
	case *x509.Certificate:
		return c.cert.(*x509.Certificate).Subject
	case *sm2.Certificate:
		return c.cert.(*sm2.Certificate).Subject
	default:
		panic("UnSupport certificate type")
	}
}

func (c *Certificate) Equal(other ICertificate) bool {
	return bytes.Equal(c.Raw(), other.Raw())
}

func (c *Certificate) Verify(opts interface{}) ([][]ICertificate, error) {
	if !common.IsSM2Certificate(c.Raw(), false) {
		chains, err := c.cert.(*x509.Certificate).Verify(opts.(x509.VerifyOptions))
		if err != nil {
			return nil, err
		}
		var chain = make([][]ICertificate, len(chains))

		for i, certs := range chains {
			var tmp = make([]ICertificate, len(certs))
			for j, cert := range certs {
				tmp[j] = NewCertificate(cert)
			}
			chain[i] = tmp
		}
		return chain, nil
	} else {
		chains, err := common.ParseX509Certificate2Sm2(c.cert.(*x509.Certificate)).Verify(opts.(sm2.VerifyOptions))
		if err != nil {
			return nil, err
		}
		var chain = make([][]ICertificate, len(chains))

		for i, certs := range chains {
			var tmp = make([]ICertificate, len(certs))
			for j, cert := range certs {
				tmp[j] = NewCertificate(cert)
			}
			chain[i] = tmp
		}
		return chain, nil
	}
}

func (c *Certificate) SerialNumber() *big.Int {
	switch c.cert.(type) {
	case *x509.Certificate:
		return c.cert.(*x509.Certificate).SerialNumber
	case *sm2.Certificate:
		return c.cert.(*sm2.Certificate).SerialNumber
	default:
		panic("UnSupport certificate type")
	}
}

func (c *Certificate) SKI() ([]byte, error) {
	var SKI []byte

	switch c.cert.(type) {
	case *x509.Certificate:
		cert := c.cert.(*x509.Certificate)
		for _, ext := range cert.Extensions {
			// Subject Key Identifier is identified by the following ASN.1 tag
			// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
			if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
				_, err := asn1.Unmarshal(ext.Value, &SKI)
				if err != nil {
					return nil, errors.Wrap(err, "failed to unmarshal Subject Key Identifier")
				}
				return SKI, nil
			}
		}
	case *sm2.Certificate:
		cert := c.cert.(*sm2.Certificate)
		for _, ext := range cert.Extensions {
			// Subject Key Identifier is identified by the following ASN.1 tag
			// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
			if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
				_, err := asn1.Unmarshal(ext.Value, &SKI)
				if err != nil {
					return nil, errors.Wrap(err, "failed to unmarshal Subject Key Identifier")
				}
				return SKI, nil
			}
		}
	default:
		panic("UnSupport certificate type")
	}

	return nil, errors.New("subjectKeyIdentifier not found in certificate")
}

func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) error {
	switch c.cert.(type) {
	case *x509.Certificate:
		return c.cert.(*x509.Certificate).CheckCRLSignature(crl)
	case *sm2.Certificate:
		return c.cert.(*sm2.Certificate).CheckCRLSignature(crl)
	default:
		panic("UnSupport certificate type")
	}
}

func (c *Certificate) Get() interface{} {
	return c.cert
}

func NewCertificate(cert interface{}) ICertificate {
	return &Certificate{
		cert: cert,
	}
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func isECDSASignedCert(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA512
}

// sanitizeECDSASignedCert checks that the signatures signing a cert
// is in low-S. This is checked against the public key of parentCert.
// If the signature is not in low-S, then a new certificate is generated
// that is equals to cert but the signature that is in low-S.
func sanitizeECDSASignedCert(cert *x509.Certificate, parentCert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("certificate must be different from nil")
	}
	if parentCert == nil {
		return nil, errors.New("parent certificate must be different from nil")
	}

	expectedSig, err := utils.SignatureToLowS(parentCert.PublicKey.(*ecdsa.PublicKey), cert.Signature)
	if err != nil {
		return nil, err
	}

	// if sig == cert.Signature, nothing needs to be done
	if bytes.Equal(cert.Signature, expectedSig) {
		return cert, nil
	}
	// otherwise create a new certificate with the new signature

	// 1. Unmarshal cert.Raw to get an instance of certificate,
	//    the lower level interface that represent an x509 certificate
	//    encoding
	var newCert certificate
	newCert, err = certFromX509Cert(cert)
	if err != nil {
		return nil, err
	}

	// 2. Change the signature
	newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}

	// 3. marshal again newCert. Raw must be nil
	newCert.Raw = nil
	newRaw, err := asn1.Marshal(newCert)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling of the certificate failed")
	}

	// 4. parse newRaw to get an x509 certificate
	return x509.ParseCertificate(newRaw)
}

func certFromX509Cert(cert *x509.Certificate) (certificate, error) {
	var newCert certificate
	_, err := asn1.Unmarshal(cert.Raw, &newCert)
	if err != nil {
		return certificate{}, errors.Wrap(err, "unmarshalling of the certificate failed")
	}
	return newCert, nil
}

// String returns a PEM representation of a certificate
func (c certificate) String() string {
	b, err := asn1.Marshal(c)
	if err != nil {
		return fmt.Sprintf("Failed marshaling cert: %v", err)
	}
	block := &pem.Block{
		Bytes: b,
		Type:  "CERTIFICATE",
	}
	b = pem.EncodeToMemory(block)
	return string(b)
}

// certToPEM converts the given x509.Certificate to a PEM
// encoded string
func certToPEM(certificate *x509.Certificate) string {
	cert, err := certFromX509Cert(certificate)
	if err != nil {
		mspIdentityLogger.Warning("Failed converting certificate to asn1", err)
		return ""
	}
	return cert.String()
}
