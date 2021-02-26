/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package lib

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	gmtls "github.com/Hyperledger-TWGC/ccs-gm/tls"
	x509GM "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/Hyperledger-TWGC/net-go-gm/http"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/util"
	"github.com/pkg/errors"
)

var clientAuthTypes = map[string]tls.ClientAuthType{
	"noclientcert":               tls.NoClientCert,
	"requestclientcert":          tls.RequestClientCert,
	"requireanyclientcert":       tls.RequireAnyClientCert,
	"verifyclientcertifgiven":    tls.VerifyClientCertIfGiven,
	"requireandverifyclientcert": tls.RequireAndVerifyClientCert,
}

// GetCertID returns both the serial number and AKI (Authority Key ID) for the certificate
func GetCertID(bytes []byte) (string, string, error) {
	cert, err := BytesToX509Cert(bytes)
	if err != nil {
		return "", "", err
	}
	serial := util.GetSerialAsHex(cert.SerialNumber)
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	return serial, aki, nil
}

// BytesToX509Cert converts bytes (PEM or DER) to an X509 certificate
func BytesToX509Cert(bytes []byte) (*x509.Certificate, error) {
	dcert, _ := pem.Decode(bytes)
	if dcert != nil {
		bytes = dcert.Bytes
	}
	cert, err := x509GM.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Buffer was neither PEM nor DER encoding")
	}
	return sw.ParseSm2Certificate2X509(cert), err
}

func addQueryParm(req *http.Request, name, value string) {
	url := req.URL.Query()
	url.Add(name, value)
	req.URL.RawQuery = url.Encode()
}

// CertificateDecoder is needed to keep track of state, to see how many certificates
// have been returned for each enrollment ID.
type CertificateDecoder struct {
	certIDCount map[string]int
	storePath   string
}

func SetTLSConfig(c *gmtls.Config) {
	isGM := false
	if len(c.Certificates) > 0 {
		_, ok := c.Certificates[0].PrivateKey.(*sm2.PrivateKey)
		if ok {
			isGM = true
		}
	} else {
		certs := c.RootCAs.GetCerts()
		if len(certs) > 0 {
			if _, ok := certs[0].PublicKey.(*sm2.PublicKey); ok {
				isGM = true
			}
		}
	}
	if isGM {
		c.GMSupport = &gmtls.GMSupport{}
		c.MinVersion = gmtls.VersionGMSSL
	} else {
		c.GMSupport = nil
		c.MinVersion = gmtls.VersionTLS12
	}
}
