/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package tls

import (
	"crypto/tls"
	"crypto/x509"
	gmtls "github.com/Hyperledger-TWGC/ccs-gm/tls"
	x509GM "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/util"
	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	log "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/logbridge"
	"github.com/pkg/errors"
)

// DefaultCipherSuites is a set of strong TLS cipher suites
var DefaultCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	gmtls.GMTLS_SM2_WITH_SM4_SM3,
	gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3,
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled     bool     `skip:"true"`
	CertFiles   [][]byte `help:"A list of comma-separated PEM-encoded trusted certificate bytes"`
	Client      KeyCertFiles
	TlsCertPool *x509.CertPool
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  []byte `help:"PEM-encoded key bytes when mutual authentication is enabled"`
	CertFile []byte `help:"PEM-encoded certificate bytes when mutual authenticate is enabled"`
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig, csp core.CryptoSuite) (*gmtls.Config, error) {
	var certs []gmtls.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	if cfg.Client.CertFile != nil {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		_, clientCert, err := util.LoadX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *TransformTLSCertificate(clientCert))
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := x509GM.NewCertPool()

	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No trusted root certificates for TLS were provided")
	}

	for _, cacert := range cfg.CertFiles {
		ok := rootCAPool.AppendCertsFromPEM(cacert)
		if !ok {
			return nil, errors.New("Failed to process certificate")
		}
	}

	config := &gmtls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}
	return config, nil
}

func checkCertDates(certPEM []byte) error {
	log.Debug("Check client TLS certificate for valid dates")

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

func TransformTLSCertificate(cert *tls.Certificate) *gmtls.Certificate {
	var leaf *x509GM.Certificate

	if cert.Leaf != nil {
		leaf = sw.ParseX509Certificate2Sm2(cert.Leaf)
	}

	return &gmtls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        leaf,
	}
}
