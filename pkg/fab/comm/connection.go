/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"crypto/x509"
	gmtls "github.com/Hyperledger-TWGC/ccs-gm/tls"
	x509GM "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/common/verifier"
	common2 "github.com/hyperledger/fabric-sdk-go/pkg/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/gmcredentials"
	fab2 "github.com/hyperledger/fabric-sdk-go/pkg/fab"
	"google.golang.org/grpc/credentials"
	"sync/atomic"

	"github.com/pkg/errors"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/options"
	fabcontext "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config/comm"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config/endpoint"
	"google.golang.org/grpc"
)

var logger = logging.NewLogger("fabsdk/fab")

const (
	// GRPC max message size (same as Fabric)
	maxCallRecvMsgSize = 100 * 1024 * 1024
	maxCallSendMsgSize = 100 * 1024 * 1024
)

// GRPCConnection manages the GRPC connection and client stream
type GRPCConnection struct {
	context     fabcontext.Client
	conn        *grpc.ClientConn
	commManager fab.CommManager
	tlsCertHash []byte
	done        int32
}

// NewConnection creates a new connection
func NewConnection(ctx fabcontext.Client, url string, opts ...options.Opt) (*GRPCConnection, error) {
	if url == "" {
		return nil, errors.New("server URL not specified")
	}

	params := defaultParams()
	options.Apply(params, opts)

	dialOpts, err := newDialOpts(ctx.EndpointConfig(), url, params)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.NewRequest(ctx,
		context.WithTimeout(params.connectTimeout),
		context.WithParent(params.parentContext))
	defer cancel()

	commManager, ok := context.RequestCommManager(reqCtx)
	if !ok {
		return nil, errors.New("unable to get comm manager")
	}

	grpcconn, err := commManager.DialContext(reqCtx, endpoint.ToAddress(url), dialOpts...)
	if err != nil {
		return nil, errors.Wrapf(err, "could not connect to %s", url)
	}

	hash, err := comm.TLSCertHash(ctx.EndpointConfig())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get tls cert hash")
	}

	return &GRPCConnection{
		context:     ctx,
		commManager: commManager,
		conn:        grpcconn,
		tlsCertHash: hash,
	}, nil
}

// ClientConn returns the underlying GRPC connection
func (c *GRPCConnection) ClientConn() *grpc.ClientConn {
	return c.conn
}

// Close closes the connection
func (c *GRPCConnection) Close() {
	if !c.setClosed() {
		logger.Debug("Already closed")
		return
	}

	logger.Debug("Releasing connection....")
	c.commManager.ReleaseConn(c.conn)

	logger.Debug("... connection successfully closed.")
}

// Closed returns true if the connection has been closed
func (c *GRPCConnection) Closed() bool {
	return atomic.LoadInt32(&c.done) == 1
}

func (c *GRPCConnection) setClosed() bool {
	return atomic.CompareAndSwapInt32(&c.done, 0, 1)
}

// TLSCertHash returns the hash of the TLS cert
func (c *GRPCConnection) TLSCertHash() []byte {
	return c.tlsCertHash
}

// Context returns the context of the client establishing the connection
func (c *GRPCConnection) Context() fabcontext.Client {
	return c.context
}

func newDialOpts(config fab.EndpointConfig, url string, params *params) ([]grpc.DialOption, error) {
	var dialOpts []grpc.DialOption

	if params.keepAliveParams.Time > 0 || params.keepAliveParams.Timeout > 0 {
		dialOpts = append(dialOpts, grpc.WithKeepaliveParams(params.keepAliveParams))
	}

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.WaitForReady(!params.failFast)))

	if endpoint.AttemptSecured(url, params.insecure) {
		isSM2 := false
		for _, cert := range config.TLSCACertPool().GetCerts() {
			if common2.IsSM2Certificate(cert.Raw, false) {
				isSM2 = true
				break
			}
		}
		if !isSM2 {
			tlsConfig, err := comm.TLSConfig(params.certificate, params.hostOverride, config)
			if err != nil {
				return nil, err
			}
			//verify if certificate was expired or not yet valid
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				return verifier.VerifyPeerCertificate(rawCerts, verifiedChains)
			}

			dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			certPool := x509GM.NewCertPool()
			if params.certificate != nil {
				certPool.AddCert(common2.ParseX509Certificate2Sm2(params.certificate))
			}
			for _, cert := range config.TLSCACertPool().GetCerts() {
				certPool.AddCert(common2.ParseX509Certificate2Sm2(cert))
			}

			var clientCerts []gmtls.Certificate
			switch config.(type) {
			case *fab2.EndpointConfig:
				clientCerts = config.(*fab2.EndpointConfig).TLSClientSM2Certs()
			}

			tlsConfig := &gmtls.Config{RootCAs: certPool, Certificates: clientCerts, ServerName: params.hostOverride}
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509GM.Certificate) error {
				return verifier.VerifyPeerSM2Certificate(rawCerts, verifiedChains)
			}
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(gmcredentials.NewTLS(tlsConfig)))
		}
		logger.Debugf("Creating a secure connection to [%s] with TLS HostOverride [%s]", url, params.hostOverride)
	} else {
		logger.Debugf("Creating an insecure connection [%s]", url)
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxCallRecvMsgSize),
		grpc.MaxCallSendMsgSize(maxCallSendMsgSize)))

	return dialOpts, nil
}
