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
package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
	"github.com/tjfoc/gmsm/sm2"
)

func signECDSA(k *ecdsa.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, err = utils.ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := utils.IsLowS(k, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAt(k.Curve))
	}

	return ecdsa.Verify(k, digest, r, s), nil
}

type ecdsaSigner struct{}

func (s *ecdsaSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	hasher := &hasher{hash: sha256.New}
	digest, err := hasher.Hash(msg, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign msg[%s]", err)
	}
	return signECDSA(k.(*ecdsaPrivateKey).privKey, digest, opts)
}

type ecdsaPrivateKeyVerifier struct{}

func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyECDSA(&(k.(*ecdsaPrivateKey).privKey.PublicKey), signature, digest, opts)
}

type ecdsaPublicKeyKeyVerifier struct{}

func (v *ecdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	puk := k.(*ecdsaPublicKey).pubKey

	switch puk.Curve {
	case sm2.P256Sm2():
		sm2pk := sm2.PublicKey{
			Curve: puk.Curve,
			X:     puk.X,
			Y:     puk.Y,
		}
		return verifyGMSM2(&sm2pk, signature, msg, opts)
	case elliptic.P256():
		hasher := &hasher{hash: sha256.New}
		digest, err := hasher.Hash(msg, nil)
		if err != nil {
			return false, fmt.Errorf("Failed to sign msg[%s]", err)
		}
		return verifyECDSA(k.(*ecdsaPublicKey).pubKey, signature, digest, opts)
	default:
		panic("UnSupport Curve for ecdsaPublicKeyKeyVerifier")
	}

}
