// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/fabric-sdk-go

replace github.com/Hyperledger-TWGC/ccs-gm => github.com/ehousecy/ccs-gm v0.1.2-0.20210226013248-cc995c360aed

require (
	github.com/Hyperledger-TWGC/ccs-gm v0.1.2-0.20210202011810-d006f903c43e
	github.com/Hyperledger-TWGC/net-go-gm v0.0.0-20200921114008-9f44067b1d7e
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/cloudflare/cfssl v1.4.1
	github.com/go-kit/kit v0.8.0
	github.com/golang/mock v1.4.3
	github.com/golang/protobuf v1.3.3
	github.com/google/certificate-transparency-go v1.0.21
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hyperledger/fabric-config v0.0.5
	github.com/hyperledger/fabric-lib-go v1.0.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.3.2
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.1.0
	github.com/spf13/afero v1.3.1 // indirect
	github.com/spf13/cast v1.3.1
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.1.1
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/net v0.0.0-20200904194848-62affa334b73
	google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v2 v2.3.0
)

go 1.14
