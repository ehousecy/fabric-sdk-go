# Hyperledger Fabric Client SDK for Go

[![Release](https://img.shields.io/github/release/hyperledger/fabric-sdk-go.svg?style=flat-square)](https://github.com/hyperledger/fabric-sdk-go/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/hyperledger/fabric-sdk-go/master/LICENSE)
[![GoDoc](https://godoc.org/github.com/hyperledger/fabric-sdk-go?status.svg)](https://godoc.org/github.com/hyperledger/fabric-sdk-go)

[![Build Status](https://dev.azure.com/hyperledger/fabric-sdk-go/_apis/build/status/hyperledger.fabric-sdk-go?branchName=master)](https://dev.azure.com/hyperledger/fabric-sdk-go/_build/latest?definitionId=19&branchName=master)
[![codecov](https://codecov.io/gh/hyperledger/fabric-sdk-go/branch/master/graph/badge.svg)](https://codecov.io/gh/hyperledger/fabric-sdk-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/hyperledger/fabric-sdk-go)](https://goreportcard.com/report/github.com/hyperledger/fabric-sdk-go)


>> 这是基于v1.0.0-rc1修改的支持国密算法的go-sdk

#### 待办事项
- [ ] fabric-ca国密支持

#### 已做修改

- [x] bccsp新增SMX密钥支持
- [x] msp修改
  - [x] 对证书接口做了抽象
  - [x] 提供x509.Certificate和sm2.Certificate互转的方法
  - [x] SigningManager 签名和identity验签的地方，哈希都注释掉了，由signer/verifier自行哈希（此处是由于同济的国密库sm2sign和sm2Verify方法默认做了哈希）  
- [x] tls部分增加对国密tls的支持
- [x] 其他适配
  - [x] ImportBCCSPKeyFromPEMBytes增加sm2.privateKey的支持
- [x] sanitizeCert方法修改  

#### 项目测试

```
# 1使用fabric-samples/fabcar进行测试
# 1.1 修改go.mod
# 1.1.1 首先通过命令获取fabric-sdk-go版本号
go get github.com/ehousecy/fabric-sdk-go@develop
# 1.1.2 go.mod添加replace
replace github.com/hyperledger/fabric-sdk-go => github.com/ehousecy/fabric-sdk-go v1.0.0-rc1.0.20210201104547-9895c8ce0d04
# 2 下载依赖
go mod vendor
# 3 运行项目
go run fabcar.go 
```