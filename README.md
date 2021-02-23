# Hyperledger Fabric 国密版
>> 这是基于v1.0.0-rc1修改的支持国密算法的go-sdk

###思路修改
- [x] bccsp新增SMX密钥支持
- [x] msp修改
  - [x] 对证书接口做了抽象
  - [x] 提供x509.Certificate和sm2.Certificate互转的方法
- [x] tls部分增加对国密tls的支持
- [x] 其他适配
  - [x] ImportBCCSPKeyFromPEMBytes增加sm2.privateKey的支持
- [x] sanitizeCert方法修改  
- [x] fabric-ca 国密支持(国密tls还未支持)

## 待办事项
- [ ]fabric-ca tls 国密支持

## 项目使用

#### 1. 获取fabric-sdk-go版本号
```
go get github.com/ehousecy/fabric-sdk-go@ccs-gm
```

#### 2. go.mod 添加replace
```
replace github.com/hyperledger/fabric-sdk-go => github.com/ehousecy/fabric-sdk-go v1.0.0-rc1.0.20210222094557-c9106585e67f
```

#### 3. 更新依赖
```
go mod vendor
```

## 关于我们
国密化改造工作主要由ehousecy完成，想要了解更多/商业合作/联系我们，欢迎访问我们的[官网](https://ebaas.com/)。