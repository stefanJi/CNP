# TLSImpl

A client program written in Kotlin that implements the TLS (v1.2) protocol.

## Target

Generate a master key by implement TLS handshake. And use the key to communicate with the server.

```
Client                                               Server

ClientHello                  -------->
                                                  ServerHello
                                                 Certificate*
                                           ServerKeyExchange*
                                        CertificateRequest*
                             <--------      ServerHelloDone
Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished                     -------->
                                         [ChangeCipherSpec]
                             <--------             Finished
Application Data             <------->     Application Data
```

## Client Flow

- [x] Client Hello
- [ ] Client Key Exchange
- [ ] Certificate Verify
- [ ] Change Cipher Spec
- [ ] Finished

## Handle Server Flow Parse

- [x] Server Hello
- [ ] Certificate
- [ ] ServerKeyExchang
- [x] ServerHelloDone
- [ ] ChangeCipherSpec
- [ ] Finished
