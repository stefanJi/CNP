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
- [x] Certificate
- [x] ServerKeyExchang
- [x] ServerHelloDone
- [ ] ChangeCipherSpec
- [ ] Finished


## Term

### Number type

- u8 -> uint_8
- u16 -> uint_16
- uN -> uint_N

#### Number extension function

```kotlin
fun ByteBuffer.getU16(): Int = (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.getU24(): Int =
    (get().toInt() and 0xFF shl 16) or (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.getU32(): Int =
    (get().toInt() and 0xFF shl 24) or (get().toInt() and 0xFF shl 16) or (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.putU8(value: Int) = run {
    put(value.toByte())
}

fun ByteBuffer.putU16(value: Int) = run {
    put((value shr 8 and 0xFF).toByte())
    put((value and 0xFF).toByte())
}

fun ByteBuffer.putU24(value: Int) = run {
    put((value shr 16 and 0xFF).toByte())
    put((value shr 8 and 0xFF).toByte())
    put((value and 0xFF).toByte())
}

fun ByteBuffer.putU32(value: Int) = run {
    put((value shr 24 and 0xFF).toByte())
    put((value shr 16 and 0xFF).toByte())
    put((value shr 8 and 0xFF).toByte())
    put((value and 0xFF).toByte())
}

fun InputStream.readU8() = read()

fun InputStream.readU16(): Int {
    return (read() and 0xFF shl 8) or (read() and 0xFF)
}

fun InputStream.readU24(): Int {
    return (read() and 0xFF shl 16) or (read() and 0xFF shl 8) or (read() and 0xFF)
}

fun InputStream.readU32(): Int {
    return (read() and 0xFF shl 24) or (read() and 0xFF shl 16) or (read() and 0xFF shl 8) or (read() and 0xFF)
}
```

## Reference

- https://ciphersuite.info/cs/
