package model

import Content
import Parseable
import putU16
import readU16
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-13
 */
class CipherSuite : Content, Parseable {

    lateinit var type: Type
        private set

    constructor()

    constructor(type: Type) {
        this.type = type
    }

    enum class Type(val value: Int) {
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xc028),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xc024),
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014),
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xc00a),
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009f),
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006b),
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcca9),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcca8),
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xccaa),
        Unknown(0xff85),
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00c4),
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088),
        TLS_GOSTR341001_WITH_28147_CNT_IMIT(0x0081),
        TLS_RSA_WITH_AES_256_GCM_SHA384(0x009d),
        TLS_RSA_WITH_AES_256_CBC_SHA256(0x003d),
        TLS_RSA_WITH_AES_256_CBC_SHA(0x0035),
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00c0),
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xc027),
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xc023),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013),
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009),
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009e),
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067),
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033),
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00be),
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045),
        TLS_RSA_WITH_AES_128_GCM_SHA256(0x009c),
        TLS_RSA_WITH_AES_128_CBC_SHA256(0x003c),
        TLS_RSA_WITH_AES_128_CBC_SHA(0x002f),
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00ba),
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041),
        TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xc011),
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xc007),
        TLS_RSA_WITH_RC4_128_SHA(0x0005),
        TLS_RSA_WITH_RC4_128_MD5(0x0004),
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xc012),
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xc008),
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016),
        TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000a),
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00ff)
    }

    override fun parse(ins: InputStream) {
        val typeV = ins.readU16()
        type = Type.values().find { it.value == typeV } ?: error("Not found match cipher suite($typeV)")
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(2).apply { putU16(type.value) }.array()
    }

    override fun size(): Int = 2

    override fun toString(): String {
        return "CipherSuite(type=${type.name})"
    }


}