package model

import Receivable
import Sendable
import putU16
import putU8
import readU16
import readU8
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-13
 */
class CipherSuite : Sendable, Receivable {

    lateinit var type: Type
        private set

    constructor()

    constructor(type: Type) {
        this.type = type
    }

    /**
     * Cipher Suite IANA name
     * @param value Hex code
     * https://ciphersuite.info/cs/
     */
    enum class Type(val value: Int) : CipherSuiteProvider {
        //        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030),
//        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c),
//        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xc028),
//        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xc024),
//        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014),
//        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xc00a),
//        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009f),
//        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006b),
//        TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039),
//        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcca9),
//        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcca8),
//        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xccaa),
//        Unknown(0xff85),
//        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00c4),
//        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088),
//        TLS_GOSTR341001_WITH_28147_CNT_IMIT(0x0081),
//        TLS_RSA_WITH_AES_256_GCM_SHA384(0x009d),
//        TLS_RSA_WITH_AES_256_CBC_SHA256(0x003d),
//        TLS_RSA_WITH_AES_256_CBC_SHA(0x0035),
//        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00c0),
//        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f) {
            override fun KeyExchange() = KeyExchangeAlgorithm.ECDHE
            override fun Authentication() = AuthenticationAlgorithm.RSA
            override fun Encryption() = EncryptionAlgorithm.AES_128_GCM
            override fun Hash() = HashAlgorithm.SHA256
        },
//        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b),
//        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xc027),
//        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xc023),
//        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013),
//        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009),
//        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009e),
//        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067),
//        TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033),
//        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00be),
//        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045),
//        TLS_RSA_WITH_AES_128_GCM_SHA256(0x009c),
//        TLS_RSA_WITH_AES_128_CBC_SHA256(0x003c),
//        TLS_RSA_WITH_AES_128_CBC_SHA(0x002f),
//        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00ba),
//        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041),
//        TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xc011),
//        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xc007),
//        TLS_RSA_WITH_RC4_128_SHA(0x0005),
//        TLS_RSA_WITH_RC4_128_MD5(0x0004),
//        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xc012),
//        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xc008),
//        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016),
//        TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000a),
//        TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00ff)
    }

    override fun parse(ins: InputStream, length: Int) {
        val typeV = ins.readU16()
        type = Type.values().find { it.value == typeV } ?: error("Not found match cipher suite($typeV)")
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(SIZE).apply { putU16(type.value) }.array()
    }

    override fun size(): Int = SIZE

    override fun toString(): String {
        return "CipherSuite(type=${type.name})"
    }

    companion object {
        const val SIZE = 2 /*u16*/
    }
}

interface CipherSuiteProvider {
    fun KeyExchange(): KeyExchangeAlgorithm
    fun Authentication(): AuthenticationAlgorithm
    fun Encryption(): EncryptionAlgorithm
    fun Hash(): HashAlgorithm
}

enum class KeyExchangeAlgorithm(val algorithm: Receivable) {
    ECDHE(ECDHEAlgorithm())
}

enum class AuthenticationAlgorithm {
    RSA
}

enum class EncryptionAlgorithm {
    AES_128_GCM
}

enum class HashAlgorithm {
    SHA256
}

class ECDHEAlgorithm : Receivable, Sendable {
    lateinit var curveType: ECCureType /*u8*/
        private set
    var namedCurve: NamedCurve? = null /*u16*/
        private set
    var pubKeyLength: Int = 0 /*u8*/
        private set
    var pubKey: ByteArray = ByteArray(0)
        private set
    var signatureAlgorithm: Int = 0 /*u16*/
        private set
    var signatureLength: Int = 0 /*u16*/
        private set
    var signature: ByteArray = ByteArray(0)
        private set

    constructor()

    /**
     * Use for client key exchange message
     */
    constructor(pubKey: ByteArray) {
        this.pubKey = pubKey
        this.pubKeyLength = pubKey.size
    }

    override fun parse(ins: InputStream, length: Int) {
        curveType = ins.readU8()
            .let { v -> ECCureType.values().find { it.number == v } ?: error("Not found match curve type($v)") }
        if (curveType == ECCureType.named_curve) {
            namedCurve = ins.readU16()
                .let { v -> NamedCurve.values().find { it.number == v } ?: error("Not found match name curve($v)") }
        } else {
            throw NotImplementedError("Not implemented for curve type(${curveType.name})")
            //TODO implement other curve type parse
        }
        pubKeyLength = ins.readU8()
        pubKey = ByteArray(pubKeyLength).apply { ins.read(this) }
        signatureAlgorithm = ins.readU16()
        signatureLength = ins.readU16()
        signature = ByteArray(signatureLength).apply { ins.read(this) }
    }

    override fun data(): ByteArray = ByteBuffer.allocate(size()).apply {
        putU8(pubKeyLength)
        put(pubKey)
    }.array()

    override fun size(): Int = 1 + pubKeyLength

    override fun toString(): String {
        return "ECDHEAlgorithm(curveType=$curveType, namedCurve=$namedCurve, pubKeyLength=$pubKeyLength, pubKey=${pubKey.contentToString()}, signatureAlgorithm=$signatureAlgorithm, signatureLength=$signatureLength, signature=${signature.contentToString()})"
    }
}

/**
enum { explicit_prime (1), explicit_char2 (2), named_curve (3), reserved(248..255) } ECCurveType;
 */
enum class ECCureType(val number: Int) {
    explicit_prime(1), explicit_char2(2), named_curve(3)
}

/**
 *
 * https://tools.ietf.org/html/rfc4492#section-5.1.1
enum {
sect163k1 (1), sect163r1 (2), sect163r2 (3),
sect193r1 (4), sect193r2 (5), sect233k1 (6),
sect233r1 (7), sect239k1 (8), sect283k1 (9),
sect283r1 (10), sect409k1 (11), sect409r1 (12),
sect571k1 (13), sect571r1 (14), secp160k1 (15),
secp160r1 (16), secp160r2 (17), secp192k1 (18),
secp192r1 (19), secp224k1 (20), secp224r1 (21),
secp256k1 (22), secp256r1 (23), secp384r1 (24),
secp521r1 (25),
reserved (0xFE00..0xFEFF),
arbitrary_explicit_prime_curves(0xFF01),
arbitrary_explicit_char2_curves(0xFF02),
(0xFFFF)
} NamedCurve;
 */
enum class NamedCurve(val number: Int) {
    //TODO more support
    secp256r1(0x17 /*23*/)
}