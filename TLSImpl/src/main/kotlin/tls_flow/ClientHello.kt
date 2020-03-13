package tls_flow

import Content
import Parseable
import putU16
import putU8
import model.CipherSuite
import model.CompressionMethod
import model.TlsRandomHeader
import model.Version
import java.io.InputStream
import java.nio.ByteBuffer

/**
 *struct {
 *  ProtocolVersion client_version;
 *  Random random;
 *  SessionID session_id;
 *  CipherSuite cipher_suites<2..2^16-2>; // 加密算法数组的长度范围为 2~((2^16)-2)
 *  CompressionMethod compression_methods<1..2^8-1>; //压缩算法数组的长度范围为 1~((2^8)-1)
 *  select (extensions_present) {
 *    case false:
 *    struct {};
 *    case true:
 *    Extension extensions<0..2^16-1>;
 *  };
 *} tls_flow.ClientHello;
 */
class ClientHello : Content, Parseable {

    constructor()

    lateinit var version: Version.Desc
    lateinit var tlsRandomHeader: TlsRandomHeader
    lateinit var sessionId: ByteArray
    lateinit var cipherSuites: Array<CipherSuite>
        private set
    lateinit var compressionMethods: Array<CompressionMethod>
        private set
    private var cipherSuitesLen: Int = 0
    private var compressionMethodsLen = 0

    val extensionLength = 0 //TODO extension inject

    constructor(
        version: Version.Desc,
        tlsRandomHeader: TlsRandomHeader,
        sessionId: ByteArray,
        cipherSuites: Array<CipherSuite>,
        compressionMethods: Array<CompressionMethod>
    ) {
        this.version = version
        this.tlsRandomHeader = tlsRandomHeader
        this.sessionId = sessionId
        this.cipherSuites = cipherSuites
        this.compressionMethods = compressionMethods
        this.cipherSuitesLen = cipherSuites.sumBy { it.size() }
        this.compressionMethodsLen = compressionMethods.sumBy { it.size() }
    }

    override fun data(): ByteArray {

        return ByteBuffer.allocate(size()).apply {
            putU8(version.major)
            putU8(version.minor)
            put(tlsRandomHeader.data())
            putU8(sessionId.size) /*session id length*/
            put(sessionId)
            putU16(cipherSuitesLen)
            cipherSuites.forEach { put(it.data()) }
            putU8(compressionMethodsLen)
            compressionMethods.forEach { put(it.data()) }
            putU16(extensionLength)
        }.array()
    }

    //1+1+28+4+1+2+2+1+2+1
    override fun size(): Int = 1/*major version*/ + 1/*minor version*/ +
            tlsRandomHeader.size() /*random length*/ +
            1/*session id length*/ + sessionId.size +
            2/*cipher len u16*/ + cipherSuitesLen +
            1 /*compression len u8*/ + compressionMethodsLen +
            2 /*extension length u16*/

    override fun parse(ins: InputStream) {
    }
}