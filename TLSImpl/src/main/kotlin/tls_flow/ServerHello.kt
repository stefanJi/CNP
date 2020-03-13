package tls_flow

import Content
import Parseable
import model.*
import putU8
import java.io.InputStream
import java.nio.ByteBuffer

/**
 *struct {
 * ProtocolVersion server_version;
 * Random random;
 * SessionID session_id;
 * CipherSuite cipher_suite;
 * CompressionMethod compression_method;
 * select (extensions_present) {
 *   case false:
 *     struct {};
 *   case true:
 *    Extension extensions<0..2^16-1>;
 *  };
 *} tls_flow.ServerHello;
 */
class ServerHello : Content, Parseable {
    lateinit var version: Version.Desc
    lateinit var random: TlsRandomHeader
    lateinit var sessionId: ByteArray
    lateinit var cipherSuite: CipherSuite
    lateinit var compressionMethod: CompressionMethod
    lateinit var extension: HelloExtension

    constructor()

    constructor(
        version: Version.Desc,
        random: TlsRandomHeader,
        sessionId: ByteArray,
        cipherSuite: CipherSuite,
        compressionMethod: CompressionMethod,
        extensions: HelloExtension
    ) {
        this.version = version
        this.random = random
        this.sessionId = sessionId
        this.cipherSuite = cipherSuite
        this.compressionMethod = compressionMethod
        this.extension = extensions
    }

    override fun parse(ins: InputStream) {
        version = Version().apply { parse(ins) }.desc
        random = TlsRandomHeader().apply { parse(ins) }
        val sessionLen = ins.read()
        sessionId = ByteArray(sessionLen)
        ins.read(sessionId)
        cipherSuite = CipherSuite().apply { parse(ins) }
        compressionMethod = CompressionMethod().apply { parse(ins) }
        extension = HelloExtension().apply { parse(ins) }
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(size()).apply {
            putU8(version.major)
            putU8(version.minor)
            put(random.data())
            putU8(sessionId.size)
            put(sessionId)
            put(cipherSuite.data())
            put(compressionMethod.data())
        }.array()
    }

    override fun size(): Int = 2 /*version*/ +
            4 + 28/*random*/ +
            1/*session id length: u8*/ + sessionId.size +
            2/*cipher suite: u16*/ +
            2/*compression method: u16*/ +
            2/*extension length: u16*/ + extension.size()

    override fun toString(): String {
        return "ServerHello(version=$version, random=$random, sessionId=${sessionId.contentToString()}, cipherSuite=$cipherSuite, compressionMethod=$compressionMethod, extension=$extension)"
    }


}