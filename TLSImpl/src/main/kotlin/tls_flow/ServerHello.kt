package tls_flow

import Receivable
import model.*
import java.io.InputStream

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
class ServerHello : Receivable {
    lateinit var version: Version.Desc
    lateinit var random: TlsRandomHeader
    lateinit var sessionId: ByteArray
    lateinit var cipherSuite: CipherSuite
    lateinit var compressionMethod: CompressionMethod
    var extension: HelloExtension = HelloExtension()

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

    override fun parse(ins: InputStream, length: Int) {
        var count = 0
        version = Version().apply { parse(ins, Version.SIZE) }.desc
        count += Version.SIZE
        random = TlsRandomHeader().apply { parse(ins, TlsRandomHeader.SIZE) }
        count += TlsRandomHeader.SIZE
        val sessionLen = ins.read()
        sessionId = ByteArray(sessionLen)
        ins.read(sessionId)
        count += 1
        count += sessionLen
        cipherSuite = CipherSuite().apply { parse(ins, CipherSuite.SIZE) }
        count += CipherSuite.SIZE
        compressionMethod = CompressionMethod().apply { parse(ins, 1) }
        count += 1
        if (count < length) {
            extension = HelloExtension().apply { parse(ins, length - count) }
        }
    }

    override fun toString(): String {
        return "ServerHello(version=$version, random=$random, sessionId=${sessionId.contentToString()}, cipherSuite=$cipherSuite, compressionMethod=$compressionMethod, extension=$extension)"
    }


}