package model

import Sendable
import Receivable
import putU24
import putU8
import readU24
import java.io.InputStream
import java.nio.ByteBuffer

/**
 *enum {
 *  hello_request(0), client_hello(1), server_hello(2),
 *  certificate(11), server_key_exchange (12),
 *  certificate_request(13), server_hello_done(14),
 *  certificate_verify(15), client_key_exchange(16),
 *  finished(20), (255)
 *} model.HandshakeType;
 *
 *struct {
 *  model.HandshakeType msg_type;    /* handshake type */
 *    uint24 length;             /* bytes in message */
 *    select (model.HandshakeType) {
 *    case hello_request:       HelloRequest;
 *    case client_hello:        tls_flow.ClientHello;
 *    case server_hello:        tls_flow.ServerHello;
 *    case certificate:         Certificate;
 *    case server_key_exchange: ServerKeyExchange;
 *    case certificate_request: CertificateRequest;
 *    case server_hello_done:   ServerHelloDone;
 *    case certificate_verify:  CertificateVerify;
 *    case client_key_exchange: ClientKeyExchange;
 *    case finished:            Finished;
 *  } body;
 *} Handshake;
 */
class HandshakeData : Sendable, Receivable {

    lateinit var handshakeType: HandshakeType.Type
        private set
    var contentLength: Int = 0
        private set
    private lateinit var body: ByteArray

    constructor()

    constructor(handshakeType: HandshakeType.Type, body: ByteArray) {
        this.body = body
        this.handshakeType = handshakeType
        this.contentLength = body.size
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(size()).apply {
            putU8(handshakeType.value)
            putU24(contentLength)
            put(body)
        }.array()
    }

    override fun size(): Int = 1/*msg type uint8*/ + 3 /*length uint24*/ + body.size

    override fun parse(ins: InputStream, length: Int) {
        handshakeType = HandshakeType().apply { parse(ins, 1) }.type
        contentLength = ins.readU24()
    }
}