package model

import Receivable
import java.io.InputStream

class HandshakeType : Receivable {
    enum class Type(val value: Int) {
        hello_request(0),
        client_hello(1),
        server_hello(2),
        certificate(11),
        server_key_exchange(12),
        certificate_request(13),
        server_hello_done(14),
        certificate_verify(15),
        client_key_exchange(16),
        finished(20)
    }

    lateinit var type: Type
    override fun parse(ins: InputStream, length: Int) {
        val typeValue = ins.read()
        type = Type.values().find { it.value == typeValue } ?: error("Not found model.HandshakeType($typeValue)")
    }

    companion object {
        const val SIZE = 1
    }
}