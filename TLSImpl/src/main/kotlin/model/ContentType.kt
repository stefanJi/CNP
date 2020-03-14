package model

import Receivable
import java.io.InputStream

class ContentType : Receivable {

    lateinit var type: Type

    enum class Type(val value: Int) {
        change_cipher_spec(20),
        alert(21),
        handshake(22),
        application_data(23)
    }

    override fun parse(ins: InputStream, length: Int) {
        val typeValue = ins.read()
        type = Type.values().find { it.value == typeValue } ?: error("Not found match ContentType($typeValue)")
    }

    companion object {
        const val SIZE = 1
    }
}