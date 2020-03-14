package model

import Sendable
import Receivable
import putU8
import readU8
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-13
 */
class CompressionMethod : Sendable, Receivable {

    constructor()

    lateinit var type: Type
        private set

    constructor(type: Type) {
        this.type = type
    }

    enum class Type(val value: Int) {
        NULL(0)
    }

    override fun parse(ins: InputStream, length: Int) {
        val typeV = ins.readU8()
        type = Type.values().find { it.value == typeV } ?: error("Not found match compression method($typeV)")
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(1).apply { putU8(type.value) }.array()
    }

    override fun size(): Int = 1 /*u8*/

    override fun toString(): String {
        return "CompressionMethod(type=${type.name})"
    }


}