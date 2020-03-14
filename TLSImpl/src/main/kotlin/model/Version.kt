package model

import Receivable
import Sendable
import putU8
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-13
 */
class Version : Sendable, Receivable {

    lateinit var desc: Version.Desc

    override fun parse(ins: InputStream, length: Int) {
        val major = ins.read()
        val minor = ins.read()
        desc = Desc.values().find { it.major == major && it.minor == minor }
            ?: error("Not found match Version($major,$minor)")
    }


    enum class Desc(val major: Int, val minor: Int) {
        V1_2(3, 3),
        V1_1(3, 2),
        V1_0(3, 0)
    }

    override fun data(): ByteArray = ByteBuffer.allocate(2).apply {
        putU8(desc.major)
        putU8(desc.minor)
    }.array()

    override fun size(): Int = SIZE

    companion object {
        const val SIZE = 2
    }
}