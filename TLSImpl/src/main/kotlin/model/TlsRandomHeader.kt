package model

import Content
import Parseable
import putU32
import readU32
import java.io.InputStream
import java.nio.ByteBuffer

class TlsRandomHeader : Content, Parseable {

    var time: Int = 0
        private set
    lateinit var randomValue: ByteArray
        private set

    constructor()
    constructor(time: Int, random: ByteArray) {
        this.time = time
        this.randomValue = random
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(size()).apply {
            putU32(time)
            put(randomValue)
        }.array()
    }

    override fun size(): Int = 4 /*gmt unit time*/ + 28 /*random*/

    override fun parse(ins: InputStream) {
        time = ins.readU32()
        randomValue = ByteArray(28)
        ins.read(randomValue)
    }
}