package model

import Content
import Parseable
import putU16
import readU16
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-12
 */
class HelloExtension : Content, Parseable {

    var length: Int = 0
        private set
    lateinit var extensions: Array<Extension>
        private set

    constructor()

    constructor(extensions: Array<Extension>) {
        this.extensions = extensions
        this.length = extensions.sumBy { it.size() }
    }

    class Extension : Content, Parseable {
        var type: Int = 0
            private set
        var length: Int = 0
            private set
        lateinit var data: ByteArray
            private set

        constructor()
        constructor(type: Int, data: ByteArray) {
            this.type = type
            this.data = data
            this.length = data.size
        }

        override fun data() = ByteBuffer.allocate(size()).apply {
            putU16(type)
            putU16(length)
            put(data)
        }.array()

        override fun size(): Int = 2 /*type: u16*/ + 2 /*len u16*/ + data.size

        override fun parse(ins: InputStream) {
            type = ins.readU16()
            length = ins.readU16()
            data = ByteArray(length).apply { ins.read(this) }
        }

        override fun toString(): String {
            return "Extension(type=$type, length=$length)"
        }

    }

    override fun data(): ByteArray =
        ByteBuffer.allocate(size()).apply {
            putU16(length)
            extensions.forEach { put(it.data()) }
        }.array()

    override fun size(): Int = 2/* extension_data length: u16 */ +
            extensions.sumBy { it.size() }

    override fun parse(ins: InputStream) {
        length = ins.readU16()
        var offset = 0
        val es = arrayListOf<Extension>()
        while (offset < length) {
            val extension = Extension().apply { parse(ins) }
            offset += extension.size()
            es.add(extension)
        }
        extensions = es.toTypedArray()
    }

    override fun toString(): String {
        return "HelloExtension(length=$length, extensions=${extensions.contentToString()})"
    }
}