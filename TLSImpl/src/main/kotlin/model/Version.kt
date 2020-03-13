package model

import Parseable
import java.io.InputStream

/**
 * Create by StefanJi in 2020-03-13
 */
class Version : Parseable {

    lateinit var desc: Version.Desc

    override fun parse(ins: InputStream) {
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
}