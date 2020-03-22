package tls_flow

import model.CipherSuite
import java.io.InputStream

class ServerKeyExchange {

    lateinit var cipherSuite: CipherSuite
        private set

    fun parse(ins: InputStream, length: Int, type: CipherSuite) {
        this.cipherSuite = type
        this.cipherSuite.type.KeyExchange().algorithm.parse(ins, length)
    }
}