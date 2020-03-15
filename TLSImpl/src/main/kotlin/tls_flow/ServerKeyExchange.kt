package tls_flow

import model.KeyExchangeAlgorithm
import java.io.InputStream

class ServerKeyExchange {

    lateinit var keyExchangeAlgorithm: KeyExchangeAlgorithm
        private set

    fun parse(ins: InputStream, length: Int, keyExchangeAlgorithm: KeyExchangeAlgorithm) {
        keyExchangeAlgorithm.algorithm.parse(ins, length)
        this.keyExchangeAlgorithm = keyExchangeAlgorithm
    }
}