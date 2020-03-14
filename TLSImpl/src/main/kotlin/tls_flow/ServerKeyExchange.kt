package tls_flow

import model.KeyExchangeAlgorithm
import java.io.InputStream

class ServerKeyExchange {

    fun parse(ins: InputStream, length: Int, keyExchangeAlgorithm: KeyExchangeAlgorithm) {
        keyExchangeAlgorithm.algorithm.parse(ins, length)
    }
}