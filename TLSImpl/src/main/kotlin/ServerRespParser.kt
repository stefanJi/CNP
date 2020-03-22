import model.ContentType
import model.HandshakeData
import model.HandshakeType
import model.TLSPlaintext
import tls_flow.Alert
import tls_flow.Certificates
import tls_flow.ServerHello
import tls_flow.ServerKeyExchange
import java.io.InputStream

/**
 * Create by StefanJi in 2020-03-13
 */
class ServerRespParser {
    lateinit var serverHello: ServerHello
        private set
    lateinit var certificates: Certificates
        private set
    lateinit var serverKeyExchange: ServerKeyExchange
        private set
    var alert: Alert? = null
        private set

    fun parse(ins: InputStream) {
        while (true) {
            //TLSPlaintText is root struct, so param [length] not meaning
            val tlsPlaintext = TLSPlaintext().apply { parse(ins) }

            when (tlsPlaintext.contentType) {
                ContentType.Type.handshake -> {
                    println("server resp: handshake")
                    val handshakeData = HandshakeData().apply { parse(ins, tlsPlaintext.contentLength) }
                    when (handshakeData.handshakeType) {
                        HandshakeType.Type.server_hello -> {
                            println("server resp: server_hello")
                            serverHello = ServerHello().apply { parse(ins, handshakeData.contentLength) }
                            println(serverHello)
                            println("server resp: server_hello [done]")
                        }
                        HandshakeType.Type.certificate -> {
                            println("server resp: certificate")
                            certificates = Certificates().apply { parse(ins, handshakeData.contentLength) }
                            println(certificates)
                            println("server resp: certificate [done]")
                        }
                        HandshakeType.Type.server_key_exchange -> {
                            println("server resp: server_key_exchange")
                            serverKeyExchange = ServerKeyExchange().apply {
                                parse(ins, handshakeData.contentLength, serverHello.cipherSuite)
                            }
                            println("server resp: server_key_exchange [done]")
                        }
                        HandshakeType.Type.server_hello_done -> {
                            println("server resp: server_hello_done")
                            /*step2 done*/
                            return
                        }
                        HandshakeType.Type.certificate_verify -> {
                            println("server resp: certificate_verify")
                            TODO()
                        }
                        HandshakeType.Type.certificate_request -> {
                            println("server resp: certificate_request")
                            TODO()
                        }
                        HandshakeType.Type.finished -> {
                            println("server resp: finished")
                            TODO()
                        }
                        else -> error("Not match handshake type(${handshakeData.handshakeType})")
                    }
                }
                ContentType.Type.change_cipher_spec -> {
                    TODO()
                }
                ContentType.Type.application_data -> {
                    TODO()
                }
                ContentType.Type.alert -> {
                    println("handle alert")
                    alert = Alert().apply { parse(ins, tlsPlaintext.contentLength) }
                    if (alert?.level == Alert.Level.fatal) {
                        throw RuntimeException("Server alert a fatal signal. ${alert?.desc?.name}")
                    }
                    println("handle alert [done]")
                }
            }
        }
    }
}

