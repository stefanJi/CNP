import model.HandshakeData
import model.Version
import tls_flow.Certificates
import tls_flow.ServerHello
import java.io.InputStream

/**
 * Create by StefanJi in 2020-03-13
 */
class ServerResponse1 {
    lateinit var type: ContentType.Type
        private set
    lateinit var version: Version.Desc
        private set
    lateinit var serverHello: ServerHello
        private set
    lateinit var certificates: Certificates
        private set

    var length: Int = 0

    fun parse(ins: InputStream) {
        type = ContentType().apply { parse(ins) }.type
        version = Version().apply { parse(ins) }.desc
        length = ins.readU16()

        when (type) {
            ContentType.Type.handshake -> {
                println("server resp: handshake")
                val handshakeData = HandshakeData().apply { parse(ins) }
                when (handshakeData.handshakeType) {
                    HandshakeType.Type.server_hello -> {
                        println("server resp: server_hello")
                        serverHello = ServerHello().apply { parse(ins) }
                        println(serverHello)
                        println("server resp: server_hello [done]")
                    }
                    HandshakeType.Type.certificate -> {
                        println("server resp: certificate")
                        certificates = Certificates().apply { parse(ins) }
                    }
                    HandshakeType.Type.server_key_exchange -> {
                        println("server resp: server_key_exchange")
                        TODO()
                    }
                    HandshakeType.Type.server_hello_done -> {
                        println("server resp: server_hello_done")
                        TODO()
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
                }
            }
            ContentType.Type.change_cipher_spec -> {
                TODO()
            }
            ContentType.Type.application_data -> {
                TODO()
            }
            ContentType.Type.alert -> {
                TODO()
            }
        }
    }
}

