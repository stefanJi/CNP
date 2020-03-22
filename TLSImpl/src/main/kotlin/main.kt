import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.security.Security

/**
 * Create by StefanJi in 2020-03-11
 */
object TlsImpl {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    lateinit var tcpSocket: Socket
        private set
    lateinit var os: OutputStream
        private set
    lateinit var ins: InputStream
        private set

    fun connect(host: String) {
        val add4 = Inet4Address.getByName(host)
        tcpSocket = Socket()
        tcpSocket.connect(InetSocketAddress(add4, 443))
        os = tcpSocket.getOutputStream() /*server's input*/
        ins = tcpSocket.getInputStream() /*server's output*/
    }

    fun handshake() {
        val reqMaker = ClientReqMaker()
        val respParser = ServerRespParser()

        try {
            /*step1: send: client_hello*/
            os.write(reqMaker.makeClientHello())

            /*step2: receive: server_hello, server certificates, server_key_exchange, ..., server_hello_done*/
            respParser.parse(BufferedInputStream(ins))

            /*step3: send: client_key_exchange*/
            val serverCertificates = respParser.certificates.certificates
            os.write(reqMaker.ClientKeyExchange(respParser.serverKeyExchange.cipherSuite))

            /*step4: send: client_change_cipher_spec*/
            os.write(reqMaker.ChangeCipherSpec())

            /*step5: send: client finished*/
            os.write(reqMaker.Finished())

            /*step6: receive: server_change_cipher_spec, server finished*/
            respParser.parse(ins)
            /*handshake finish*/
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun sendData(bytes: ByteArray) {}

    fun close() {
        kotlin.runCatching {
            os.close()
            ins.close()
            tcpSocket.close()
        }
    }
}

/**
 * Usage:java <build_dir> MainKt <host>
 */
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        throw IllegalArgumentException("Must put host")
    }
    TlsImpl.connect(args[0])
    TlsImpl.handshake()
    //TODO send and read data
    TlsImpl.close()
}