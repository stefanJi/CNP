import model.*
import kotlin.random.Random

/**
 * Create by StefanJi in 2020-03-10
 */
class ClientReqMaker : ClientFlow {
    var randomTime = 0
        private set
    lateinit var random: ByteArray
        private set

    fun makeClientHello(): ByteArray {
        randomTime = (System.currentTimeMillis() / 1000L).toInt()
        random = Random(10).nextBytes(28)

        val sessionId = ByteArray(0)

        val clientHello = tls_flow.ClientHello(
            Version.Desc.V1_2,
            TlsRandomHeader(randomTime, random), sessionId,
            CipherSuite.Type.values().map { CipherSuite(it) }.toTypedArray(),
            arrayOf(CompressionMethod(CompressionMethod.Type.NULL))
        )
        val handshakeData = HandshakeData(HandshakeType.Type.client_hello, clientHello.data())
        val tlsPlaintext = TLSPlaintext(
            ContentType.Type.handshake,
            Version.Desc.V1_2,
            handshakeData.data()
        )
        return tlsPlaintext.data()
    }

    override fun ClientHello(): ByteArray = makeClientHello()

    override fun Certificate(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ClientKeyExchange(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun CertificateVerify(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ChangeCipherSpec(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun Finished(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ApplicationData(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}

