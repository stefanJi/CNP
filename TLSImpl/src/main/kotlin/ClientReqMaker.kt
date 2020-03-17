import model.*
import tls_flow.ServerKeyExchange
import java.security.KeyPairGenerator
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

    /**
     * https://tools.ietf.org/html/rfc4492#section-5.7
     */
    override fun ClientKeyExchange(serverKeyExchange: ServerKeyExchange): ByteArray {
        if (serverKeyExchange.keyExchangeAlgorithm.algorithm is ECDHEAlgorithm) {
            val serverECDHEAlgorithm = serverKeyExchange.keyExchangeAlgorithm.algorithm as ECDHEAlgorithm
            val alicePubKey = serverECDHEAlgorithm.pubKey
            val signature = serverECDHEAlgorithm.signature

            // Generate ephemeral ECDH keypair
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
            kpg.initialize(256) /*for secp256r1*/
            val kp = kpg.generateKeyPair()
            val ourPk = kp.public.encoded
            val bobPublicKey = ourPk.copyOfRange(ourPk.size - 65, ourPk.size)

            //TODO generate secret

            // send to server our public key
            val handshakeData =
                HandshakeData(HandshakeType.Type.client_key_exchange, ECDHEAlgorithm(bobPublicKey).data())
            val tlsPlaintext = TLSPlaintext(ContentType.Type.handshake, Version.Desc.V1_2, handshakeData.data())
            return tlsPlaintext.data()
        } else {
            throw NotImplementedError("Not implement this key exchange algorithm")
        }
    }

    override fun CertificateVerify(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ChangeCipherSpec(): ByteArray {
        val tlsPlaintext = TLSPlaintext(
            ContentType.Type.change_cipher_spec,
            Version.Desc.V1_2,
            ByteArray(1) { 1 }
        )
        return tlsPlaintext.data()
    }

    override fun Finished(): ByteArray {
        // RPF(master_secret, finished_label, hash(handshake_message))
        // handshake_message: All of the data from all messages in this handshake (not
        //including any HelloRequest messages) up to, but not including,
        //this message. This is only data visible at the handshake layer
        //and does not include record layer headers
        val masterSecret = ByteArray(20)//todo
        val finishedLeable = "client finished".toByteArray(Charsets.UTF_8)
        val finished = ByteArray(40)
        try {
            PRF.computePRF(finished, masterSecret, finishedLeable, ByteArray(0))
        } catch (e: Exception) {
            e.printStackTrace()
        }
        val tlsPlaintext = TLSPlaintext(
            ContentType.Type.handshake,
            Version.Desc.V1_2,
            finished
        )
        return tlsPlaintext.data()
    }

    override fun ApplicationData(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}

