import model.*
import model.CipherSuite.Type
import utils.ECDHNamedCurveUtil
import utils.encodeLocal
import kotlin.random.Random


/**
 * Create by StefanJi in 2020-03-10
 */
class ClientReqMaker : ClientFlow {
    var randomTime = 0
        private set
    lateinit var random: ByteArray
        private set
    lateinit var preMasterSecret: ByteArray
        private set
    lateinit var masterSecret: ByteArray
        private set

    fun makeClientHello(): ByteArray {
        randomTime = (System.currentTimeMillis() / 1000L).toInt()
        random = Random(10).nextBytes(28)

        val sessionId = ByteArray(0)

        val clientHello = tls_flow.ClientHello(
            Version.Desc.V1_2,
            TlsRandomHeader(randomTime, random), sessionId,
            Type.values().map { CipherSuite(it) }.toTypedArray(),
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
    https://tools.ietf.org/html/rfc4492#section-5.4

    Actions of the sender:

    The server selects elliptic curve domain parameters and an ephemeral
    ECDH public key corresponding to these parameters according to the
    ECKAS-DH1 scheme from IEEE 1363.  It conveys this information to
    the client in the ServerKeyExchange message using the format defined
    above.

    Actions of the receiver:

    The client verifies the signature (when present) and retrieves the
    server's elliptic curve domain parameters and ephemeral ECDH public
    key from the ServerKeyExchange message.  (A possible reason for a
    fatal handshake failure is that the client's capabilities for
    handling elliptic curves and point formats are exceeded;
     *
     *
     *
     * Alice: the server
     * Bob:   the client
     */
    override fun ClientKeyExchange(serverCipherSuite: CipherSuite): ByteArray {
        if (serverCipherSuite.type == Type.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
            val serverECDHEAlgorithm = serverCipherSuite.type.KeyExchange().algorithm as ECDHEAlgorithm
            val namedCurve = serverECDHEAlgorithm.namedCurve!!

            /**
             * signature = RSA(ClientHello.random + ServerHello.random + ServerKeyExchange.params)
             */
            val alicePubKey = serverECDHEAlgorithm.pubKey
            val signature = serverECDHEAlgorithm.signature
            //TODO verify the signature

            // Generate ephemeral ECDH keypair
            val kp = ECDHNamedCurveUtil.generateKeyPair(namedCurve)
            val bobPubKey = kp.public.encodeLocal()
            val bobPriKey = kp.private.encodeLocal()

            preMasterSecret = with(ECDHNamedCurveUtil) { agreementSecret(bobPriKey, alicePubKey, namedCurve) }
            println("[ClientKeyExchange] premater_secret: ${preMasterSecret.contentToString()}")

            // send bob public key to alice
            val handshakeData =
                HandshakeData(HandshakeType.Type.client_key_exchange, ECDHEAlgorithm(bobPubKey).data())
            val tlsPlaintext = TLSPlaintext(ContentType.Type.handshake, Version.Desc.V1_2, handshakeData.data())
            return tlsPlaintext.data()
        } else {
            TODO("${serverCipherSuite.type} Not Support Now")
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
        val masterSecret = ByteArray(20) //TODO generate master secret
        val finishedLeable = "client finished".toByteArray(Charsets.UTF_8)
        val finished = ByteArray(40)
        try {
            TODO("encrypted handshake message")
//            PRF.computePRF(finished, masterSecret, finishedLeable, ByteArray(0))
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

