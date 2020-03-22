package utils

import model.NamedCurve
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

/**
 * Create by StefanJi in 2020-03-22
 */
data class ECKeyPair(val private: ECPrivateKey, val public: ECPublicKey)

fun ECPublicKey.encodeLocal(): ByteArray = this.q.getEncoded(true)
fun ECPrivateKey.encodeLocal(): ByteArray = this.d.toByteArray()

fun NamedCurve.toParamterSpec() = ECNamedCurveTable.getParameterSpec(name)

object ECDHNamedCurveUtil {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private const val ALGORITHM = "ECDH"
    private val kpg = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)
    private val keyFactory = KeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)
    private val keyAgreement = KeyAgreement.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)

    fun ByteArray.parsePublicKey(namedCurve: NamedCurve): ECPublicKey =
        ECPublicKeySpec(
            namedCurve.toParamterSpec().curve.decodePoint(this),
            ECNamedCurveTable.getParameterSpec(namedCurve.name)
        ).let {
            keyFactory.generatePublic(it) as ECPublicKey
        }

    fun ByteArray.parsePrivateKey(namedCurve: NamedCurve): ECPrivateKey =
        ECPrivateKeySpec(BigInteger(this), namedCurve.toParamterSpec()).let {
            keyFactory.generatePrivate(it) as ECPrivateKey
        }

    fun generateKeyPair(namedCurve: NamedCurve): ECKeyPair {
        kpg.initialize(ECGenParameterSpec(namedCurve.name))
        return kpg.genKeyPair().let { ECKeyPair(it.private as ECPrivateKey, it.public as ECPublicKey) }
    }

    fun agreementSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    fun agreementSecret(privateKey: ByteArray, publicKey: ByteArray, namedCurve: NamedCurve): ByteArray {
        val private = privateKey.parsePrivateKey(namedCurve)
        val public = publicKey.parsePublicKey(namedCurve)
        return agreementSecret(private, public)
    }
}