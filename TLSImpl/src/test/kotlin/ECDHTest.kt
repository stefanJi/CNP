import model.NamedCurve
import org.junit.Assert
import org.junit.Test
import utils.ECDHNamedCurveUtil
import utils.encodeLocal

/**
 * Create by StefanJi in 2020-03-22
 */

class ECDHTest {

    @Test
    fun testKeyExchange() {
        val namedCurve = NamedCurve.secp256r1
        with(ECDHNamedCurveUtil) {

            val aliceKp = generateKeyPair(namedCurve)
            val alicePublicKey = aliceKp.public.encodeLocal()
            val alickPrivateKey = aliceKp.private.encodeLocal()

            val bobKp = generateKeyPair(namedCurve)
            val bobPublicKey = bobKp.public.encodeLocal()
            val bobPrivateKey = bobKp.private.encodeLocal()

            val aliceSecret = agreementSecret(alickPrivateKey, bobPublicKey, namedCurve)
            val bobSecret = agreementSecret(bobPrivateKey, alicePublicKey, namedCurve)

            Assert.assertArrayEquals(aliceSecret, bobSecret)
        }
    }
}