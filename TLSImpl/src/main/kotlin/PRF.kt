import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

/**
 * This class provides functionality for computation
 * of PRF values for TLS (http://www.ietf.org/rfc/rfc2246.txt)
 * and SSL v3 (http://wp.netscape.com/eng/ssl3) protocols.
 */
object PRF {
    private var md5_mac: Mac? = null
    private var sha_mac: Mac? = null
    internal var md5: MessageDigest? = null
    internal var sha: MessageDigest? = null
    private var md5_mac_length = 0
    private var sha_mac_length = 0
    private val logger: Logger? = Logger()
    @Throws(NoSuchAlgorithmException::class)
    private fun init() {
        md5_mac = Mac.getInstance("HmacMD5")
        sha_mac = Mac.getInstance("HmacSHA1")
        md5_mac_length = md5_mac!!.getMacLength()
        sha_mac_length = sha_mac!!.getMacLength()
        md5 = MessageDigest.getInstance("MD5")
        sha = MessageDigest.getInstance("SHA-1")
    }

    /**
     * Computes the value of SSLv3 pseudo random function.
     *
     * @param out:    the buffer to fill up with the value of the function.
     * @param secret: the buffer containing the secret value to generate prf.
     * @param seed:   the seed to be used.
     */
    @Synchronized
    @Throws(NoSuchAlgorithmException::class)
    fun computePRF_SSLv3(out: ByteArray, secret: ByteArray?, seed: ByteArray?) {
        if (sha == null) {
            init()
        }
        var pos = 0
        var iteration = 1
        var digest: ByteArray?
        while (pos < out.size) {
            val pref = ByteArray(iteration)
            Arrays.fill(pref, (64 + iteration++).toByte())
            sha!!.update(pref)
            sha!!.update(secret)
            sha!!.update(seed)
            md5!!.update(secret)
            md5!!.update(sha!!.digest())
            digest = md5!!.digest() // length == 16
            if (pos + 16 > out.size) {
                System.arraycopy(digest, 0, out, pos, out.size - pos)
                pos = out.size
            } else {
                System.arraycopy(digest, 0, out, pos, 16)
                pos += 16
            }
        }
    }

    /**
     * Computes the value of TLS pseudo random function.
     *
     * @param out:       the buffer to fill up with the value of the function.
     * @param secret:    the buffer containing the secret value to generate prf.
     * @param str_bytes: the label bytes to be used.
     * @param seed:      the seed to be used.
     */
    @Synchronized
    @Throws(GeneralSecurityException::class)
    fun computePRF(
        out: ByteArray, secret: ByteArray?,
        str_bytes: ByteArray, seed: ByteArray
    ) {
        var secret = secret
        if (sha_mac == null) {
            init()
        }
        // Do concatenation of the label with the seed:
// (metterings show that is is faster to concatenate the arrays
// and to call HMAC.update on cancatenation, than twice call for
// each of the part, i.e.:
// time(HMAC.update(label+seed))
//          < time(HMAC.update(label)) + time(HMAC.update(seed))
// but it takes more memmory (approximaty on 4%)
/*
        byte[] tmp_seed = new byte[seed.length + str_bytes.length];
        System.arraycopy(str_bytes, 0, tmp_seed, 0, str_bytes.length);
        System.arraycopy(seed, 0, tmp_seed, str_bytes.length, seed.length);
        seed = tmp_seed;
        */
        val keyMd5: SecretKeySpec
        val keySha1: SecretKeySpec
        if (secret == null || secret.size == 0) {
            secret = ByteArray(8)
            keyMd5 = SecretKeySpec(secret, "HmacMD5")
            keySha1 = SecretKeySpec(secret, "HmacSHA1")
        } else {
            val length = secret.size shr 1 // division by 2
            val offset = secret.size and 1 // remainder
            keyMd5 = SecretKeySpec(
                secret, 0, length + offset,
                "HmacMD5"
            )
            keySha1 = SecretKeySpec(
                secret, length, length
                        + offset, "HmacSHA1"
            )
        }
        //byte[] str_bytes = label.getBytes();
        if (logger != null) {
            logger.println("secret[" + secret.size + "]: ")
            logger.printAsHex(16, "", " ", secret)
            logger.println("label[" + str_bytes.size + "]: ")
            logger.printAsHex(16, "", " ", str_bytes)
            logger.println("seed[" + seed.size + "]: ")
            logger.printAsHex(16, "", " ", seed)
            logger.println("MD5 key:")
            logger.printAsHex(16, "", " ", keyMd5.encoded)
            logger.println("SHA1 key:")
            logger.printAsHex(16, "", " ", keySha1.encoded)
        }
        md5_mac!!.init(keyMd5)
        sha_mac!!.init(keySha1)
        var pos = 0
        md5_mac!!.update(str_bytes)
        var hash = md5_mac!!.doFinal(seed) // A(1)
        while (pos < out.size) {
            md5_mac!!.update(hash)
            md5_mac!!.update(str_bytes)
            md5_mac!!.update(seed)
            pos += if (pos + md5_mac_length < out.size) {
                md5_mac!!.doFinal(out, pos)
                md5_mac_length
            } else {
                System.arraycopy(
                    md5_mac!!.doFinal(), 0, out,
                    pos, out.size - pos
                )
                break
            }
            // make A(i)
            hash = md5_mac!!.doFinal(hash)
        }
        if (logger != null) {
            logger.println("P_MD5:")
            logger.printAsHex(md5_mac_length, "", " ", out)
        }
        pos = 0
        sha_mac!!.update(str_bytes)
        hash = sha_mac!!.doFinal(seed) // A(1)
        var sha1hash: ByteArray
        while (pos < out.size) {
            sha_mac!!.update(hash)
            sha_mac!!.update(str_bytes)
            sha1hash = sha_mac!!.doFinal(seed)
            var i = 0
            while ((i < sha_mac_length) and (pos < out.size)) {
                out[pos++] = out[pos++] xor sha1hash[i]
                i++
            }
            // make A(i)
            hash = sha_mac!!.doFinal(hash)
        }
        if (logger != null) {
            logger.println("PRF:")
            logger.printAsHex(sha_mac_length, "", " ", out)
        }
    }

    internal class Logger {
        fun println(s: String?) {
            kotlin.io.println(s)
        }

        fun printAsHex(i: Int, s: String, s1: String, secret: ByteArray?) {
            kotlin.io.println(i.toString() + s + s1 + Arrays.toString(secret))
        }
    }
}