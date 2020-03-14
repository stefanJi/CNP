package tls_flow

import Receivable
import Sendable
import putU24
import readU24
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate


/**
 * Create by StefanJi in 2020-03-13
 *<pre>
 *opaque ASN.1Cert<1..2^24-1>;
 *
 *struct {
 *   ASN.1Cert certificate_list<0..2^24-1>;
 *} Certificate;
 * </pre>
 */
class Certificates : Sendable, Receivable {
    var certificates: Array<Certificate> = emptyArray()
        private set
    private val certificatesEncode = certificates.map { it.data() }

    constructor()
    constructor(certificates: Array<Certificate>) {
        this.certificates = certificates
    }

    override fun data(): ByteArray = ByteBuffer.allocate(size()).apply {
        putU24(size())
        certificatesEncode.forEach { put(it) }
    }.array()

    override fun size(): Int = certificatesEncode.sumBy { it.size }

    override fun parse(ins: InputStream, length: Int) {
        var offset = 0
        val cs = ArrayList<Certificate>()
        val certificatesLength = ins.readU24()
        while (offset < certificatesLength) {
            val certificateLength = ins.readU24()
            val certificate = Certificate().apply { parse(ins, certificateLength) }
            offset += 3 /*u24 certificateLength*/
            offset += certificateLength
            cs.add(certificate)
        }
        certificates = cs.toTypedArray()
    }

    override fun toString(): String {
        return "Certificates(certificates=${certificates.contentToString()})"
    }

    /**
     * <pre>
    enum {
    cert_fingerprint (0), cert (1), (255)
    } OpenPGPCertDescriptorType;

    opaque OpenPGPCertFingerprint<16..20>;

    opaque OpenPGPCert<0..2^24-1>;

    struct {
    OpenPGPCertDescriptorType descriptorType;
    select (descriptorType) {
    case cert_fingerprint: OpenPGPCertFingerprint;
    case cert: OpenPGPCert;
    }
    } Certificate;
     * </pre>
     */
    class Certificate : Sendable, Receivable {

        lateinit var certificate: X509Certificate
            private set
        private var certificateEncoded = ByteArray(0)

        constructor()

        constructor(certificate: X509Certificate) {
            this.certificate = certificate
            this.certificateEncoded = certificate.encoded
        }

        override fun data(): ByteArray = certificateEncoded

        override fun size(): Int = certificateEncoded.size

        override fun parse(ins: InputStream, length: Int) {
            val cf = CertificateFactory.getInstance("X.509")
            certificate = cf.generateCertificate(ins) as X509Certificate
        }
    }
}