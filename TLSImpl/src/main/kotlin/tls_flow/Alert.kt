package tls_flow

import Receivable
import readU8
import java.io.InputStream

/**
 * Create by StefanJi in 2020-03-15
 */
class Alert : Receivable {
    lateinit var level: Level
        private set
    lateinit var desc: Desc
        private set

    override fun parse(ins: InputStream, length: Int) {
        val l = ins.readU8()
        level = Level.values().find { l == it.value } ?: error("Not found match Alert($l)")
        val d = ins.readU8()
        desc = Desc.values().find { d == it.value } ?: error("Not found match Desc($d)")
    }

    enum class Level(val value: Int) {
        warning(1), fatal(2)
    }

    enum class Desc(val value: Int) {
        close_notify(0),
        unexpected_message(10),
        bad_record_mac(20),
        decryption_failed_RESERVED(21),
        record_overflow(22),
        decompression_failure(30),
        handshake_failure(40),
        no_certificate_RESERVED(41),
        bad_certificate(42),
        unsupported_certificate(43),
        certificate_revoked(44),
        certificate_expired(45),
        certificate_unknown(46),
        illegal_parameter(47),
        unknown_ca(48),
        access_denied(49),
        decode_error(50),
        decrypt_error(51),
        export_restriction_RESERVED(60),
        protocol_version(70),
        insufficient_security(71),
        internal_error(80),
        user_canceled(90),
        no_renegotiation(100),
        unsupported_extension(110)
    }

    companion object {
        const val SIZE = 0
    }
}