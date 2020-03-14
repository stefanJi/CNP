package model

import Sendable
import putU16
import putU8
import readU16
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * <pre>
 * struct {
 *     uint8 major;
 *     uint8 minor;
 * } ProtocolVersion;
 *
 * enum {
 *     change_cipher_spec(20), alert(21), handshake(22),
 *     application_data(23), (255)
 * } model.ContentType;
 *
 * struct {
 *     model.ContentType type;
 *     ProtocolVersion version;
 *     uint16 length;
 *     opaque fragment[TLSPlaintext.length];
 * } TLSPlaintext;
 * </pre>
 */
class TLSPlaintext : Sendable {

    lateinit var contentType: ContentType.Type
        private set
    lateinit var version: Version.Desc
        private set
    var contentLength: Int = 0
        private set
    var fragment: ByteArray = ByteArray(0)
        private set

    constructor()

    constructor(contentType: ContentType.Type, version: Version.Desc, fragment: ByteArray) {
        this.contentType = contentType
        this.version = version
        this.fragment = fragment
        this.contentLength = this.fragment.size
    }

    override fun data(): ByteArray {
        return ByteBuffer.allocate(size()).apply {
            putU8(contentType.value)
            putU8(version.major)
            putU8(version.minor)
            putU16(contentLength)
            put(fragment)
        }.array()
    }

    override fun size(): Int = 1/*content type uint8*/ + 1/*major version uint8*/ +
            1/*minor version unit8*/ + 2/*fragment length uint16*/ + fragment.size

    fun parse(ins: InputStream) {
        contentType = ContentType().apply { parse(ins, ContentType.SIZE) }.type
        version = Version().apply { parse(ins, ContentType.SIZE) }.desc
        contentLength = ins.readU16()
    }
}