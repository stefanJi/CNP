import model.CipherSuite
import tls_flow.ServerKeyExchange
import java.io.InputStream
import java.nio.ByteBuffer

interface Sendable {
    fun data(): ByteArray

    fun size(): Int
}

interface Receivable {
    fun parse(ins: InputStream, length: Int)
}

interface ClientFlow {
    fun ClientHello(): ByteArray
    fun Certificate(): ByteArray
    fun ClientKeyExchange(serverCipherSuite: CipherSuite): ByteArray
    fun CertificateVerify(): ByteArray
    fun ChangeCipherSpec(): ByteArray
    fun Finished(): ByteArray
    fun ApplicationData(): ByteArray
}

interface ServerFlow {
    fun ServerHello(): ByteArray
    fun Certificate(): ByteArray
    fun ServerKeyExchange(): ByteArray
    fun CertificateRequest(): ByteArray
    fun ServerHelloDone(): ByteArray
    fun ChangeCipherSpec(): ByteArray
    fun Finished(): ByteArray
    fun ApplicationData(): ByteArray
}

//region read extensions

fun ByteBuffer.getU16(): Int = (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.getU24(): Int =
    (get().toInt() and 0xFF shl 16) or (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.getU32(): Int =
    (get().toInt() and 0xFF shl 24) or (get().toInt() and 0xFF shl 16) or (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.putU8(value: Int) = run {
    put(value.toByte())
}

fun ByteBuffer.putU16(value: Int) = run {
    put((value shr 8).toByte())
    put((value and 0xFF).toByte())
}

fun ByteBuffer.putU24(value: Int) = run {
    put((value shr 16).toByte())
    put((value shr 8 and 0xFF).toByte())
    put((value and 0xFF).toByte())
}

fun ByteBuffer.putU32(value: Int) = run {
    put((value shr 24).toByte())
    put((value shr 16 and 0xFF).toByte())
    put((value shr 8 and 0xFF).toByte())
    put((value and 0xFF).toByte())
}

fun InputStream.readU8() = read()

fun InputStream.readU16(): Int {
    return (read() and 0xFF shl 8) or (read())
}

fun InputStream.readU24(): Int {
    return (read() and 0xFF shl 16) or (read() and 0xFF shl 8) or (read())
}

fun InputStream.readU32(): Int {
    return (read() and 0xFF shl 24) or (read() and 0xFF shl 16) or (read() and 0xFF shl 8) or (read())
}
//endregion
