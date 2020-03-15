import model.ECDHEAlgorithm
import java.io.BufferedInputStream
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Create by StefanJi in 2020-03-11
 */
fun tlsHandshake(host: String) {
    val add4 = Inet4Address.getByName(host)
    val tcpSocket = Socket()
    tcpSocket.connect(InetSocketAddress(add4, 443))
    val os = tcpSocket.getOutputStream() /*server's input*/
    val ins = tcpSocket.getInputStream() /*server's output*/

    val reqMaker = ClientReqMaker()
    val respParser = ServerRespParser()

    try {
        /*step1: send: client_hello*/
        os.write(reqMaker.makeClientHello())

        /*step2: receive: server_hello, server certificates, server_key_exchange, ..., server_hello_done*/
        respParser.parse(BufferedInputStream(ins))

        /*step3: send: client_key_exchange*/
        val serverCertificates = respParser.certificates.certificates
        val ecdheAlgorithm = respParser.serverKeyExchange.keyExchangeAlgorithm.algorithm as ECDHEAlgorithm
        os.write(reqMaker.ClientKeyExchange())

        /*step4: send: client_change_cipher_spec*/
        os.write(reqMaker.ChangeCipherSpec())

        /*step5: send: client finished*/
        os.write(reqMaker.Finished())

        /*step6: receive: server_change_cipher_spec, server finished*/
        TODO()
        /*handshake finish*/
    } catch (e: Exception) {
        e.printStackTrace()
    }

    os.close()
    ins.close()
    tcpSocket.close()
}

/**
 * Usage:java <build_dir> MainKt <host>
 */
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        throw IllegalArgumentException("Must put host")
    }
    tlsHandshake(args[0])
}