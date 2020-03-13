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

    val clientReqMaker = ClientReqMaker()
    os.write(clientReqMaker.makeClientHello())

    try {
        val bufferIns = BufferedInputStream(ins)
        while (true) {
            ServerResponse1().parse(bufferIns)
        }
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