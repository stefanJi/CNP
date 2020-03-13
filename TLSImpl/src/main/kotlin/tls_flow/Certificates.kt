package tls_flow

import Content
import Parseable
import readU24
import java.io.InputStream

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
class Certificates : Content, Parseable {
    var certificateSize = 0 /*u24*/

    override fun data(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun size(): Int {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun parse(ins: InputStream) {
        certificateSize = ins.readU24()
    }


    class Certificate : Content, Parseable {

        var length = 0 /*u24*/
            private set
        var version = 0 /*u1*/

        lateinit var serialName: ByteArray

        override fun data(): ByteArray {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }

        override fun size(): Int {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }

        override fun parse(ins: InputStream) {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }

    }
}