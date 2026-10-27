// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun checksum(input: java.io.InputStream): ByteArray {
    val md = MessageDigest.getInstance("MD5")
    val buffer = ByteArray(8192)
    while (true) {
        val n = input.read(buffer)
        if (n < 0) break
        md.update(buffer, 0, n)
    }
    return md.digest()
}
