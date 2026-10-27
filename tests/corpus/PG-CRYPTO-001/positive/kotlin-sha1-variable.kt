// corpus: expect=PG-CRYPTO-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun hash(rawPassword: String): ByteArray {
    val md = MessageDigest.getInstance("SHA-1")
    md.update(rawPassword.toByteArray())
    return md.digest()
}
