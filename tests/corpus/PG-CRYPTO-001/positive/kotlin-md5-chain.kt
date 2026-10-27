// corpus: expect=PG-CRYPTO-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun hash(password: String): ByteArray =
    MessageDigest.getInstance("MD5").digest(password.toByteArray())
