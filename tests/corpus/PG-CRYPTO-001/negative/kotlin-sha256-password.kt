// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun hash(password: String): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
