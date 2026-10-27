// corpus: expect=PG-CRYPTO-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

class Hasher {
    companion object { const val ALGORITHM = "MD5" }
    fun hash(password: String): ByteArray =
        MessageDigest.getInstance(ALGORITHM).digest(password.toByteArray())
}
