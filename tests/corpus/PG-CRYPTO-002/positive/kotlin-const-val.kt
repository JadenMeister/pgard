// corpus: expect=PG-CRYPTO-002
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

object Keys { const val SECRET = "kotlin-const-secret" }
fun key() = SecretKeySpec(Keys.SECRET.toByteArray(), "AES")
