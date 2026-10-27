// corpus: expect=PG-CRYPTO-002
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun key() = SecretKeySpec("kotlin-aes-key-literal".toByteArray(), "AES")
