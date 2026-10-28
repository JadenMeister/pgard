// corpus: expect=PG-CRYPTO-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun hash(password: String): String =
    com.google.common.hash.Hashing.sha1().hashString(password, Charsets.UTF_8).toString()
