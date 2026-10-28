// corpus: expect=PG-CRYPTO-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun hash(password: String): String =
    org.apache.commons.codec.digest.DigestUtils.md5Hex(password)
