// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun key(): SecretKeySpec {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return SecretKeySpec(bytes, "AES")
}
