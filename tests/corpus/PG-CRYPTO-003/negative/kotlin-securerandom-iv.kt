// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun iv(): GCMParameterSpec {
    val bytes = ByteArray(12)
    SecureRandom().nextBytes(bytes)
    return GCMParameterSpec(128, bytes)
}
