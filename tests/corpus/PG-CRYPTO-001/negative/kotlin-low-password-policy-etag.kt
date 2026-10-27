// corpus: expect=low
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

class PasswordPolicyReport {
    fun etag(body: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(body)
}
