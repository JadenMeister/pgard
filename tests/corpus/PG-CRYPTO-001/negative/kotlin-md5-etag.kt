// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun etag(body: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(body)
