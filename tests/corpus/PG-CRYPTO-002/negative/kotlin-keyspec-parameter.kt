// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun key(material: ByteArray) = SecretKeySpec(material, "AES")
