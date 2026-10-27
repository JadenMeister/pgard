// corpus: expect=PG-CRYPTO-003
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

class Crypto {
    companion object { const val TRANSFORMATION = "RC4" }
    fun cipher(): Cipher = Cipher.getInstance(TRANSFORMATION)
}
