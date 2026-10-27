// corpus: expect=PG-CRYPTO-003
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun cipher(): Cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
