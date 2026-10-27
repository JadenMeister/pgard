// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun cipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
