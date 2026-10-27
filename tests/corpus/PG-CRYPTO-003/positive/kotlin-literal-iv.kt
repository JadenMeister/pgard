// corpus: expect=PG-CRYPTO-003
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun iv() = IvParameterSpec("fixed-iv-0123456".toByteArray())
