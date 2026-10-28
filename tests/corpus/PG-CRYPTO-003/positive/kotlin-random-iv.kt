// corpus: expect=PG-CRYPTO-003
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun iv(): IvParameterSpec {
    val bytes = ByteArray(16)
    java.util.Random().nextBytes(bytes)
    return IvParameterSpec(bytes)
}
