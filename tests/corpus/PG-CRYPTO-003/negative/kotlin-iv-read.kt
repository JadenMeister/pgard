// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun iv(input: java.io.InputStream): IvParameterSpec {
    val bytes = ByteArray(16)
    input.read(bytes)
    return IvParameterSpec(bytes)
}
