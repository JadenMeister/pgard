// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun make(): String {
    val token = java.util.UUID.randomUUID().toString()
    return token
}
