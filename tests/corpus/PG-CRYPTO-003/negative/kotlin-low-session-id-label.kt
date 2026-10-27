// corpus: expect=low
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun label(): String {
    val sessionId = java.util.Random().nextInt(1000).toString()
    return "demo-" + sessionId
}
