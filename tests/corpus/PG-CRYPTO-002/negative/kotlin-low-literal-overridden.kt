// corpus: expect=low
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun key(): SecretKeySpec {
    var material = "dev-only-key-material"
    System.getenv("APP_KEY")?.let { material = it }
    return SecretKeySpec(material.toByteArray(), "AES")
}
