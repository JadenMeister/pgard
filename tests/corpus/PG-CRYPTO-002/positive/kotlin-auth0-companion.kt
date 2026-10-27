// corpus: expect=PG-CRYPTO-002
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

class Tokens {
    companion object { private const val SECRET = "kotlin-companion-secret" }
    fun algorithm() = com.auth0.jwt.algorithms.Algorithm.HMAC256(SECRET)
}
