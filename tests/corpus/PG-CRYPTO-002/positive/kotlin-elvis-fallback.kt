// corpus: expect=PG-CRYPTO-002
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun key() = io.jsonwebtoken.security.Keys.hmacShaKeyFor(
    (System.getenv("JWT_KEY") ?: "kotlin-fallback-secret-0123456789abcdef").toByteArray())
