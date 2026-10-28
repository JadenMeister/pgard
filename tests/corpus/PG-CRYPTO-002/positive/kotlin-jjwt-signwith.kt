// corpus: expect=PG-CRYPTO-002
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun token(): String = io.jsonwebtoken.Jwts.builder()
    .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "kotlin-jjwt-secret").compact()
