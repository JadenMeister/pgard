// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun hash(password: String): String =
    org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(password)
