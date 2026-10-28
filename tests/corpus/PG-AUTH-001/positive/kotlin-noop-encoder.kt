// corpus: expect=PG-AUTH-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun encoder() = org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance()
