// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun signup(req: SignupRequest, jdbcTemplate: org.springframework.jdbc.core.JdbcTemplate, passwordEncoder: PasswordEncoder) {
    jdbcTemplate.update("INSERT INTO users (email, password) VALUES (?, ?)", req.email, passwordEncoder.encode(req.password))
}
