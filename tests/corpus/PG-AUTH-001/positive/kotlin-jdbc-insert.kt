// corpus: expect=PG-AUTH-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun signup(req: SignupRequest, jdbcTemplate: org.springframework.jdbc.core.JdbcTemplate) {
    jdbcTemplate.update("INSERT INTO users (email, password) VALUES (?, ?)", req.email, req.password)
}
