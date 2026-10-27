// corpus: expect=PG-AUTH-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun register(email: String, password: String, repo: UserRepository) {
    val user = User()
    user.password = password
    repo.save(user)
}
