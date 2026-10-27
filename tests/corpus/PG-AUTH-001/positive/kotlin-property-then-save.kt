// corpus: expect=PG-AUTH-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun signup(req: SignupRequest, userRepository: UserRepository) {
    val user = User()
    user.password = req.password
    userRepository.save(user)
}
