// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun signup(req: SignupRequest, userRepository: UserRepository) {
    userRepository.save(User(email = req.email))
}
