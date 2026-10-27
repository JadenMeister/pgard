// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun signup(req: SignupRequest, userRepository: UserRepository, encoder: PasswordEncoder) {
    userRepository.save(User(email = req.email, password = encoder.encode(req.password)))
}
