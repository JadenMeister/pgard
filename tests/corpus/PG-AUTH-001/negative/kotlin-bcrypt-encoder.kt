// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun signup(req: SignupRequest, userRepository: UserRepository, passwordEncoder: PasswordEncoder) {
    val user = User()
    user.password = passwordEncoder.encode(req.password)
    userRepository.save(user)
}
