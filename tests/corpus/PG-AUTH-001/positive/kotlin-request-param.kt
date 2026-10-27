// corpus: expect=PG-AUTH-001
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*
import org.springframework.web.bind.annotation.*

@PostMapping("/signup")
fun signup(@RequestParam email: String, @RequestParam password: String, userRepository: UserRepository) {
    userRepository.save(User(email, password))
}
