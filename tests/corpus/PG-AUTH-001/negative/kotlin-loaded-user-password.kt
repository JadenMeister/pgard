// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

fun touch(id: Long, userRepository: UserRepository) {
    val user = userRepository.findById(id).get()
    userRepository.save(user)
}
