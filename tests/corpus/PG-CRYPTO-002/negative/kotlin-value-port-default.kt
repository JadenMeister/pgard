// corpus: expect=none
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*
import org.springframework.beans.factory.annotation.Value

class Config(@Value("\${server.port:8080}") val port: Int)
