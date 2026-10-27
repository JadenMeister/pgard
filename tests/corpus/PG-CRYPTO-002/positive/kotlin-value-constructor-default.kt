// corpus: expect=PG-CRYPTO-002
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*
import org.springframework.beans.factory.annotation.Value

class Signer(@Value("\${app.signing-key:dev-signing-key}") val key: String)
