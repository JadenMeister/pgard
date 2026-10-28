// corpus: expect=PG-CRYPTO-003
import java.security.*
import javax.crypto.*
import javax.crypto.spec.*
import java.util.*

import kotlin.random.Random
fun make(): String {
    val token = Random.nextInt().toString()
    return token
}
