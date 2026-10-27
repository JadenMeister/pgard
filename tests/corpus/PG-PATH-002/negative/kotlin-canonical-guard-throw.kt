// corpus: expect=low
import java.io.File
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class KotlinCanonicalController {
    private val root = File("/srv/kt").canonicalFile

    @GetMapping("/kt")
    fun read(@RequestParam name: String): Unit {
        val file = File(root, name).canonicalFile
        if (!file.path.startsWith(root.path + File.separator)) {
            throw IllegalArgumentException("outside the root")
        }
        file.readText()
    }
}
