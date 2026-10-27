// corpus: expect=PG-PATH-002
import java.nio.file.Files
import java.nio.file.Paths
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class KotlinFileController {
    private val root = Paths.get("/srv/kt")

    @GetMapping("/kt")
    fun read(@RequestParam name: String): ByteArray {
        val path = root.resolve(name)
        return Files.readAllBytes(path)
    }
}
