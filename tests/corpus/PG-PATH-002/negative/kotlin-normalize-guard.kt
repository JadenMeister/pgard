// corpus: expect=low
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class KotlinGuardController {
    private val base: Path = Paths.get("/srv/kt").toAbsolutePath().normalize()

    @GetMapping("/kt")
    fun read(@RequestParam name: String): ByteArray {
        val p = base.resolve(name).normalize()
        require(p.startsWith(base))
        return Files.readAllBytes(p)
    }
}
