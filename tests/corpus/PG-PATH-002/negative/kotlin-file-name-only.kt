// corpus: expect=low
import java.io.File
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class KotlinNameController {
    @GetMapping("/kn")
    fun read(@RequestParam name: String): String {
        val leaf = File(name).name
        return File("/srv/kn", leaf).readText()
    }
}
