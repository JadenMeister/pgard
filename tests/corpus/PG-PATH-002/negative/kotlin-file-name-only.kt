// corpus: expect=low
import java.io.File
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class KotlinNameController {
    @GetMapping("/kn")
    fun read(@RequestParam name: String): Unit {
        val leaf = File(name).name
        File("/srv/kn", leaf).readText()
    }
}
