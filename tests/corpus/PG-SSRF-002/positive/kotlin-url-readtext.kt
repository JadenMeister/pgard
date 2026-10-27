// corpus: expect=PG-SSRF-002
import java.net.URL
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FetchController {
    @GetMapping("/fetch")
    fun fetch(@RequestParam url: String): String = URL(url).readText()
}
