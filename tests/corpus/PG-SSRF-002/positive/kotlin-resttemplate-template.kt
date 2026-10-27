// corpus: expect=PG-SSRF-002
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate

@RestController
class FetchController(private val restTemplate: RestTemplate) {
    @GetMapping("/fetch")
    fun fetch(@RequestParam host: String) {
        restTemplate.getForObject("http://$host/status", String::class.java)
    }
}
