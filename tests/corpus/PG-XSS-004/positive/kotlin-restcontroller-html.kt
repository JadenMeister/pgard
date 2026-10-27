// corpus: expect=PG-XSS-004
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class PageController {
    @GetMapping("/greet")
    fun greet(@RequestParam name: String): String {
        return "<h1>Hello $name</h1>"
    }
}
