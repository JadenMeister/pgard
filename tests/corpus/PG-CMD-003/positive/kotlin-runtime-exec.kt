// corpus: expect=PG-CMD-003
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class LsController {
    @GetMapping("/ls")
    fun ls(@RequestParam dir: String): Unit {
        val p = Runtime.getRuntime().exec("ls -l $dir")
        p.inputStream.bufferedReader().readText()
    }
}
