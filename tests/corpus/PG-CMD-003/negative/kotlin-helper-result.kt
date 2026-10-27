// corpus: expect=low
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class KotlinHelperController {
    @GetMapping("/run")
    fun run(@RequestParam job: String) {
        val script = scriptFor(job)
        ProcessBuilder("sh", "-c", script).start()
    }

    private fun scriptFor(job: String): String = "run-" + job.lowercase()
}
