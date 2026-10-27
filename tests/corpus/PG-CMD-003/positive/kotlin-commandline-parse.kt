// corpus: expect=PG-CMD-003
import org.apache.commons.exec.CommandLine
import org.apache.commons.exec.DefaultExecutor
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class TraceController {
    @GetMapping("/trace")
    fun trace(@RequestParam host: String) {
        val line = CommandLine.parse("traceroute $host")
        DefaultExecutor().execute(line)
    }
}
