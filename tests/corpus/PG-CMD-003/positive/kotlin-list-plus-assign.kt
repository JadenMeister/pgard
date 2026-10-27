// corpus: expect=PG-CMD-003
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FfmpegController {
    @PostMapping("/ffmpeg")
    fun run(@RequestParam input: String) {
        val cmd = mutableListOf("ffmpeg")
        cmd += listOf("-i", input)
        ProcessBuilder(cmd).start()
    }
}
