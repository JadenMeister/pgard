// corpus: expect=PG-CMD-003
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class VideoController {
    @PostMapping("/transcode")
    fun transcode(@RequestParam input: String) {
        ProcessBuilder(listOf("ffmpeg", "-i", input, "out.mp4")).start()
    }
}
