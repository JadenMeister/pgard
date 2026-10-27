// corpus: expect=low
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FormatController {
    private val formats = setOf("png", "jpg")

    @GetMapping("/convert")
    fun convert(@RequestParam format: String) {
        require(format in formats)
        ProcessBuilder("convert", "in.bmp", "out.$format").start()
    }
}
