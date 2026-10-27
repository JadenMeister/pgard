// corpus: expect=PG-PATH-002
import java.io.File
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

@RestController
class NotesController {
    @GetMapping("/notes/{name}")
    fun note(@PathVariable name: String): Unit {
        File("/data/notes/" + name).readText()
    }
}
