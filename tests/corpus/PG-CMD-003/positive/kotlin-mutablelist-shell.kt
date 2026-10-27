// corpus: expect=PG-CMD-003
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class MaintenanceController {
    @PostMapping("/maintenance")
    fun run(@RequestBody script: String) {
        val command = mutableListOf("/bin/sh", "-c")
        command.add(script)
        ProcessBuilder(command).inheritIO().start()
    }
}
