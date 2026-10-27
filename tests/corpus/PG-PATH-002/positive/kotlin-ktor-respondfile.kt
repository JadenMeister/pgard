// corpus: expect=PG-PATH-002
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.File

fun Route.downloads() {
    get("/download") {
        val name = call.parameters["name"]!!
        call.respondFile(File("/srv/downloads", name))
    }
}
