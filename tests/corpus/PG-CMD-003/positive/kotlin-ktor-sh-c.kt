// corpus: expect=PG-CMD-003
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.diag() {
    get("/ping") {
        val host = call.parameters["host"] ?: "localhost"
        ProcessBuilder("sh", "-c", "ping -c 1 $host").start()
        call.respondText("ok")
    }
}
