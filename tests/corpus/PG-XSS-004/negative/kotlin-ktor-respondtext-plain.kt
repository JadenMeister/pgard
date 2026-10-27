// corpus: expect=none
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondText

suspend fun greet(call: ApplicationCall) {
    val name = call.parameters["name"]
    call.respondText("<h1>Hello $name</h1>")
}
