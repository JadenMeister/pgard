// corpus: expect=none
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondText

suspend fun ApplicationCall.greet() {
    val name = parameters["name"]
    respondText("Hello $name")
}
