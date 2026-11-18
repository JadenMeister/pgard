// corpus: expect=none
import io.ktor.server.application.ApplicationCall
import io.ktor.server.html.respondHtml
import kotlinx.html.body
import kotlinx.html.p

suspend fun profile(call: ApplicationCall) {
    val bio = call.request.queryParameters["bio"] ?: ""
    call.respondHtml {
        body {
            p { +bio }
        }
    }
}
