// corpus: expect=PG-XSS-004
import io.ktor.server.application.ApplicationCall
import io.ktor.server.html.respondHtml
import kotlinx.html.body
import kotlinx.html.unsafe

suspend fun profile(call: ApplicationCall) {
    val bio = call.request.queryParameters["bio"] ?: ""
    call.respondHtml {
        body {
            unsafe { +bio }
        }
    }
}
