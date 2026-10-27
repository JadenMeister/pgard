// corpus: expect=PG-PATH-002
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import java.io.File

fun Route.upload() {
    post("/upload") {
        val multipart = call.receiveMultipart()
        multipart.forEachPart { part ->
            if (part is PartData.FileItem) {
                val target = File("/srv/uploads/" + part.originalFileName)
                target.writeBytes(ByteArray(0))
            }
        }
    }
}
