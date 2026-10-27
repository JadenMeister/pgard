// corpus: expect=PG-SQL-005
import java.sql.Connection
import io.ktor.server.application.*
import io.ktor.server.routing.*
fun Route.r(conn: Connection) {
  post("/del") {
    val ids = call.parameters.getAll("id") ?: emptyList()
    outer@ for (id in ids) {
      conn.createStatement().executeUpdate("DELETE FROM t WHERE id = '$id'")
    }
  }
}
