import java.sql.Connection

fun Application.routes(connection: Connection) {
    routing {
        get("/users/{id}") {
            val id = call.parameters["id"]
            connection.createStatement().executeQuery("SELECT * FROM users WHERE id = $id")
        }
    }
}
