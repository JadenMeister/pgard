import java.sql.Connection

fun Application.routes(connection: Connection) {
    routing {
        get("/users/{id}") {
            val statement = connection.prepareStatement("SELECT * FROM users WHERE id = ?")
            statement.setString(1, call.parameters["id"])
            statement.executeQuery()
        }
    }
}
