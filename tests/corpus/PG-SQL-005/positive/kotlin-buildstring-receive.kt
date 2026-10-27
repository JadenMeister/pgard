// corpus: expect=PG-SQL-005
package com.example.ktor

import io.ktor.server.application.Application
import io.ktor.server.request.receive
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.sql.Connection

data class Filter(val owner: String, val minAmount: Int)

fun Application.module(connection: Connection) {
    routing {
        post("/payments/search") {
            val filter = call.receive<Filter>()
            val sql = buildString {
                append("SELECT * FROM payments WHERE owner = '")
                append(filter.owner)
                append("'")
            }
            connection.createStatement().executeQuery(sql)
        }
    }
}
