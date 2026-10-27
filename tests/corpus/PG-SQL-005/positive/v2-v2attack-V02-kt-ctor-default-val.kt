// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
class Dao(private val jdbc: JdbcTemplate, private val table: String = "users") {
  fun all(): Any = jdbc.queryForList("SELECT * FROM " + table)
}
