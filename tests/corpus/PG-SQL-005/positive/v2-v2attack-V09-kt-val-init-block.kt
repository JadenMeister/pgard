// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
class Dao(private val jdbc: JdbcTemplate, t: String) {
  private val table: String
  init { table = t }
  fun all(): Any = jdbc.queryForList("SELECT * FROM $table")
}
