// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
open class Base(val jdbc: JdbcTemplate) {
  open val table = "t"
  fun all(): Any = jdbc.queryForList("SELECT * FROM $table")
}
