// corpus: expect=PG-SQL-005
import org.springframework.jdbc.core.JdbcTemplate as Jt
class D(private val ops: Jt) {
  fun f(filter: String): Any = ops.queryForList(BASE + filter)
  companion object { private const val BASE = "SELECT * FROM t WHERE " }
}
