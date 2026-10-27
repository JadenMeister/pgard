// corpus: expect=low
import org.springframework.jdbc.core.JdbcTemplate;

class StatsDao {
  private JdbcTemplate jdbc;

  // Tables.EVENTS is defined in another file, so it is only inferred to be fixed text.
  Object count() {
    return jdbc.queryForObject("SELECT COUNT(*) FROM " + Tables.EVENTS, Long.class);
  }
}
