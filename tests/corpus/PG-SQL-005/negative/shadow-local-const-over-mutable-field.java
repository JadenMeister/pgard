// corpus: expect=none
import org.springframework.jdbc.core.JdbcTemplate;

class TenantDao {
  // The field can be changed by anything; the local below has its own fixed value.
  private String table = System.getProperty("tenant.table");
  private JdbcTemplate jdbc;

  int count() {
    String table = "tenant_accounts";
    return jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Integer.class);
  }
}
