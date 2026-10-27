// corpus: expect=PG-SQL-005
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class InvoiceController {
  private final NamedParameterJdbcTemplate namedJdbc;

  InvoiceController(NamedParameterJdbcTemplate namedJdbc) {
    this.namedJdbc = namedJdbc;
  }

  @GetMapping("/invoices")
  Object list(@RequestParam String customer, @RequestParam String sort) {
    String sql = "SELECT * FROM invoices WHERE customer = :customer ORDER BY " + sort;
    return namedJdbc.queryForList(sql, Map.of("customer", customer));
  }
}
