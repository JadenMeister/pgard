// corpus: expect=PG-SQL-005
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ProductSearch {
  private final Connection connection;

  ProductSearch(Connection connection) {
    this.connection = connection;
  }

  @GetMapping("/products")
  ResultSet find(@RequestParam String category, @RequestParam(required = false) String brand)
      throws SQLException {
    StringBuilder sql = new StringBuilder("SELECT * FROM products WHERE 1=1");
    sql.append(" AND category = '").append(category).append("'");
    if (brand != null) {
      sql.append(" AND brand = '").append(brand).append("'");
    }
    Statement statement = connection.createStatement();
    return statement.executeQuery(sql.toString());
  }
}
