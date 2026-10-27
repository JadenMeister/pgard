// corpus: expect=PG-SQL-005
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface CustomerRepository extends JpaRepository<Customer, Long> {
  // #{[0]} is replaced by the text of the first argument before the query is parsed.
  @Query(value = "SELECT * FROM customers WHERE segment = '#{[0]}'", nativeQuery = true)
  List<Customer> bySegment(String segment);

  @Query("select c from #{#entityName} c where c.email = ?1")
  Customer byEmail(String email);
}
