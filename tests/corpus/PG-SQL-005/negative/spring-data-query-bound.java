// corpus: expect=none
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OrderRepository extends JpaRepository<Order, Long> {
  @Query("select o from #{#entityName} o where o.status = :status")
  List<Order> byStatus(@Param("status") String status);

  @Query(value = "SELECT * FROM orders WHERE customer_id = ?1 AND total > ?2", nativeQuery = true)
  List<Order> big(long customerId, java.math.BigDecimal min);

  @Query("select o from Order o where o.owner = :#{#user.name}")
  List<Order> byUser(@Param("user") User user);
}
