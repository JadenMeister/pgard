// corpus: expect=PG-SQL-005
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class OrderController {
  @PersistenceContext private EntityManager em;

  @GetMapping("/orders/{status}")
  List<Order> byStatus(@PathVariable String status) {
    return em.createQuery("select o from Order o where o.status = '" + status + "'", Order.class)
        .getResultList();
  }
}
