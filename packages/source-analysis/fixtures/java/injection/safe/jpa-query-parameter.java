import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class OrderController {
  private EntityManager em;

  @GetMapping("/orders")
  Object byStatus(@RequestParam String status) {
    return em.createQuery("select o from Order o where o.status = :status")
        .setParameter("status", status)
        .getResultList();
  }
}
