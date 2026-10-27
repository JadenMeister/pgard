// corpus: expect=none
package demo.jpa;

import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ProductQueryController {
  private final EntityManager em;
  ProductQueryController(EntityManager em) { this.em = em; }

  @GetMapping("/products")
  List<Product> byCategory(@RequestParam String category) {
    CriteriaBuilder cb = em.getCriteriaBuilder();
    CriteriaQuery<Product> cq = cb.createQuery(Product.class);
    Root<Product> root = cq.from(Product.class);
    cq.select(root).where(cb.equal(root.get("category"), category));
    return em.createQuery(cq).getResultList();
  }
}
