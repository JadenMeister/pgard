// corpus: expect=PG-SQL-005
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class SearchController {
  private final EntityManager entityManager;

  SearchController(EntityManager entityManager) {
    this.entityManager = entityManager;
  }

  @PostMapping("/search")
  Object search(@RequestBody SearchForm form) {
    return entityManager
        .createNativeQuery("SELECT * FROM products WHERE title LIKE '%" + form.getTitle() + "%'")
        .getResultList();
  }
}
