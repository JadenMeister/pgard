// corpus: expect=none
import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class MemberController {
  private final EntityManager em;

  MemberController(EntityManager em) {
    this.em = em;
  }

  @GetMapping("/members/{team}")
  List<Member> byTeam(@PathVariable String team) {
    return em.createQuery("select m from Member m where m.team = :team", Member.class)
        .setParameter("team", team)
        .getResultList();
  }

  List<Object> nativeByRank(int rank) {
    return em.createNativeQuery("SELECT * FROM members WHERE rank = ?1")
        .setParameter(1, rank)
        .getResultList();
  }
}
