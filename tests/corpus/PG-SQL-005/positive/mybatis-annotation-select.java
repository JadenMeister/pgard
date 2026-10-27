// corpus: expect=PG-SQL-005
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface TicketMapper {
  @Select("SELECT * FROM tickets WHERE status = #{status} ORDER BY ${orderBy}")
  List<Ticket> list(@Param("status") String status, @Param("orderBy") String orderBy);
}
