// corpus: expect=none
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface NoteMapper {
  @Select("SELECT * FROM notes WHERE owner = #{owner} AND title LIKE CONCAT('%', #{term}, '%')")
  java.util.List<Note> search(@Param("owner") String owner, @Param("term") String term);

  @Insert("INSERT INTO notes(owner, title) VALUES (#{owner}, #{title})")
  int add(Note note);

  @Delete({"DELETE FROM notes", "WHERE id = #{id}"})
  int remove(long id);
}
