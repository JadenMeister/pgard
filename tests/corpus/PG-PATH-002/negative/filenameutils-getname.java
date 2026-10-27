// corpus: expect=low
import java.io.File;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

class NameOnly {
  File target(HttpServletRequest request) {
    String name = FilenameUtils.getName(request.getParameter("file"));
    return new File("/srv/uploads", name);
  }
}
