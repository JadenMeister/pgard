// corpus: expect=low
import java.io.File;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class InvoiceController {
  @GetMapping("/invoice/{id}")
  File invoice(@PathVariable long id) {
    return new File("/srv/invoices", id + ".pdf");
  }
}
