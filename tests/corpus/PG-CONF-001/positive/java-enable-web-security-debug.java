// corpus: expect=PG-CONF-001
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@EnableWebSecurity(debug = true)
class SecurityConfig {
}
