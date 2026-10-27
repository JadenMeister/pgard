// corpus: expect=none
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.csrf.CookieCsrfTokenRepository

@Configuration
class SecurityConfig {
  @Bean
  fun chain(http: HttpSecurity): SecurityFilterChain = http {
    csrf { csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse() }
    formLogin { }
  }
}
