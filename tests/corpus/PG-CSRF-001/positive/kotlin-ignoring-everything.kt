// corpus: expect=PG-CSRF-001
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

class Config {
  @Bean
  fun chain(http: HttpSecurity): SecurityFilterChain = http {
    csrf { ignoringRequestMatchers("/**") }
    formLogin { }
  }
}
