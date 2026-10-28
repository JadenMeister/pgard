// corpus: expect=low
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

class Config {
  @Bean
  fun chain(http: HttpSecurity, flag: Boolean): SecurityFilterChain = http {
    csrf { disable() }
    sessionManagement {
      flag.takeIf { it }?.let { return@sessionManagement }
      sessionCreationPolicy = SessionCreationPolicy.STATELESS
    }
    oauth2ResourceServer { jwt { } }
  }
}
