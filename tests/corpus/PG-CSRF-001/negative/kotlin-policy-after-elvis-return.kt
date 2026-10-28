// corpus: expect=low
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

class Config {
  @Bean
  fun chain(http: HttpSecurity): SecurityFilterChain = http {
    csrf { disable() }
    sessionManagement {
      val profile = System.getenv("PROFILE") ?: return@sessionManagement
      println(profile)
      sessionCreationPolicy = SessionCreationPolicy.STATELESS
    }
    oauth2ResourceServer { jwt { } }
  }
}
