// corpus: expect=low
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

class Config {
  @Bean
  fun chain(http: HttpSecurity, profile: String): SecurityFilterChain {
    http {
      csrf { disable() }
      oauth2ResourceServer { jwt { } }
    }
    listOf(profile).forEach { if (it.isEmpty()) return http.build() }
    http {
      sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }
    }
    return http.build()
  }
}
