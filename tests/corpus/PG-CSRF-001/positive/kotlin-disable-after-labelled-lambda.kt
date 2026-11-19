// corpus: expect=PG-CSRF-001
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {
  @Bean
  fun chain(http: HttpSecurity, extra: List<String>): SecurityFilterChain {
    extra.firstOrNull()?.let loaded@{ name ->
      if (name.isBlank()) return@loaded
      register(name)
    }
    http.csrf { it.disable() }
    http.formLogin { }
    return http.build()
  }

  private fun register(name: String) {}
}
