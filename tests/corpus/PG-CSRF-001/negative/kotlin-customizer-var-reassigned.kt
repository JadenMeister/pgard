// corpus: expect=low
import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

class Config {
  @Bean
  fun chain(http: HttpSecurity, legacy: Boolean): SecurityFilterChain {
    var mode = Customizer.withDefaults<CsrfConfigurer<HttpSecurity>>()
    if (legacy) {
      mode = Customizer { it.disable() }
    }
    http.csrf(mode)
    http.formLogin(Customizer.withDefaults())
    return http.build()
  }
}
