// corpus: expect=low
import org.springframework.context.annotation.Bean
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.web.SecurityFilterChain

class Config {
  @Bean
  fun chain(http: HttpSecurity, flag: Boolean): SecurityFilterChain {
    val custom = if (flag) Customizer.withDefaults() else Customizer { it.disable() }
    http.csrf(custom)
    http.formLogin(Customizer.withDefaults())
    return http.build()
  }
}
