// corpus: expect=low
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
class WebConfig {
  @Bean
  WebSecurityCustomizer customizer() {
    return web -> web.ignoring().requestMatchers("/swagger-ui/**", "/v3/api-docs/**");
  }
}
