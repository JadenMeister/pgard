// corpus: expect=low
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

class Config {
  @Bean
  SecurityFilterChain chain(HttpSecurity http, boolean legacy) throws Exception {
    Customizer<CsrfConfigurer<HttpSecurity>> mode = Customizer.withDefaults();
    mode = c -> c.disable();
    http.csrf(mode).formLogin(Customizer.withDefaults());
    return http.build();
  }
}
