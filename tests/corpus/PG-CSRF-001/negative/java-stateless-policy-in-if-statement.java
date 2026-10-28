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
    http.csrf(c -> c.disable()).oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));
    if (legacy) {
      http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
    return http.build();
  }
}
