// corpus: expect=low
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class SecurityConfig {
  @Bean
  SecurityFilterChain chain(HttpSecurity http, SecurityProperties props) throws Exception {
    try {
      if (props.getRealm() == null) {
        throw new IllegalStateException("security.realm is required");
      }
    } catch (IllegalStateException e) {
      return http.build();
    }
    http.csrf(c -> c.disable()).formLogin(Customizer.withDefaults());
    return http.build();
  }

  interface SecurityProperties {
    String getRealm();
  }
}
