// corpus: expect=none
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

class Config {
  @Bean
  SecurityFilterChain chain(HttpSecurity http, java.util.List<String> required) throws Exception {
    http.csrf(c -> c.disable())
        .sessionManagement(s -> {
          for (String item : required) {
            if (item == null) {
              break;
            }
          }
          s.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        })
        .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));
    return http.build();
  }
}
