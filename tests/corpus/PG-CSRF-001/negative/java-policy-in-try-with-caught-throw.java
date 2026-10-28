// corpus: expect=low
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
          try {
            for (String item : required) {
              if (item == null) {
                throw new IllegalArgumentException("missing");
              }
            }
            s.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
          } catch (IllegalArgumentException ignored) {
            // the policy stays unset
          }
        })
        .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));
    return http.build();
  }
}
