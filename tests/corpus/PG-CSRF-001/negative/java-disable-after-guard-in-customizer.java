// corpus: expect=low
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

class Config {
  @Bean
  SecurityFilterChain chain(HttpSecurity http, boolean external) throws Exception {
    http.csrf(c -> {
      if (external) {
        return;
      }
      c.disable();
    }).formLogin(Customizer.withDefaults());
    return http.build();
  }
}
