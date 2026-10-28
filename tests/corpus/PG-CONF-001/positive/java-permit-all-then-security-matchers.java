// corpus: expect=PG-CONF-001
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

class Config {
  @Bean
  SecurityFilterChain chain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).securityMatchers(m -> m.requestMatchers("/a/**"));
    return http.build();
  }
}
