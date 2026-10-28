// corpus: expect=none
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

class ReactiveConfig {
  @Bean
  SecurityWebFilterChain chain(ServerHttpSecurity http) {
    return http.authorizeExchange(e -> e.pathMatchers("/health").permitAll().anyExchange().authenticated()).build();
  }
}
