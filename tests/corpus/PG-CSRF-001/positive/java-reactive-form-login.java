// corpus: expect=PG-CSRF-001
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

class ReactiveConfig {
  @Bean
  SecurityWebFilterChain chain(ServerHttpSecurity http) {
    return http.csrf().disable()
        .authorizeExchange().anyExchange().authenticated()
        .and().formLogin().and().build();
  }
}
