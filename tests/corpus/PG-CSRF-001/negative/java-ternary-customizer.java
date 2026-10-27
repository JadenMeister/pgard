// corpus: expect=low
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

class Config {
  @Bean
  SecurityFilterChain chain(HttpSecurity http, boolean flag) throws Exception {
    http.csrf(flag ? Customizer.withDefaults() : AbstractHttpConfigurer::disable).formLogin(Customizer.withDefaults());
    return http.build();
  }
}
