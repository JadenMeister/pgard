// corpus: expect=low
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;

class CorsSetup {
  @Bean
  CorsConfigurationSource cors() {
    CorsConfiguration config = new CorsConfiguration();
    boolean credentials = System.getenv("CORS_CREDENTIALS") != null;
    config.setAllowedOrigins(List.of("*"));
    config.setAllowCredentials(credentials);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }
}
