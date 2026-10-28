// corpus: expect=none
import org.springframework.context.annotation.Bean
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

class CorsSetup {
  @Bean
  fun cors(): CorsConfigurationSource {
    val config = CorsConfiguration()
    config.allowedOrigins = listOf("https://app.example.com")
    config.allowCredentials = true
    val source = UrlBasedCorsConfigurationSource()
    source.registerCorsConfiguration("/**", config)
    return source
  }
}
