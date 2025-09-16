package uz.consortgroup.api_gateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration cors = new CorsConfiguration();

        // 1. ВСЕ возможные origins
        cors.setAllowedOriginPatterns(List.of(
                "http://localhost:*",
                "http://127.0.0.1:*",
                "http://0.0.0.0:*",
                "http://164.92.247.120:*",
                "https://164.92.247.120:*"
        ));

        // 2. ВСЕ методы
        cors.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "PATCH",
                "DELETE", "OPTIONS", "HEAD", "TRACE"
        ));

        // 3. ВСЕ заголовки (которые могут прийти от фронта)
        cors.setAllowedHeaders(List.of(
                "*",
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "X-CSRF-Token",
                "X-XSRF-TOKEN",
                "X-Forwarded-For",
                "X-Forwarded-Proto",
                "X-Forwarded-Host",
                "Cache-Control",
                "Pragma",
                "Expires",
                "If-Modified-Since",
                "If-None-Match",
                "Range",
                "Content-Range",
                "Content-Disposition",
                "Content-Length",
                "User-Agent",
                "Referer",
                "Sec-Fetch-Mode",
                "Sec-Fetch-Site",
                "Sec-Fetch-Dest"
        ));

        // 4. ВСЕ заголовки (которые фронт может читать из ответа)
        cors.setExposedHeaders(List.of(
                "Authorization",
                "Content-Disposition",
                "Location",
                "X-Total-Count",
                "Content-Range",
                "X-Rate-Limit-Limit",
                "X-Rate-Limit-Remaining",
                "X-Rate-Limit-Reset",
                "X-Request-ID",
                "X-Powered-By",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection"
        ));

        // 5. ВКЛЮЧИТЬ ВСЕ ВОЗМОЖНОСТИ
        cors.setAllowCredentials(true);
        cors.setMaxAge(7200L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);

        return new CorsWebFilter(source);
    }
}