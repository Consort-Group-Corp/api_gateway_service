package uz.consortgroup.api_gateway_service.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;

import reactor.core.publisher.Mono;
import uz.consortgroup.api_gateway_service.security.JsonAccessDeniedHandler;
import uz.consortgroup.api_gateway_service.security.JsonAuthenticationEntryPoint;
import uz.consortgroup.api_gateway_service.security.JwtMaxAgeValidator;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private final JsonAuthenticationEntryPoint jsonAuthenticationEntryPoint;
    private final JsonAccessDeniedHandler jsonAccessDeniedHandler;

    @Autowired
    public SecurityConfig(JsonAuthenticationEntryPoint jsonAuthenticationEntryPoint,
                          JsonAccessDeniedHandler jsonAccessDeniedHandler) {
        this.jsonAuthenticationEntryPoint = jsonAuthenticationEntryPoint;
        this.jsonAccessDeniedHandler = jsonAccessDeniedHandler;
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder(AppSecurityProps props) {
        byte[] secret = props.isTokenBase64()
                ? Base64.getDecoder().decode(props.getToken())
                : props.getToken().getBytes(StandardCharsets.UTF_8);

        SecretKey key = new SecretKeySpec(secret, "HmacSHA256");
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withSecretKey(key).build();

        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefault();
        OAuth2TokenValidator<Jwt> timestamp = new JwtTimestampValidator(Duration.ofSeconds(props.getClockSkewSeconds()));
        OAuth2TokenValidator<Jwt> maxAge = new JwtMaxAgeValidator(
                Duration.ofSeconds(props.getMaxAccessTokenTtlSeconds()),
                Duration.ofSeconds(props.getClockSkewSeconds())
        );

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(defaultValidators, timestamp, maxAge));
        return decoder;
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                     ReactiveJwtDecoder jwtDecoder) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // public endpoints
                        .pathMatchers(
                                "/v3/api-docs/",
                                "/v3/api-docs/swagger-config",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/webjars/**",
                                "/user/v3/api-docs",
                                "/user/v3/api-docs/**",
                                "/course/v3/api-docs",
                                "/course/v3/api-docs/**",
                                "/forum/v3/api-docs",
                                "/forum/v3/api-docs/**",
                                "/webinar/v3/api-docs",
                                "/webinar/v3/api-docs/**",
                                "/payment/v3/api-docs",
                                "/payment/v3/api-docs/**",
                                "/support/v3/api-docs",
                                "/support/v3/api-docs/**"
                        ).permitAll()

                        .pathMatchers(
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/v3/api-docs/swagger-config",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/webjars/**",
                                "/actuator/health",
                                "/actuator/health/**"
                        ).permitAll()

                        .pathMatchers("/actuator/health").permitAll()
                        .pathMatchers("/api/v1/device-tokens/**").permitAll()
                        .pathMatchers("/api/v1/password/**").permitAll()
                        .pathMatchers("/api/v1/users/registration/**").permitAll()
                        .pathMatchers("/api/v1/users/*/verification").permitAll()
                        .pathMatchers("/api/v1/users/*/new-verification-code").permitAll()
                        .pathMatchers("/api/v1/users/*/new-password").permitAll()
                        .pathMatchers("/api/certificates/**").permitAll() //TODO Закроем после тестирование

                        // auth
                        .pathMatchers("/api/v1/auth/**").permitAll()

                        // --- payment-service --- (доступ всем)
                        .pathMatchers("/api/v1/click/**").permitAll()
                        .pathMatchers("/api/v1/paycom/**").permitAll()
                        .pathMatchers("/api/v1/orders/**").permitAll()

                        // --- webinar-service ---
                        .pathMatchers(HttpMethod.POST, "/api/v1/webinars/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/webinars/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.DELETE, "/api/v1/webinars/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.GET, "/api/v1/webinars/**").hasAnyAuthority("SUPER_ADMIN", "ADMIN", "MENTOR", "HR", "STUDENT")

                        // --- support-service ---
                        .pathMatchers(HttpMethod.GET, "/api/v1/support/presets").authenticated()
                        .pathMatchers(HttpMethod.POST, "/api/v1/support/tickets").authenticated()
                        .pathMatchers("/api/v1/support/presets/super-admin/**").hasAuthority("SUPER_ADMIN")
                        .pathMatchers(HttpMethod.GET, "/api/v1/support/tickets").hasAnyAuthority("SUPER_ADMIN", "SUPPORT")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/support/tickets/**").hasAnyAuthority("SUPER_ADMIN", "SUPPORT")

                        // --- course-service ---
                        .pathMatchers(HttpMethod.POST, "/api/v1/courses/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.DELETE, "/api/v1/courses/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.GET, "/api/v1/courses/**").hasAnyAuthority("SUPER_ADMIN", "ADMIN", "MENTOR", "HR", "STUDENT")

                        // Исправленные пути для медиа-файлов уроков
                        .pathMatchers(HttpMethod.POST, "/api/v1/lessons/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.DELETE, "/api/v1/lessons/**").hasAnyAuthority("SUPER_ADMIN", "MENTOR")
                        .pathMatchers(HttpMethod.GET, "/api/v1/lessons/**").hasAnyAuthority("SUPER_ADMIN", "ADMIN", "MENTOR", "HR", "STUDENT")

                        // --- user-service ---
                        .pathMatchers("/api/v1/super-admin/**").hasAuthority("SUPER_ADMIN")
                        .pathMatchers("/api/v1/users/course-orders/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","HR","STUDENT")
                        .pathMatchers("/api/v1/users/search").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","HR")
                        .pathMatchers("/api/v1/users/**").hasAnyAuthority("SUPER_ADMIN","ADMIN")
                        .pathMatchers("/api/v1/hr/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","HR")
                        .pathMatchers("/api/v1/mentor/**").hasAnyAuthority("MENTOR","ADMIN","SUPER_ADMIN")

                        // --- forum-service ---
                        .pathMatchers("/api/v1/forums/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR")
                        .pathMatchers("/api/v1/forum/forum-topic/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","STUDENT")
                        .pathMatchers("/api/v1/forum/forum-comment/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","STUDENT")
                        .pathMatchers("/api/v1/forum/likes/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","STUDENT")
                        .pathMatchers("/api/v1/forum/complaints/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","STUDENT")
                        .pathMatchers("/api/v1/forum/moderation/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MODERATOR")
                        .pathMatchers("/api/v1/forum/forbidden-words/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MODERATOR")

                        // прочее — требуем аутентификацию
                        .anyExchange().authenticated()
                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(jsonAuthenticationEntryPoint)
                        .accessDeniedHandler(jsonAccessDeniedHandler)
                )
                .oauth2ResourceServer(o -> o
                        .authenticationEntryPoint(jsonAuthenticationEntryPoint)
                        .accessDeniedHandler(jsonAccessDeniedHandler)
                        .jwt(jwt -> jwt
                                .jwtDecoder(jwtDecoder)
                                .jwtAuthenticationConverter(source -> {
                                    var authorities = mapAuthorities(source);
                                    return Mono.just(new JwtAuthenticationToken(source, authorities, source.getSubject()));
                                })
                        )
                )
                .build();
    }

    private Collection<? extends GrantedAuthority> mapAuthorities(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles == null || roles.isEmpty()) {
            String userType = jwt.getClaimAsString("userType");
            if (userType != null && !userType.isBlank()) {
                roles = List.of(userType);
            }
        }
        if (roles == null) return List.of();
        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}
