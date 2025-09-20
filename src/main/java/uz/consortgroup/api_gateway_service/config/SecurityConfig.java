package uz.consortgroup.api_gateway_service.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
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
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.beans.factory.annotation.Autowired;

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

                        // public
                        .pathMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .pathMatchers("/actuator/health").permitAll()
                        .pathMatchers("/api/v1/device-tokens/**").permitAll()
                        .pathMatchers("/api/v1/password/**").permitAll()
                        .pathMatchers("/api/v1/users/registration/**").permitAll()
                        .pathMatchers("/api/v1/users/*/verification").permitAll()
                        .pathMatchers("/api/v1/users/*/new-verification-code").permitAll()
                        .pathMatchers("/api/v1/users/*/new-password").permitAll()

                        // auth
                        .pathMatchers("/api/v1/auth/**").permitAll()

                        // role-based
                        .pathMatchers("/api/v1/super-admin/**").hasAuthority("SUPER_ADMIN")
                        .pathMatchers("/api/v1/users/course-orders/**")
                        .hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","HR","STUDENT")
                        .pathMatchers("/api/v1/users/search")
                        .hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","HR")
                        .pathMatchers("/api/v1/users/**").hasAnyAuthority("SUPER_ADMIN","ADMIN")
                        .pathMatchers("/api/v1/hr/**").hasAnyAuthority("SUPER_ADMIN","ADMIN","MENTOR","HR")
                        .pathMatchers("/api/v1/mentor/**").hasAnyAuthority("MENTOR","ADMIN","SUPER_ADMIN")

                        .anyExchange().permitAll()
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
                                .jwtAuthenticationConverter(source -> Mono.just(
                                        new AbstractAuthenticationToken(mapAuthorities(source)) {
                                            @Override public Object getCredentials() { return source.getTokenValue(); }
                                            @Override public Object getPrincipal() { return source.getSubject(); }
                                            { setAuthenticated(true); }
                                        }
                                ))
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
        if (roles == null) {
            return List.of();
        }
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
