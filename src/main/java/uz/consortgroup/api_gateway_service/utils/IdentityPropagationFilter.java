package uz.consortgroup.api_gateway_service.utils;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class IdentityPropagationFilter implements GlobalFilter {

    private static final String HDR_AUTH_VALIDATED = "X-Auth-Validated";
    private static final String HDR_USER_ID        = "X-User-Id";
    private static final String HDR_USER_EMAIL     = "X-User-Email";
    private static final String HDR_USER_ROLES     = "X-User-Roles";
    private static final String HDR_REQUEST_ID     = "X-Request-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (isPreflight(exchange)) {
            return chain.filter(exchange);
        }
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .flatMap(auth -> propagateIfAuthenticated(exchange, chain, auth))
                .switchIfEmpty(chain.filter(exchange));
    }


    private boolean isPreflight(ServerWebExchange exchange) {
        return exchange.getRequest().getMethod() == HttpMethod.OPTIONS;
    }

    private Mono<Void> propagateIfAuthenticated(ServerWebExchange exchange,
                                                GatewayFilterChain chain,
                                                Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return chain.filter(exchange);
        }

        String userId  = extractUserId(auth);
        if (userId == null || userId.isBlank()) {
            return chain.filter(exchange);
        }

        String email   = extractEmail(auth);
        String roles   = extractRoles(auth);

        ServerHttpRequest.Builder req = exchange.getRequest().mutate()
                .header(HDR_AUTH_VALIDATED, "true")
                .header(HDR_USER_ID, userId)
                .header(HDR_REQUEST_ID, exchange.getRequest().getId());

        if (email != null && !email.isBlank()) {
            req.header(HDR_USER_EMAIL, email);
        }
        if (roles != null && !roles.isBlank()) {
            req.header(HDR_USER_ROLES, roles);
        }

        return chain.filter(exchange.mutate().request(req.build()).build());
    }

    private String extractUserId(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jat) {
            Jwt jwt = jat.getToken();
            return jwt.getClaimAsString("userId");
        }
        return null;
    }

    private String extractEmail(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jat) {
            return jat.getToken().getSubject();
        }
        Object p = auth.getPrincipal();
        return (p != null) ? p.toString() : null;
    }

    private String extractRoles(Authentication auth) {
        String fromAuthorities = (auth.getAuthorities() == null) ? "" :
                auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.joining(","));

        if (auth instanceof JwtAuthenticationToken jat) {
            List<String> rs = jat.getToken().getClaimAsStringList("roles");
            if (rs != null && !rs.isEmpty()) {
                return String.join(",", rs);
            }
        }
        return fromAuthorities;
    }
}
