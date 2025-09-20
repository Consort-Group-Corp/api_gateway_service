package uz.consortgroup.api_gateway_service.utils;

import java.util.stream.Collectors;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class IdentityPropagationFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .flatMap(auth -> {
                    Object principal = auth.getPrincipal();

                    if (principal instanceof Jwt jwt) {
                        String userId = jwt.getClaimAsString("userId");
                        String email = jwt.getSubject();
                        String roles = auth.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(","));

                        exchange.getRequest().getId();
                        ServerHttpRequest req = exchange.getRequest().mutate()
                                .header("X-User-Id", userId == null ? "" : userId)
                                .header("X-User-Email", email == null ? "" : email)
                                .header("X-User-Roles", roles)
                                .header("X-Auth-Validated", "true")
                                .header("X-Request-Id",
                                        exchange.getRequest().getId())
                                .build();

                        return chain.filter(exchange.mutate().request(req).build());
                    }
                    return chain.filter(exchange);
                }).switchIfEmpty(chain.filter(exchange));
    }
}
