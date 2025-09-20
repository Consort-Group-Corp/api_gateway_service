package uz.consortgroup.api_gateway_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.time.Instant;

@RequiredArgsConstructor
public class JwtMaxAgeValidator implements OAuth2TokenValidator<Jwt> {

    private final Duration maxAge;
    private final Duration clockSkew;


    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Instant iat = token.getIssuedAt();
        if (iat == null) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "JWT is missing 'iat' claim", null));
        }

        Instant now = Instant.now().plus(clockSkew);
        Duration age = Duration.between(iat, now);

        if (age.compareTo(maxAge) > 0) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "JWT is older than allowed by gateway policy", null));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
