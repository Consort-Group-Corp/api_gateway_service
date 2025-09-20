package uz.consortgroup.api_gateway_service.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "security")
public class AppSecurityProps {
    private String token;
    private boolean tokenBase64 = false;
    private long clockSkewSeconds = 60;
    private long maxAccessTokenTtlSeconds = 3600;
}
