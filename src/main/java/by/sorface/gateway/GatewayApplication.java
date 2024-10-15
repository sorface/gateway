package by.sorface.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@Configuration
@SpringBootApplication
@RestController
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @GetMapping("/token")
    public Mono<Map<String, Object>> token(@AuthenticationPrincipal OidcUser oidcUser, @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient auth2AuthorizedClient) {
        return Mono.defer(() -> Mono.just(Map.of("user", oidcUser, "client", auth2AuthorizedClient)));
    }
}
