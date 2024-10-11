package by.sorface.sorface.gateway.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
public class TestController {

    @GetMapping(value = "/token")
    public Mono<Map<String, Object>> getHome(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient, @AuthenticationPrincipal(errorOnInvalidType = true) OidcUser user) {
        return Mono.defer(() -> Mono.just(Map.of("token", oAuth2AuthorizedClient, "user", user)));
    }

}
