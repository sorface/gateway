package by.sorface.gateway

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@Configuration
@SpringBootApplication
@RestController
open class GatewayApplication

@GetMapping("/token")
fun token(@AuthenticationPrincipal oidcUser: OidcUser, @RegisteredOAuth2AuthorizedClient auth2AuthorizedClient: OAuth2AuthorizedClient): Mono<Map<String, Any>?> {
    return Mono.defer { Mono.just(java.util.Map.of("user", oidcUser, "client", auth2AuthorizedClient)) }
}

fun main(args: Array<String>) {
    SpringApplication.run(GatewayApplication::class.java, *args)
}
