package by.sorface.gateway.config

import by.sorface.gateway.service.RedisReactiveOAuth2AuthorizedClientService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import java.net.URI

@Configuration
@EnableWebFluxSecurity
class SecurityConfig(
    private val authorizedClientService: RedisReactiveOAuth2AuthorizedClientService,
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository
) {

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .csrf { it.disable() }
            .authorizeExchange {
                it.pathMatchers("/actuator/**").permitAll()
                    .pathMatchers("/login/**", "/oauth2/**").permitAll()
                    .anyExchange().authenticated()
            }
            .oauth2Login {
                it.authenticationSuccessHandler(authenticationSuccessHandler())
            }
            .logout {
                it.logoutSuccessHandler(oidcLogoutSuccessHandler())
            }
            .build()
    }

    @Bean
    fun authorizedClientRepository(): ServerOAuth2AuthorizedClientRepository {
        return WebSessionServerOAuth2AuthorizedClientRepository()
    }

    @Bean
    fun authenticationSuccessHandler(): ServerAuthenticationSuccessHandler {
        val redirectHandler = RedirectServerAuthenticationSuccessHandler()
        redirectHandler.setLocation(URI.create("/"))
        return redirectHandler
    }

    @Bean
    fun oidcLogoutSuccessHandler(): ServerLogoutSuccessHandler {
        val oidcLogoutHandler = OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository)
        oidcLogoutHandler.setPostLogoutRedirectUri("{baseUrl}")
        return oidcLogoutHandler
    }
} 