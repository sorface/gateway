package by.sorface.gateway.config

import by.sorface.gateway.config.filters.RequestQueryWebSessionStoreWebFilter
import by.sorface.gateway.config.handlers.*
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler
import org.springframework.security.web.server.authorization.AuthorizationContext
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisIndexedWebSession
import reactor.core.publisher.Mono
import java.net.URI
import java.util.*

@EnableRedisIndexedWebSession
@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
open class OAuth2LoginSecurityConfig {

    @Bean
    open fun securityFilterChain(http: ServerHttpSecurity, clientRegistrationRepository: ReactiveClientRegistrationRepository): SecurityWebFilterChain {
        http
            .authorizeExchange { exchanges: ServerHttpSecurity.AuthorizeExchangeSpec ->
                exchanges.pathMatchers("/api/**").authenticated()
                exchanges.pathMatchers("/oauth2/authorization/passport").access { authentication: Mono<Authentication>, _: AuthorizationContext? ->
                    authentication.filter { obj: Authentication -> obj.isAuthenticated }
                        .flatMap { Mono.just(AuthorizationDecision(false)) }
                        .switchIfEmpty(Mono.just(AuthorizationDecision(true)))
                }
                exchanges.pathMatchers("/actuator/**").permitAll()
                exchanges.pathMatchers("/logout").authenticated()
                exchanges.anyExchange().authenticated()
            }
            .addFilterBefore(RequestQueryWebSessionStoreWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
            .oauth2Login { oAuth2LoginSpec: ServerHttpSecurity.OAuth2LoginSpec ->
                val pkceResolver = DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository)
                pkceResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce())

                oAuth2LoginSpec.authorizationRequestResolver(pkceResolver)

                val authenticationSuccessHandler = StateRedirectUrlServerAuthenticationSuccessHandler()
                oAuth2LoginSpec.authenticationSuccessHandler(authenticationSuccessHandler)

                val authenticationFailureHandler = HttpStatusJsonAuthenticationFailureHandler(HttpStatus.UNAUTHORIZED)
                oAuth2LoginSpec.authenticationFailureHandler(authenticationFailureHandler)
            }
            .exceptionHandling { exceptionHandlingSpec: ServerHttpSecurity.ExceptionHandlingSpec ->
                val accessDeniedHandler = HttpStatusJsonServerAccessDeniedHandler(HttpStatus.FORBIDDEN)
                exceptionHandlingSpec.accessDeniedHandler(accessDeniedHandler)

                val httpStatusJsonServerAuthenticationEntryPoint = HttpStatusJsonServerAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED)
                exceptionHandlingSpec.authenticationEntryPoint(httpStatusJsonServerAuthenticationEntryPoint)
            }
            .oidcLogout { spec: ServerHttpSecurity.OidcLogoutSpec -> spec.backChannel(Customizer.withDefaults()) }
            .logout { logoutSpec: ServerHttpSecurity.LogoutSpec ->
                val logoutHandler = DelegatingServerLogoutHandler(WebSessionServerLogoutHandler(), SecurityContextServerLogoutHandler())

                logoutSpec.logoutHandler(logoutHandler)
                logoutSpec.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
            }
            .oauth2ResourceServer { oAuth2ResourceServerSpec: ServerHttpSecurity.OAuth2ResourceServerSpec ->
                oAuth2ResourceServerSpec.jwt(Customizer.withDefaults()).authenticationFailureHandler(
                    HttpStatusJsonAuthenticationFailureHandler(
                        HttpStatus.UNAUTHORIZED
                    )
                )
            }
            .cors { it.disable() }
            .csrf { it.disable() }

        return http.build()
    }

    /**
     * Provides a custom ErrorWebExceptionHandler if one is not already present.
     *
     * @return the ErrorWebExceptionHandler
     */
    @Bean
    @ConditionalOnMissingBean(value = [ErrorWebExceptionHandler::class])
    open fun customErrorWebExceptionHandler(): ErrorWebExceptionHandler {
        return GlobalErrorWebExceptionHandler()
    }

    private fun oidcLogoutSuccessHandler(clientRegistrationRepository: ReactiveClientRegistrationRepository): ServerLogoutSuccessHandler {
        val delegate = OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository)

        return DelegateServerSuccessLogoutHandler(
            ServerLogoutSuccessHandler { exchange: WebFilterExchange, authentication: Authentication? ->
                exchange.exchange.request.queryParams.getFirst("location")?.let {
                    delegate.setPostLogoutRedirectUri(it)
                    delegate.setLogoutSuccessUrl(URI.create(it))
                }

                delegate.onLogoutSuccess(exchange, authentication)
            }
        )
    }
}
