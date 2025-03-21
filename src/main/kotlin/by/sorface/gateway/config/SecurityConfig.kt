package by.sorface.gateway.config

import by.sorface.gateway.config.entrypoints.HttpStatusJsonServerAuthenticationEntryPoint
import by.sorface.gateway.config.handlers.*
import by.sorface.gateway.config.resolvers.SpaServerOAuth2AuthorizationRequestResolver
import by.sorface.gateway.properties.*
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.web.ServerProperties
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.cloud.gateway.config.GlobalCorsProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.data.redis.core.RedisKeyValueAdapter
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseCookie
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
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
import org.springframework.session.ReactiveSessionRepository
import org.springframework.session.Session
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisIndexedWebSession
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.server.session.CookieWebSessionIdResolver
import org.springframework.web.server.session.WebSessionIdResolver
import java.net.URI

@EnableWebFlux
@Configuration
@EnableWebFluxSecurity
@EnableRedisIndexedWebSession(redisNamespace = "gateway:sessions", maxInactiveIntervalInSeconds = 432000)
@EnableRedisRepositories(enableKeyspaceEvents = RedisKeyValueAdapter.EnableKeyspaceEvents.ON_STARTUP)
@EnableReactiveMethodSecurity
class SecurityConfig(
    private val signInProperties: SignInProperties,
    private val signOutProperties: SignOutProperties,
    private val securityWhiteList: SecurityWhiteList
) {

    private val log = LoggerFactory.getLogger(SecurityConfig::class.java)

    @Bean
    fun securityFilterChain(http: ServerHttpSecurity, clientRegistrationRepository: ReactiveClientRegistrationRepository,
                            globalCorsProperties: GlobalCorsProperties): SecurityWebFilterChain {
        http
            .cors(Customizer.withDefaults())
            .authorizeExchange { exchanges: ServerHttpSecurity.AuthorizeExchangeSpec ->
                exchanges.pathMatchers(*securityWhiteList.permitAllPatterns.toTypedArray()).permitAll()
                exchanges.pathMatchers(HttpMethod.OPTIONS).permitAll()
                exchanges.anyExchange().authenticated()
            }
            .oauth2Login { oAuth2LoginSpec: ServerHttpSecurity.OAuth2LoginSpec ->
                val pkceResolver = DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository)
                pkceResolver.setAuthorizationRequestCustomizer { builder ->
                    OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder)
                }

                val spaServerOAuth2AuthorizationRequestResolver = SpaServerOAuth2AuthorizationRequestResolver(pkceResolver, signInProperties.redirectQueryParam)
                oAuth2LoginSpec.authorizationRequestResolver(spaServerOAuth2AuthorizationRequestResolver)

                oAuth2LoginSpec.authenticationSuccessHandler(StateRedirectUrlServerAuthenticationSuccessHandler())

                val authenticationFailureHandler = HttpStatusJsonAuthenticationFailureHandler(HttpStatus.UNAUTHORIZED)
                oAuth2LoginSpec.authenticationFailureHandler(authenticationFailureHandler)
            }
            .exceptionHandling { exceptionHandlingSpec: ServerHttpSecurity.ExceptionHandlingSpec ->
                val accessDeniedHandler = HttpStatusJsonServerAccessDeniedHandler(HttpStatus.FORBIDDEN)
                exceptionHandlingSpec.accessDeniedHandler(accessDeniedHandler)

                val httpStatusJsonServerAuthenticationEntryPoint =
                    HttpStatusJsonServerAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED)
                exceptionHandlingSpec.authenticationEntryPoint(httpStatusJsonServerAuthenticationEntryPoint)
            }
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
            .csrf { it.disable() }

        return http.build()
    }

    @Bean
    fun corsConfigSource(globalCorsProperties: GlobalCorsProperties): CorsConfigurationSource {
        val corsConfig = CorsConfiguration()

        val globalCorsConfiguration = globalCorsProperties.corsConfigurations["/**"]
            ?: throw Exception("No global cors configuration found")

        log.info("CORS CONFIG -> {}{}", System.lineSeparator(), ObjectMapper().writeValueAsString(globalCorsConfiguration))

        corsConfig.allowedOrigins = globalCorsConfiguration.allowedOrigins
        corsConfig.allowedMethods = globalCorsConfiguration.allowedMethods
        corsConfig.allowedHeaders = globalCorsConfiguration.allowedHeaders
        corsConfig.allowCredentials = globalCorsConfiguration.allowCredentials

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", corsConfig)

        return source
    }

    @Bean
    @Primary
    fun defaultWebSessionIdResolver(
        serverProperties: ServerProperties,
        gatewaySessionCookieProperties: GatewaySessionCookieProperties,
        reactiveSessionRepository: ReactiveSessionRepository<out Session>,
    ): WebSessionIdResolver {
        val webSessionIdResolver = CookieWebSessionIdResolver()
        webSessionIdResolver.cookieName = gatewaySessionCookieProperties.name

        webSessionIdResolver.addCookieInitializer { cookieBuilder: ResponseCookie.ResponseCookieBuilder ->
            cookieBuilder.httpOnly(gatewaySessionCookieProperties.httpOnly)
            cookieBuilder.domain(gatewaySessionCookieProperties.domain)
            cookieBuilder.path(gatewaySessionCookieProperties.path)
            cookieBuilder.secure(gatewaySessionCookieProperties.secure)
            cookieBuilder.sameSite(gatewaySessionCookieProperties.sameSite.attributeValue())
        }

        return webSessionIdResolver
    }



    @Bean
    @ConditionalOnMissingBean(value = [ErrorWebExceptionHandler::class])
    fun customErrorWebExceptionHandler(): ErrorWebExceptionHandler {
        return GlobalErrorWebExceptionHandler()
    }

    private fun oidcLogoutSuccessHandler(clientRegistrationRepository: ReactiveClientRegistrationRepository): ServerLogoutSuccessHandler {
        val oidcBackChannelServerLogoutHandler = OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository)

        return DelegateServerSuccessLogoutHandler(
            ServerLogoutSuccessHandler { exchange: WebFilterExchange, authentication: Authentication ->
                exchange.exchange.request.queryParams.getFirst(signOutProperties.redirectQueryParam)?.let {
                    oidcBackChannelServerLogoutHandler.setPostLogoutRedirectUri(it)
                    oidcBackChannelServerLogoutHandler.setLogoutSuccessUrl(URI.create(it))
                }

                oidcBackChannelServerLogoutHandler.onLogoutSuccess(exchange, authentication)
            }
        )
    }

}
