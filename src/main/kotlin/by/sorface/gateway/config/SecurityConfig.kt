package by.sorface.gateway.config

import by.sorface.gateway.config.security.entrypoints.HttpStatusJsonServerAuthenticationEntryPoint
import by.sorface.gateway.config.security.handlers.*
import by.sorface.gateway.config.security.repository.RedisReactiveOidcSessionRepository
import by.sorface.gateway.config.security.resolvers.SpaServerOAuth2AuthorizationRequestResolver
import by.sorface.gateway.properties.GatewaySessionCookieProperties
import by.sorface.gateway.properties.SecurityWhiteList
import by.sorface.gateway.properties.SignInProperties
import by.sorface.gateway.service.RedisReactiveOAuth2AuthorizedClientService
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.cloud.gateway.config.GlobalCorsProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseCookie
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.session.CookieWebSessionIdResolver
import org.springframework.web.server.session.WebSessionIdResolver

@EnableWebFlux
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
class SecurityConfig(
    private val signInProperties: SignInProperties,
    private val securityWhiteList: SecurityWhiteList
) {

    private val log = LoggerFactory.getLogger(SecurityConfig::class.java)

    @Bean
    fun securityFilterChain(
        http: ServerHttpSecurity,
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        globalCorsProperties: GlobalCorsProperties,
        redisReactiveOAuth2AuthorizedClientService: RedisReactiveOAuth2AuthorizedClientService,
        oAuth2ClientServerLogoutSuccessHandler: OAuth2ClientServerLogoutSuccessHandler,
        redirectClientInitiatedServerLogoutHandler: RedirectClientInitiatedServerLogoutHandler,
        redisReactiveOidcSessionRepository: RedisReactiveOidcSessionRepository
    ): SecurityWebFilterChain {
        http
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
                oAuth2LoginSpec.authorizedClientService(redisReactiveOAuth2AuthorizedClientService)

                val authenticationFailureHandler = HttpStatusJsonAuthenticationFailureHandler(HttpStatus.UNAUTHORIZED)
                oAuth2LoginSpec.authenticationFailureHandler(authenticationFailureHandler)
            }
            .oidcLogout { oidcLogoutSpec ->
                oidcLogoutSpec.backChannel { }
                oidcLogoutSpec.oidcSessionRegistry(redisReactiveOidcSessionRepository)
            }
            .exceptionHandling { exceptionHandlingSpec: ServerHttpSecurity.ExceptionHandlingSpec ->
                val accessDeniedHandler = HttpStatusJsonServerAccessDeniedHandler(HttpStatus.FORBIDDEN)
                exceptionHandlingSpec.accessDeniedHandler(accessDeniedHandler)

                val httpStatusJsonServerAuthenticationEntryPoint = HttpStatusJsonServerAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED)
                exceptionHandlingSpec.authenticationEntryPoint(httpStatusJsonServerAuthenticationEntryPoint)
            }
            .logout { logoutSpec: ServerHttpSecurity.LogoutSpec ->
                val logoutHandler = DelegatingServerLogoutHandler(
                    SecurityContextServerLogoutHandler(),
                    WebSessionServerLogoutHandler()
                )

                val delegateServerSuccessLogoutHandler = DelegateServerSuccessLogoutHandler(
                    redirectClientInitiatedServerLogoutHandler,
                    oAuth2ClientServerLogoutSuccessHandler
                )

                logoutSpec.logoutUrl("/logout")
                logoutSpec.logoutHandler(logoutHandler)
                logoutSpec.logoutSuccessHandler(delegateServerSuccessLogoutHandler)
            }
            .oauth2ResourceServer { oAuth2ResourceServerSpec: ServerHttpSecurity.OAuth2ResourceServerSpec ->
                val httpStatusJsonAuthenticationFailureHandler = HttpStatusJsonAuthenticationFailureHandler(HttpStatus.UNAUTHORIZED)
                val httpStatusJsonServerAuthenticationEntryPoint = HttpStatusJsonServerAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED)
                val accessDeniedHandler = HttpStatusJsonServerAccessDeniedHandler(HttpStatus.FORBIDDEN)

                oAuth2ResourceServerSpec
                    .jwt {}
                    .accessDeniedHandler(accessDeniedHandler)
                    .authenticationEntryPoint(httpStatusJsonServerAuthenticationEntryPoint)
                    .authenticationFailureHandler(httpStatusJsonAuthenticationFailureHandler)
            }
            .cors { corsConfigSource(globalCorsProperties) }
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
        gatewaySessionCookieProperties: GatewaySessionCookieProperties
    ): WebSessionIdResolver {
        val webSessionIdResolver = CookieWebSessionIdResolver()
        webSessionIdResolver.cookieName = gatewaySessionCookieProperties.name

        webSessionIdResolver.addCookieInitializer { cookieBuilder: ResponseCookie.ResponseCookieBuilder ->
            cookieBuilder.httpOnly(gatewaySessionCookieProperties.httpOnly)
            cookieBuilder.domain(gatewaySessionCookieProperties.domain)
            cookieBuilder.path(gatewaySessionCookieProperties.path)
            cookieBuilder.secure(gatewaySessionCookieProperties.secure)
            cookieBuilder.sameSite(gatewaySessionCookieProperties.sameSite.attributeValue())
            cookieBuilder.maxAge(gatewaySessionCookieProperties.maxAge)
        }

        return webSessionIdResolver
    }

    @Bean
    fun reactiveOAuth2AuthorizedClientManager(
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        authorizedClientService: RedisReactiveOAuth2AuthorizedClientService
    ): ReactiveOAuth2AuthorizedClientManager {
        val authorizedClientProvider: ReactiveOAuth2AuthorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .build()

        val authorizedClientManager = AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
            clientRegistrationRepository,
            authorizedClientService
        )
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider)

        return authorizedClientManager
    }

    @Bean
    fun webClient(): WebClient.Builder {
        return WebClient.builder()
    }

    @Bean
    @ConditionalOnMissingBean(value = [ErrorWebExceptionHandler::class])
    fun customErrorWebExceptionHandler(): ErrorWebExceptionHandler {
        return GlobalErrorWebExceptionHandler()
    }

}
