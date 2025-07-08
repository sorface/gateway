package by.sorface.gateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import reactor.core.publisher.Mono

@Configuration
@EnableWebFluxSecurity
class SecurityConfig {

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .csrf { it.disable() }
            .authorizeExchange {
                it.pathMatchers("/actuator/**").permitAll()
                    .anyExchange().authenticated()
            }
            .oauth2Login {
                it.authenticationSuccessHandler(authenticationSuccessHandler())
            }
            .oauth2Client { }
            .requestCache {
                it.requestCache(requestCache())
            }
            .exceptionHandling {
                it.authenticationEntryPoint { _, ex ->
                    Mono.error(ex)
                }.accessDeniedHandler { _, ex ->
                    Mono.error(ex)
                }
            }
            .build()
    }

    @Bean
    fun requestCache(): ServerRequestCache {
        return WebSessionServerRequestCache()
    }

    @Bean
    fun authenticationSuccessHandler(): ServerAuthenticationSuccessHandler {
        val redirectHandler = RedirectServerAuthenticationSuccessHandler()
        redirectHandler.setRequestCache(requestCache())
        return redirectHandler
    }

    @Bean
    fun securityContextRepository(): ServerSecurityContextRepository {
        return WebSessionServerSecurityContextRepository()
    }
} 