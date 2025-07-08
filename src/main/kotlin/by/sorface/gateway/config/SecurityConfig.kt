package by.sorface.gateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
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
            .oauth2Login { }
            .oauth2Client { }
            .exceptionHandling {
                it.authenticationEntryPoint { exchange, ex ->
                    Mono.error(ex)
                }.accessDeniedHandler { exchange, ex ->
                    Mono.error(ex)
                }
            }
            .build()
    }

    @Bean
    fun securityContextRepository(): ServerSecurityContextRepository {
        return WebSessionServerSecurityContextRepository()
    }
} 