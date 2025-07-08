package by.sorface.gateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ResourceLoader
import org.springframework.http.HttpStatus
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders
import reactor.core.publisher.Mono

/**
 * Конфигурация безопасности для Gateway API.
 *
 * Отвечает за:
 * - Настройку OAuth2 аутентификации
 * - Управление правами доступа к эндпоинтам
 * - Обработку ошибок аутентификации и авторизации
 * - Сохранение и восстановление исходных запросов
 */
@Configuration
@EnableWebFluxSecurity
class SecurityConfig {

    /**
     * Создает основную цепочку фильтров безопасности.
     *
     * Настраивает:
     * - Правила доступа к эндпоинтам
     * - OAuth2 аутентификацию
     * - Обработку ошибок
     * - Кэширование запросов
     */
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity, resourceLoader: ResourceLoader): SecurityWebFilterChain {
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
            .oauth2ResourceServer { oauth2 ->
                oauth2
                    .jwt { jwt ->
                        jwt.jwtDecoder(ReactiveJwtDecoders.fromIssuerLocation("http://localhost:8080"))
                    }
                    .bearerTokenConverter(ServerBearerTokenAuthenticationConverter())
                    .authenticationEntryPoint { exchange, ex ->
                        val response = exchange.response
                        response.statusCode = HttpStatus.UNAUTHORIZED
                        when (ex) {
                            is OAuth2AuthenticationException -> {
                                val error = ex.error

                                Mono.error(OAuth2AuthenticationException(
                                    OAuth2Error(
                                        error.errorCode,
                                        "Invalid token: ${error.description}",
                                        error.uri
                                    )
                                ))
                            }
                            else -> Mono.error(ex)
                        }
                    }
                    .accessDeniedHandler(accessDeniedHandler())
            }
            .requestCache {
                it.requestCache(requestCache())
            }
            .exceptionHandling {
                it.authenticationEntryPoint(authenticationEntryPoint())
                    .accessDeniedHandler(accessDeniedHandler())
            }
            .build()
    }

    /**
     * Создает обработчик для случаев отказа в доступе.
     * Возвращает 403 Forbidden с соответствующим сообщением.
     */
    @Bean
    fun accessDeniedHandler(): ServerAccessDeniedHandler {
        return HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN)
    }

    /**
     * Создает точку входа аутентификации.
     * Возвращает 401 Unauthorized для неаутентифицированных запросов.
     */
    @Bean
    fun authenticationEntryPoint(): ServerAuthenticationEntryPoint {
        return HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)
    }

    /**
     * Создает кэш для сохранения исходных запросов.
     *
     * Используется для:
     * - Сохранения URL, с которого пользователь был перенаправлен на аутентификацию
     * - Восстановления исходного запроса после успешной аутентификации
     */
    @Bean
    fun requestCache(): ServerRequestCache {
        return WebSessionServerRequestCache()
    }

    /**
     * Создает обработчик успешной аутентификации.
     *
     * После успешной аутентификации:
     * - Проверяет наличие сохраненного запроса
     * - Перенаправляет пользователя на исходный URL
     * - Если исходный URL отсутствует, использует URL по умолчанию
     */
    @Bean
    fun authenticationSuccessHandler(): ServerAuthenticationSuccessHandler {
        val redirectHandler = RedirectServerAuthenticationSuccessHandler()
        redirectHandler.setRequestCache(requestCache())
        return redirectHandler
    }
} 