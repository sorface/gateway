package by.sorface.gateway.config

import by.sorface.gateway.service.RedisReactiveOidcSessionRegistry
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.web.server.session.WebSessionManager
import reactor.core.publisher.Mono
import org.springframework.web.server.WebSession
import org.springframework.web.server.session.DefaultWebSessionManager
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.server.ServerWebExchange
import reactor.core.scheduler.Schedulers

/**
 * Конфигурация для управления OIDC сессиями.
 * 
 * Этот класс отвечает за:
 * - Управление веб-сессиями пользователей
 * - Сохранение информации о сессиях OIDC в Redis
 * - Настройку репозиториев для контекста безопасности и OAuth2 клиентов
 */
@Configuration
class OidcSessionConfig(
    private val oidcSessionRegistry: RedisReactiveOidcSessionRegistry
) {

    /**
     * Создает менеджер веб-сессий с расширенной функциональностью для OIDC.
     * 
     * При создании новой сессии:
     * 1. Проверяет наличие OAuth2 аутентификации
     * 2. Извлекает информацию о пользователе OIDC
     * 3. Сохраняет данные сессии в Redis для последующего использования
     * 
     * @return WebSessionManager с настроенной обработкой OIDC сессий
     */
    @Bean
    fun oidcWebSessionManager(): WebSessionManager {
        return object : DefaultWebSessionManager() {
            override fun getSession(exchange: ServerWebExchange): Mono<WebSession> {
                return super.getSession(exchange)
                    .publishOn(Schedulers.boundedElastic())
                    .doOnNext { session ->
                        exchange.getPrincipal<OAuth2AuthenticationToken>()
                            .filter { it is OAuth2AuthenticationToken }
                            .map { it as OAuth2AuthenticationToken }
                            .filter { it.principal is OidcUser }
                            .subscribe { auth ->
                                val oidcUser = auth.principal as OidcUser
                                oidcSessionRegistry.saveSessionInformation(
                                    registrationId = auth.authorizedClientRegistrationId,
                                    principalName = auth.name,
                                    sessionId = session.id,
                                    idToken = oidcUser.idToken
                                ).subscribe()
                            }
                    }
            }
        }
    }

    /**
     * Создает репозиторий для хранения контекста безопасности в веб-сессии.
     * 
     * @return Репозиторий контекста безопасности, использующий веб-сессию для хранения
     */
    @Bean
    fun securityContextRepository() = WebSessionServerSecurityContextRepository()

    /**
     * Создает репозиторий для хранения авторизованных OAuth2 клиентов.
     * 
     * Используется для:
     * - Хранения токенов доступа
     * - Управления refresh токенами
     * - Поддержки сессий OAuth2 клиентов
     * 
     * @return Репозиторий OAuth2 клиентов, использующий веб-сессию для хранения
     */
    @Bean
    fun authorizedClientRepository(): ServerOAuth2AuthorizedClientRepository {
        return WebSessionServerOAuth2AuthorizedClientRepository()
    }
} 