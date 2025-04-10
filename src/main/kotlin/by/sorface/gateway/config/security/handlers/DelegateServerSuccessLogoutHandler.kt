package by.sorface.gateway.config.security.handlers

import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

/**
 * Делегат обработчиков выхода из системы
 *
 * @constructor delegates обработчики успешного выхода из системы
 */
class DelegateServerSuccessLogoutHandler(vararg delegates: ServerLogoutSuccessHandler) : ServerLogoutSuccessHandler {

    /**
     * Обработчики успешного выхода из системы
     */
    private val delegates: MutableList<ServerLogoutSuccessHandler> = ArrayList()

    init {
        this.delegates.addAll(listOf(*delegates))
    }

    /**
     * Поэтапный вызов обработчика выхода из системы
     *
     * @param exchange запрос выхода из системы
     * @param authentication аутентификация пользователя
     */
    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> = Flux.fromIterable(this.delegates)
        .concatMap { delegate: ServerLogoutSuccessHandler -> delegate.onLogoutSuccess(exchange, authentication) }
        .then()

}
