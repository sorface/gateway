package by.sorface.gateway.config.handlers

import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.util.*

class DelegateServerSuccessLogoutHandler(vararg delegates: ServerLogoutSuccessHandler) : ServerLogoutSuccessHandler {

    private val delegates: MutableList<ServerLogoutSuccessHandler> = ArrayList()

    init {
        this.delegates.addAll(listOf(*delegates))
    }

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> = Flux.fromIterable(this.delegates)
            .concatMap { delegate: ServerLogoutSuccessHandler -> delegate.onLogoutSuccess(exchange, authentication) }
            .then()

}
