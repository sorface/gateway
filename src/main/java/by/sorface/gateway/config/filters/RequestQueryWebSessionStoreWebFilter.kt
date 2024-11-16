package by.sorface.gateway.config.filters

import by.sorface.gateway.config.constants.WebSessionAttributes
import lombok.Setter
import org.springframework.http.HttpMethod
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.util.MultiValueMap
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.server.WebSession
import reactor.core.publisher.Mono
import java.util.function.Function

@Setter
class RequestQueryWebSessionStoreWebFilter : WebFilter {

    private val serverWebExchangeMatchers: ServerWebExchangeMatcher = PathPatternParserServerWebExchangeMatcher("/oauth2/authorization/**", HttpMethod.GET)

    private val queryParamName = "redirect_url"

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        return chain.filter(exchange);
//        return serverWebExchangeMatchers.matches(exchange)
//                .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
//                .filter { exchange.request.queryParams.containsKey(queryParamName) }
//                .flatMap { exchange.session }
//                .flatMap { session ->
//                    exchange.request.queryParams.getFirst(queryParamName).let { paramValue ->
//                        session.attributes.put(WebSessionAttributes.ORIGINAL_REQUEST_ATTRIBUTE, paramValue)
//                    }
//
//                    Mono.empty<WebSession>()
//                 }
//                .then(chain.filter(exchange))
    }
}
