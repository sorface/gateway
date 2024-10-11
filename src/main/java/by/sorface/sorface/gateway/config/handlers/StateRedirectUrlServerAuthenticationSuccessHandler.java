package by.sorface.sorface.gateway.config.handlers;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.util.MultiValueMap;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Objects;

public class StateRedirectUrlServerAuthenticationSuccessHandler extends RedirectServerAuthenticationSuccessHandler {

    private static final String QUERY_STATE = "state";

    private static final String SEPARATOR_QUERY_PARAM_STATE = "~";

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        return Mono.defer(() -> {
            final MultiValueMap<String, String> queryParams = webFilterExchange.getExchange().getRequest().getQueryParams();

            boolean hasState = queryParams.containsKey(QUERY_STATE);

            if (hasState) {
                final var state = queryParams.getFirst(QUERY_STATE);

                if (Objects.isNull(state)) {
                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                }

                final var split = state.split(SEPARATOR_QUERY_PARAM_STATE);

                if (split.length <= 1) {
                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                }

                final String redirectUrl = split[1];

                return new DefaultServerRedirectStrategy().sendRedirect(webFilterExchange.getExchange(), URI.create(redirectUrl));
            }

            return super.onAuthenticationSuccess(webFilterExchange, authentication);
        });
    }
}
