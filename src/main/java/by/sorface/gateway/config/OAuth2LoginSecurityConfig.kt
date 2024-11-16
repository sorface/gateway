package by.sorface.gateway.config;

import by.sorface.gateway.config.handlers.*;
import by.sorface.gateway.config.resolvers.RedirectServerOAuth2AuthorizationRequestResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * This is a configuration class that handles OAuth2 login security. It enables WebFlux security and method security,
 * and configures the authorization request resolver, authentication success and failure handlers,
 * access denied handler, and authentication entry point.
 *
 * @author Sorface
 */
@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
@EnableMethodSecurity
public class OAuth2LoginSecurityConfig {

    /**
     * Creates a SecurityWebFilterChain that configures the security settings for the application.
     * It sets the authorization rules and handlers for the application.
     *
     * @param http the ServerHttpSecurity object
     * @param clientRegistrationRepository the ReactiveClientRegistrationRepository object
     * @return the SecurityWebFilterChain
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(final ServerHttpSecurity http,
                                                            final ReactiveClientRegistrationRepository clientRegistrationRepository) {
        http
                .authorizeExchange(exchanges -> {
                    exchanges.pathMatchers("/signin", "/oauth2/authorization/gateway").permitAll();
                    exchanges.anyExchange().authenticated();
                })
                .oauth2Login(oAuth2LoginSpec -> {
                    final var authorizationRequestResolver = new RedirectServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "redirectUri", "~");
                    oAuth2LoginSpec.authorizationRequestResolver(authorizationRequestResolver);

                    final var authenticationSuccessHandler = new StateRedirectUrlServerAuthenticationSuccessHandler();
                    oAuth2LoginSpec.authenticationSuccessHandler(authenticationSuccessHandler);

                    final var authenticationFailureHandler = new HttpStatusJsonAuthenticationFailureHandler(HttpStatus.UNAUTHORIZED);
                    oAuth2LoginSpec.authenticationFailureHandler(authenticationFailureHandler);
                })
                .exceptionHandling(exceptionHandlingSpec -> {
                    final var accessDeniedHandler = new HttpStatusJsonServerAccessDeniedHandler(HttpStatus.FORBIDDEN);
                    exceptionHandlingSpec.accessDeniedHandler(accessDeniedHandler);

                    final var httpStatusJsonServerAuthenticationEntryPoint = new HttpStatusJsonServerAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED);
                    exceptionHandlingSpec.authenticationEntryPoint(httpStatusJsonServerAuthenticationEntryPoint);
                })
                .logout(logoutSpec -> {
                    logoutSpec.requiresLogout(new PathPatternParserServerWebExchangeMatcher("/signout", HttpMethod.POST));
                    logoutSpec.logoutSuccessHandler(new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository));
                })
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> {
                    oAuth2ResourceServerSpec.jwt(withDefaults()).authenticationFailureHandler(new HttpStatusJsonAuthenticationFailureHandler(HttpStatus.UNAUTHORIZED));
                })
                .csrf(ServerHttpSecurity.CsrfSpec::disable);

        return http.build();
    }

    /**
     * Provides a custom ErrorWebExceptionHandler if one is not already present.
     *
     * @return the ErrorWebExceptionHandler
     */
    @Bean
    @ConditionalOnMissingBean(value = ErrorWebExceptionHandler.class)
    public ErrorWebExceptionHandler customErrorWebExceptionHandler() {
        return new GlobalErrorWebExceptionHandler();
    }
}
