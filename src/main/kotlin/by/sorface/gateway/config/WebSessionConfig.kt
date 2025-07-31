package by.sorface.gateway.config

import by.sorface.gateway.config.properties.SessionProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository
import org.springframework.web.server.session.CookieWebSessionIdResolver
import org.springframework.web.server.session.WebSessionIdResolver

@Configuration
class WebSessionConfig(private val sessionProperties: SessionProperties) {

    @Bean
    fun webSessionIdResolver(): WebSessionIdResolver {
        val resolver = CookieWebSessionIdResolver()
        with(sessionProperties.cookie) {
            resolver.setCookieName(name)
            resolver.addCookieInitializer { cookie ->
                cookie.domain(domain)
                cookie.path(path)
                cookie.httpOnly(httpOnly)
                cookie.secure(secure)
                cookie.maxAge(maxAge)
                cookie.sameSite(sameSite)
            }
        }
        return resolver
    }

} 