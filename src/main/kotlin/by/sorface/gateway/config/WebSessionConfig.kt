package by.sorface.gateway.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.server.session.CookieWebSessionIdResolver
import org.springframework.web.server.session.WebSessionIdResolver
import java.time.Duration

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
                cookie.maxAge(Duration.ofSeconds(maxAge.toLong()))
                cookie.sameSite(sameSite)
            }
        }

        return resolver
    }
}

@ConfigurationProperties("spring.session")
data class SessionProperties(
    val cookie: CookieProperties = CookieProperties()
)

data class CookieProperties(
    val name: String = "gtw_sid",
    val domain: String = "localhost",
    val path: String = "/",
    val httpOnly: Boolean = true,
    val secure: Boolean = false,
    val sameSite: String = "Lax",
    val maxAge: Int = 1000000000
) 