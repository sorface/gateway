package by.sorface.gateway.config.handler

import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

class OAuth2RedirectAuthenticationSuccessHandler(
    private val queryParamNameRedirectLocation: String,
    private val allowedHosts: Set<String>,
    private val redirectStrategy: ServerRedirectStrategy = DefaultServerRedirectStrategy()
) : ServerAuthenticationSuccessHandler {

    private val logger = LoggerFactory.getLogger(OAuth2RedirectAuthenticationSuccessHandler::class.java)

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange,
        authentication: Authentication
    ): Mono<Void> {
        logger.debug("Authentication success for user: {}", authentication.name)
        logger.debug("Authentication type: {}", authentication.javaClass.simpleName)
        logger.debug("Authentication details: {}", authentication.details)

        val exchange = webFilterExchange.exchange

        return when (authentication) {
            is OAuth2AuthenticationToken -> {
                logger.debug(
                    "Processing OAuth2 authentication - Principal: {}, Authorities: {}, Client Registration ID: {}",
                    authentication.principal.name,
                    authentication.authorities,
                    authentication.authorizedClientRegistrationId
                )
                handleOAuth2Authentication(exchange, authentication)
            }
            else -> {
                logger.warn("Unsupported authentication type: {}", authentication.javaClass.simpleName)
                redirectStrategy.sendRedirect(exchange, URI.create("/"))
            }
        }
    }

    private fun handleOAuth2Authentication(
        exchange: ServerWebExchange,
        authentication: OAuth2AuthenticationToken
    ): Mono<Void> {
        logger.debug("Handling OAuth2 authentication success")
        logger.debug("Exchange attributes: {}", exchange.attributes.keys)

        val attributes = exchange.attributes
        val savedRequest = attributes["SPRING_SECURITY_SAVED_REQUEST"]
        logger.debug("Saved request found: {}", savedRequest != null)

        val redirectLocation = savedRequest?.let { request ->
            when (request) {
                is Map<*, *> -> {
                    logger.debug("Processing saved request map")
                    val attrs = request["attributes"] as? Map<*, *>
                    logger.debug("Request attributes: {}", attrs?.keys)
                    
                    val location = attrs?.get(queryParamNameRedirectLocation) as? String
                    logger.debug("Found redirect location from attribute '{}': {}", queryParamNameRedirectLocation, location)
                    location
                }
                else -> {
                    logger.warn("Unexpected saved request type: {}", request.javaClass.simpleName)
                    null
                }
            }
        }

        val targetUrl = when {
            redirectLocation != null && isValidRedirectUrl(redirectLocation) -> {
                logger.debug("Using validated redirect location: {}", redirectLocation)
                redirectLocation
            }
            else -> {
                logger.debug(
                    "Using default redirect location '/' because {}",
                    when {
                        redirectLocation == null -> "no redirect location found"
                        else -> "redirect location '$redirectLocation' is not valid"
                    }
                )
                "/"
            }
        }

        logger.debug("Performing redirect to: {}", targetUrl)
        return redirectStrategy.sendRedirect(exchange, URI.create(targetUrl))
            .doOnSuccess { logger.debug("Redirect completed successfully") }
            .doOnError { e -> logger.error("Error during redirect", e) }
    }

    private fun isValidRedirectUrl(url: String): Boolean {
        return try {
            logger.debug("Validating redirect URL: {}", url)
            val uri = URI.create(url)
            val host = uri.host
            
            if (host == null) {
                logger.warn("Invalid redirect URL - no host present: {}", url)
                return false
            }

            val isValid = allowedHosts.any { allowedHost ->
                val matches = host.equals(allowedHost, ignoreCase = true) ||
                        host.endsWith(".$allowedHost", ignoreCase = true)
                if (matches) {
                    logger.debug("Host '{}' matches allowed host '{}'", host, allowedHost)
                }
                matches
            }

            if (!isValid) {
                logger.warn("Host '{}' is not in the allowed hosts list: {}", host, allowedHosts)
            }

            isValid
        } catch (e: Exception) {
            logger.warn("Invalid redirect URL format: {}", url, e)
            false
        }
    }
} 