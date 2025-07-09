package by.sorface.gateway.config

import by.sorface.gateway.config.properties.SecurityProperties
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository

@TestConfiguration
class TestConfig {
    
    @Bean
    fun securityProperties(): SecurityProperties {
        return SecurityProperties(
            queryParamNameRedirectLocation = "redirect-location",
            allowedRedirectHosts = setOf("localhost")
        )
    }

    @Bean
    fun clientRegistrationRepository(): ReactiveClientRegistrationRepository {
        val registration = ClientRegistration.withRegistrationId("passport")
            .clientId("test-client")
            .clientSecret("test-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:9000/login/oauth2/code/passport")
            .scope("openid", "profile")
            .authorizationUri("http://localhost:8080/oauth2/authorize")
            .tokenUri("http://localhost:8080/oauth2/token")
            .build()
        
        return InMemoryReactiveClientRegistrationRepository(registration)
    }

    @Bean
    fun authorizedClientRepository(): ServerOAuth2AuthorizedClientRepository {
        return WebSessionServerOAuth2AuthorizedClientRepository()
    }
} 