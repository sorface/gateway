package by.sorface.gateway.config.route

import io.micrometer.tracing.Tracer
import io.micrometer.tracing.TraceContext
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.junit.jupiter.MockitoExtension
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.HttpHeaders
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.net.URI
import java.security.Principal
import java.time.Instant
import java.util.*

@ExtendWith(MockitoExtension::class)
class RouteFilterConfigurationTest {

    @Mock
    private lateinit var tracer: Tracer

    @Mock
    private lateinit var traceContext: TraceContext

    @Mock
    private lateinit var chain: GatewayFilterChain

    @InjectMocks
    private lateinit var configuration: RouteFilterConfiguration

    @Test
    fun `preRouteFilter should add trace ID and log for anonymous user`() {
        // given
        val traceId = "test-trace-id"
        val request = MockServerHttpRequest.get("http://example.com").build()
        val exchange = MockServerWebExchange.from(request)
        
        `when`(tracer.currentTraceContext()).thenReturn(object {
            fun context() = traceContext
        })
        `when`(traceContext.traceId()).thenReturn(traceId)
        `when`(chain.filter(exchange)).thenReturn(Mono.empty())

        // when
        val filter = configuration.preRouteFilter()
        val result = filter.filter(exchange, chain)

        // then
        StepVerifier.create(result)
            .verifyComplete()

        verify(chain).filter(exchange)
        assert(exchange.response.headers["X-B3-TraceId"]?.first() == traceId)
    }

    @Test
    fun `preRouteFilter should handle OAuth2 authenticated user`() {
        // given
        val userName = "test-user"
        val request = MockServerHttpRequest.get("http://example.com")
            .header(HttpHeaders.AUTHORIZATION, "Bearer token")
            .build()
        val exchange = MockServerWebExchange.from(request)
        
        val idToken = OidcIdToken("token", Instant.now(), Instant.now().plusSeconds(60),
            mapOf("name" to userName))
        val oidcUser = DefaultOidcUser(emptyList(), idToken)
        val authentication = OAuth2AuthenticationToken(oidcUser, emptyList(), "test")
        
        exchange.attributes["SPRING_SECURITY_CONTEXT"] = authentication
        
        `when`(tracer.currentTraceContext()).thenReturn(object {
            fun context() = traceContext
        })
        `when`(traceContext.traceId()).thenReturn("test-trace-id")
        `when`(chain.filter(exchange)).thenReturn(Mono.empty())

        // when
        val filter = configuration.preRouteFilter()
        val result = filter.filter(exchange, chain)

        // then
        StepVerifier.create(result)
            .verifyComplete()

        verify(chain).filter(exchange)
    }

    @Test
    fun `postRouteFilter should log response details for anonymous user`() {
        // given
        val request = MockServerHttpRequest.get("http://example.com").build()
        val exchange = MockServerWebExchange.from(request)
        
        `when`(chain.filter(exchange)).thenReturn(Mono.empty())

        // when
        val filter = configuration.postRouteFilter()
        val result = filter.filter(exchange, chain)

        // then
        StepVerifier.create(result)
            .verifyComplete()

        verify(chain).filter(exchange)
    }

    @Test
    fun `postRouteFilter should log response details for OAuth2 user`() {
        // given
        val userName = "test-user"
        val request = MockServerHttpRequest.get("http://example.com").build()
        val exchange = MockServerWebExchange.from(request)
        
        val idToken = OidcIdToken("token", Instant.now(), Instant.now().plusSeconds(60),
            mapOf("name" to userName))
        val oidcUser = DefaultOidcUser(emptyList(), idToken)
        val authentication = OAuth2AuthenticationToken(oidcUser, emptyList(), "test")
        
        exchange.attributes["SPRING_SECURITY_CONTEXT"] = authentication
        
        `when`(chain.filter(exchange)).thenReturn(Mono.empty())

        // when
        val filter = configuration.postRouteFilter()
        val result = filter.filter(exchange, chain)

        // then
        StepVerifier.create(result)
            .verifyComplete()

        verify(chain).filter(exchange)
    }
} 