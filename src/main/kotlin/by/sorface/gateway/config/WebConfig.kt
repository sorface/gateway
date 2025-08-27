package by.sorface.gateway.config

import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.config.ResourceHandlerRegistry
import org.springframework.web.reactive.config.WebFluxConfigurer

@Configuration
class WebConfig : WebFluxConfigurer {

    override fun addResourceHandlers(registry: ResourceHandlerRegistry) {
        registry.addResourceHandler("/.well-known/**")
            .addResourceLocations("classpath:/static/.well-known/")
            .resourceChain(true)
    }

}