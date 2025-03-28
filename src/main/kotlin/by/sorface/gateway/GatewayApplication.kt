package by.sorface.gateway

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.context.properties.EnableConfigurationProperties
import reactor.core.publisher.Hooks

@EnableConfigurationProperties
@ConfigurationPropertiesScan
@SpringBootApplication
class GatewayApplication

fun main(args: Array<String>) {
    Hooks.enableAutomaticContextPropagation()

    SpringApplication.run(GatewayApplication::class.java, *args)
}
