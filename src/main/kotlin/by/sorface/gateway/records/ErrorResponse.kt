package by.sorface.gateway.records

data class ErrorResponse(
    val traceId: String,
    val spanId: String,
    val code: Int,
    val reason: String
)