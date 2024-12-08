package by.sorface.gateway.records

data class AuthorizationErrorOperation(val code: Int, val description: String?, val authentication: Boolean = true)
