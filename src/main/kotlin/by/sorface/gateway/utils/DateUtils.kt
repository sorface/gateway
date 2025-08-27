package by.sorface.gateway.utils

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val formatter = DateTimeFormatter
    .ofPattern("yyyy-MM-dd HH:mm:ss")
    .withZone(ZoneId.systemDefault())

fun Instant.formatYYYYMMddHHmmss(): String = formatter.format(this)