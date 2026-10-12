package com.kurori.dns.rules

import java.net.IDN

class DomainMatcher(domains: Iterable<String>) {
    private val domains = domains.toHashSet()

    fun matches(domain: String): Boolean {
        var start = 0
        while (true) {
            if (domains.contains(domain.substring(start))) return true
            val separator = domain.indexOf('.', start)
            if (separator < 0) return false
            start = separator + 1
        }
    }

    companion object {
        fun normalize(input: String): String? {
            val trimmed = input.trim().trimEnd('.').lowercase()
            if (trimmed.isEmpty()) return null

            val ascii = try {
                IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).lowercase()
            } catch (_: IllegalArgumentException) {
                return null
            }
            if (ascii.length > 253) return null
            if (ascii.split('.').any { it.isEmpty() || it.length > 63 }) return null
            return ascii
        }
    }
}