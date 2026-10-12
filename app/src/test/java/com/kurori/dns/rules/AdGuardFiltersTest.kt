package com.kurori.dns.rules

import org.junit.Assert.assertEquals
import org.junit.Test

class AdGuardFiltersTest {
    @Test
    fun parsesHostWideRulesAndHostsEntriesOnly() {
        val parsed = AdGuardFilters.parseLines(
            sequenceOf(
                "! filter metadata",
                "[Adblock Plus 2.0]",
                "||ads.example^",
                "||ads.example/path/*",
                "||tracker.example^\$third-party",
                "||nxdomain.example^\$dnsrewrite=NXDOMAIN",
                "0.0.0.0 hosts.example tracker.example",
                "127.0.0.1 localhost localhost.localdomain",
                "example.com##.sponsored",
                "||safe.example^",
                "@@||safe.example^"
            ),
            "test-version"
        )

        assertEquals(setOf("ads.example", "nxdomain.example", "hosts.example", "tracker.example"), parsed.domains)
        assertEquals(4, parsed.ignoredRuleCount)
        assertEquals("test-version", parsed.sourceVersion)
    }

    @Test
    fun acceptsOnlyDnsWideModifiers() {
        val parsed = AdGuardFilters.parseLines(
            sequenceOf(
                "||important.example^\$important",
                "||document.example^\$document",
                "||nxdomain.example^\$dnsrewrite=NXDOMAIN"
            ),
            ""
        )

        assertEquals(setOf("important.example", "nxdomain.example"), parsed.domains)
        assertEquals(1, parsed.ignoredRuleCount)
    }
}