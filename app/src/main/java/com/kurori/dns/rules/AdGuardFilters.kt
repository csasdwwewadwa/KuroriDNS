package com.kurori.dns.rules

import org.json.JSONObject
import java.io.BufferedReader
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

object AdGuardFilters {
    private const val CATALOG_URL = "https://filters.adtidy.org/android/filters.json"
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 30_000
    private const val MAX_CATALOG_BYTES = 5 * 1024 * 1024
    private const val MAX_FILTER_BYTES = 30 * 1024 * 1024
    private const val MAX_FILTER_LINES = 1_000_000

    fun loadCatalog(): List<FilterCatalogEntry> {
        val root = JSONObject(downloadText(CATALOG_URL, MAX_CATALOG_BYTES))
        val groups = HashMap<Int, String>()
        val groupArray = root.optJSONArray("groups") ?: throw IOException("AdGuard registry has no groups")
        for (index in 0 until groupArray.length()) {
            val group = groupArray.getJSONObject(index)
            groups[group.getInt("groupId")] = group.getString("groupName")
        }

        val filters = root.optJSONArray("filters") ?: throw IOException("AdGuard registry has no filters")
        return buildList {
            for (index in 0 until filters.length()) {
                val filter = filters.getJSONObject(index)
                val filterId = filter.optInt("filterId", -1)
                val groupId = filter.optInt("groupId", -1)
                val url = filter.optString("downloadUrl")
                if (filterId < 0 || groupId < 0 || !url.startsWith("https://filters.adtidy.org/android/filters/")) continue
                add(
                    FilterCatalogEntry(
                        filterId = filterId,
                        name = filter.optString("name", "Filter $filterId"),
                        description = filter.optString("description"),
                        registryGroupId = groupId,
                        registryGroupName = groups[groupId] ?: "Other",
                        downloadUrl = url,
                        version = filter.optString("version"),
                        deprecated = filter.optBoolean("deprecated", false)
                    )
                )
            }
        }.sortedWith(compareBy<FilterCatalogEntry>({ it.registryGroupId }, { it.name.lowercase() }))
    }

    fun downloadAndParse(filter: FilterCatalogEntry): ParsedFilter {
        val connection = open(filter.downloadUrl)
        try {
            return connection.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                parseLines(generateSequence { reader.readLine() }, filter.version)
            }
        } finally {
            connection.disconnect()
        }
    }

    internal fun parseLines(lines: Sequence<String>, sourceVersion: String): ParsedFilter {
        val result = LinkedHashSet<String>()
        val exceptions = HashSet<String>()
        var ignoredRules = 0
        var ruleLines = 0
        var byteCount = 0L
        for (line in lines) {
            byteCount += line.length * 2L + 2L
            if (byteCount > MAX_FILTER_BYTES) throw IOException("Filter exceeds the download size limit")
            val candidate = line.trim()
            if (candidate.isEmpty() || candidate.startsWith("!") || candidate.startsWith("[")) continue
            ruleLines++
            if (ruleLines > MAX_FILTER_LINES) throw IOException("Filter exceeds the rule count limit")
            val hostEntries = parseHostsLine(candidate)
            if (hostEntries != null) {
                result.addAll(hostEntries)
                continue
            }

            val exception = candidate.startsWith("@@")
            val rule = if (exception) candidate.substring(2) else candidate
            val match = DOMAIN_RULE.matchEntire(rule)
            if (match == null || !isDnsWideModifierSet(match.groupValues[2])) {
                ignoredRules++
                continue
            }
            val domain = DomainMatcher.normalize(match.groupValues[1])
            if (domain == null || isLocalOnlyDomain(domain)) {
                ignoredRules++
            } else if (exception) {
                exceptions.add(domain)
            } else {
                result.add(domain)
            }
        }
        result.removeAll(exceptions)
        return ParsedFilter(result, ignoredRules, ruleLines, sourceVersion)
    }

    private fun isDnsWideModifierSet(value: String): Boolean {
        if (value.isEmpty()) return true
        return value.split(',').all { modifier ->
            modifier == "important" || modifier.equals("dnsrewrite=NXDOMAIN", ignoreCase = true)
        }
    }

    private fun parseHostsLine(line: String): Set<String>? {
        val fields = line.substringBefore('#').trim().split(WHITESPACE)
        if (fields.size < 2 || fields[0] !in NULL_ROUTE_ADDRESSES) return null
        val entries = LinkedHashSet<String>()
        for (field in fields.drop(1)) {
            DomainMatcher.normalize(field)
                ?.takeUnless(::isLocalOnlyDomain)
                ?.let(entries::add)
        }
        return entries.takeIf { it.isNotEmpty() }
    }

    private fun isLocalOnlyDomain(domain: String): Boolean =
        domain == "localhost" || domain == "localhost.localdomain" || domain.endsWith(".localhost") ||
            domain.endsWith(".localdomain") || domain.endsWith(".local") ||
            domain.endsWith(".test") || domain.endsWith(".invalid") ||
            domain.matches(Regex("\\d{1,3}(?:\\.\\d{1,3}){3}"))

    private fun downloadText(url: String, maxBytes: Int): String {
        val connection = open(url)
        try {
            val output = StringBuilder()
            connection.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                val buffer = CharArray(8192)
                var total = 0
                while (true) {
                    val count = reader.read(buffer)
                    if (count < 0) break
                    total += count * 2
                    if (total > maxBytes) throw IOException("AdGuard registry exceeds the size limit")
                    output.append(buffer, 0, count)
                }
            }
            return output.toString()
        } finally {
            connection.disconnect()
        }
    }

    private fun open(url: String): HttpURLConnection {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.setRequestProperty("Accept", "text/plain, application/json")
        connection.setRequestProperty("User-Agent", "KuroriDNS/0.1 Android")
        connection.instanceFollowRedirects = true
        if (connection.responseCode !in 200..299) {
            val status = connection.responseCode
            connection.disconnect()
            throw IOException("Download failed with HTTP $status")
        }
        return connection
    }

    private val DOMAIN_RULE = Regex("^\\|\\|([A-Za-z0-9.-]+)\\^(?:\\$(.*))?$")
    private val WHITESPACE = Regex("\\s+")
    private val NULL_ROUTE_ADDRESSES = setOf("0.0.0.0", "127.0.0.1", "::", "::1")
}