package com.kurori.dns.rules

data class ManagedGroup(
    val id: Long,
    val parentId: Long?,
    val name: String,
    val type: String,
    val enabled: Boolean,
    val registryGroupId: Int?,
    val filterId: Int?,
    val downloadUrl: String?,
    val description: String?,
    val version: String?,
    val updatedAt: Long?,
    val domainCount: Int,
    val ignoredRuleCount: Int
)

data class FilterCatalogEntry(
    val filterId: Int,
    val name: String,
    val description: String,
    val registryGroupId: Int,
    val registryGroupName: String,
    val downloadUrl: String,
    val version: String,
    val deprecated: Boolean
)

data class ParsedFilter(
    val domains: Set<String>,
    val ignoredRuleCount: Int,
    val totalRuleLines: Int,
    val sourceVersion: String
)

data class GroupUpdateDifference(
    val addedDomains: Int,
    val removedDomains: Int,
    val unchangedDomains: Int,
    val importedDomains: Int,
    val ignoredRuleCount: Int
)

data class DomainGroupSnapshot(
    val name: String,
    val type: String,
    val enabled: Boolean,
    val sourceKey: String?,
    val registryGroupId: Int?,
    val filterId: Int?,
    val downloadUrl: String?,
    val description: String?,
    val version: String?,
    val updatedAt: Long?,
    val domainCount: Int,
    val ignoredRuleCount: Int,
    val domains: List<String>,
    val children: List<DomainGroupSnapshot>
)

object GroupType {
    const val MANUAL = "manual"
    const val SOURCE = "source"
    const val CATEGORY = "category"
    const val FILTER = "filter"
}