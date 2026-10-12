package com.kurori.dns.rules

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class DomainStore(context: Context) : SQLiteOpenHelper(context, "kurori-dns.db", null, 2) {
    override fun onConfigure(db: SQLiteDatabase) {
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE domains (
                domain TEXT PRIMARY KEY NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0,
                hidden INTEGER NOT NULL DEFAULT 0,
                suggested_at INTEGER
            )"""
        )
        db.execSQL("CREATE INDEX domains_blocked_idx ON domains(blocked, domain)")
        db.execSQL("CREATE INDEX domains_hidden_idx ON domains(hidden, domain)")
        db.execSQL("CREATE INDEX domains_suggested_idx ON domains(suggested_at)")
        createGroupTables(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            createGroupTables(db)
            db.execSQL("INSERT OR IGNORE INTO group_domains(group_id, domain) SELECT 1, domain FROM domains WHERE blocked = 1")
            db.execSQL("UPDATE domains SET blocked = 0 WHERE blocked = 1")
        }
    }

    @Synchronized
    fun loadBlocked(): Set<String> {
        val values = LinkedHashSet<String>()
        readableDatabase.rawQuery(
            """WITH RECURSIVE enabled_groups(group_id, enabled) AS (
                SELECT id, enabled FROM managed_groups WHERE parent_id IS NULL
                UNION ALL
                SELECT child.id, parent.enabled * child.enabled
                FROM managed_groups child JOIN enabled_groups parent ON child.parent_id = parent.group_id
            )
            SELECT domain FROM domains WHERE blocked = 1
            UNION
            SELECT gd.domain FROM group_domains gd
            JOIN enabled_groups eg ON eg.group_id = gd.group_id
            WHERE eg.enabled = 1
            ORDER BY domain""",
            null
        ).use { cursor ->
            while (cursor.moveToNext()) values.add(cursor.getString(0))
        }
        return values
    }

    @Synchronized
    fun getGroups(parentId: Long?): List<ManagedGroup> {
        val groups = mutableListOf<ManagedGroup>()
        val selection = if (parentId == null) "parent_id IS NULL" else "parent_id = ?"
        val args = parentId?.let { arrayOf(it.toString()) }
        readableDatabase.query(
            "managed_groups",
            GROUP_COLUMNS,
            selection,
            args,
            null,
            null,
            "type, name COLLATE NOCASE"
        ).use { cursor ->
            while (cursor.moveToNext()) groups.add(cursor.toManagedGroup())
        }
        return groups
    }

    @Synchronized
    fun getGroup(groupId: Long): ManagedGroup? = readableDatabase.query(
        "managed_groups",
        GROUP_COLUMNS,
        "id = ?",
        arrayOf(groupId.toString()),
        null,
        null,
        null
    ).use { cursor -> if (cursor.moveToFirst()) cursor.toManagedGroup() else null }

    @Synchronized
    fun getGroupDomains(groupId: Long): List<String> {
        val domains = mutableListOf<String>()
        readableDatabase.query(
            "group_domains",
            arrayOf("domain"),
            "group_id = ?",
            arrayOf(groupId.toString()),
            null,
            null,
            "domain COLLATE NOCASE"
        ).use { cursor -> while (cursor.moveToNext()) domains.add(cursor.getString(0)) }
        return domains
    }

    @Synchronized
    fun exportGroupTree(): List<DomainGroupSnapshot> = getGroups(null).map(::snapshotGroup)

    @Synchronized
    fun importGroupTree(groups: Collection<DomainGroupSnapshot>) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            importGroupTree(db, groups)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun importBackup(
        groups: Collection<DomainGroupSnapshot>,
        ignoredDomains: Collection<String>,
        candidates: Collection<String>
    ) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            importGroupTree(db, groups)
            importRules(db, ignoredDomains, "hidden")
            importCandidateRows(db, candidates)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun importCandidates(candidates: Collection<String>): Int {
        if (candidates.isEmpty()) return 0
        val db = writableDatabase
        db.beginTransaction()
        try {
            val imported = importCandidateRows(db, candidates)
            db.setTransactionSuccessful()
            return imported
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun countGroupDomains(groupId: Long): Int = readableDatabase.rawQuery(
        """WITH RECURSIVE group_tree(id) AS (
            SELECT id FROM managed_groups WHERE id = ?
            UNION ALL SELECT child.id FROM managed_groups child JOIN group_tree parent ON child.parent_id = parent.id
        ) SELECT COUNT(DISTINCT gd.domain) FROM group_domains gd JOIN group_tree tree ON gd.group_id = tree.id""",
        arrayOf(groupId.toString())
    ).use { cursor -> if (cursor.moveToFirst()) cursor.getInt(0) else 0 }

    @Synchronized
    fun getManualRootId(): Long = MANUAL_ROOT_ID

    @Synchronized
    fun addManualFolder(parentId: Long, name: String): Long {
        requireGroupType(parentId, GroupType.MANUAL)
        val values = ContentValues().apply {
            put("parent_id", parentId)
            put("name", name.trim())
            put("type", GroupType.MANUAL)
            put("enabled", 1)
        }
        return writableDatabase.insertOrThrow("managed_groups", null, values)
    }

    @Synchronized
    fun addManualDomain(groupId: Long, domain: String) {
        requireGroupType(groupId, GroupType.MANUAL)
        val db = writableDatabase
        db.beginTransaction()
        try {
            val domainValues = ContentValues().apply {
                put("domain", domain)
                put("blocked", 0)
            }
            db.insertWithOnConflict("domains", null, domainValues, SQLiteDatabase.CONFLICT_IGNORE)
            db.execSQL("INSERT OR IGNORE INTO group_domains(group_id, domain) VALUES (?, ?)", arrayOf(groupId, domain))
            db.execSQL("UPDATE domains SET suggested_at = NULL WHERE domain = ?", arrayOf(domain))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun removeManualDomain(groupId: Long, domain: String) {
        requireGroupType(groupId, GroupType.MANUAL)
        writableDatabase.execSQL("DELETE FROM group_domains WHERE group_id = ? AND domain = ?", arrayOf(groupId, domain))
        deleteEmptyRows()
    }

    @Synchronized
    fun toggleGroup(groupId: Long): Boolean {
        val db = writableDatabase
        db.execSQL("UPDATE managed_groups SET enabled = 1 - enabled WHERE id = ?", arrayOf(groupId))
        return getGroup(groupId)?.enabled == true
    }

    @Synchronized
    fun setGroupEnabled(groupId: Long, enabled: Boolean) {
        writableDatabase.execSQL(
            "UPDATE managed_groups SET enabled = ? WHERE id = ?",
            arrayOf(if (enabled) 1 else 0, groupId)
        )
    }

    @Synchronized
    fun renameGroup(groupId: Long, name: String) {
        require(groupId != MANUAL_ROOT_ID) { "The Manual folder cannot be renamed" }
        writableDatabase.execSQL("UPDATE managed_groups SET name = ? WHERE id = ?", arrayOf(name.trim(), groupId))
    }

    @Synchronized
    fun deleteGroup(groupId: Long) {
        require(groupId != MANUAL_ROOT_ID) { "The Manual folder cannot be deleted" }
        writableDatabase.execSQL("DELETE FROM managed_groups WHERE id = ?", arrayOf(groupId))
        deleteEmptyRows()
    }

    @Synchronized
    fun createAdGuardGroup(name: String, filters: Collection<FilterCatalogEntry>): Long {
        require(filters.isNotEmpty()) { "Choose at least one filter list" }
        val db = writableDatabase
        var sourceId = -1L
        db.beginTransaction()
        try {
            val sourceValues = ContentValues().apply {
                put("name", name.trim())
                put("type", GroupType.SOURCE)
                put("enabled", 1)
                put("source_key", ADGUARD_SOURCE_KEY)
            }
            sourceId = db.insertOrThrow("managed_groups", null, sourceValues)
            val categories = HashMap<Int, Long>()
            filters.distinctBy { it.filterId }.forEach { filter ->
                val categoryId = categories.getOrPut(filter.registryGroupId) {
                    val categoryValues = ContentValues().apply {
                        put("parent_id", sourceId)
                        put("name", filter.registryGroupName)
                        put("type", GroupType.CATEGORY)
                        put("enabled", 1)
                        put("registry_group_id", filter.registryGroupId)
                    }
                    db.insertOrThrow("managed_groups", null, categoryValues)
                }
                val filterValues = ContentValues().apply {
                    put("parent_id", categoryId)
                    put("name", filter.name)
                    put("type", GroupType.FILTER)
                    put("enabled", 1)
                    put("filter_id", filter.filterId)
                    put("download_url", filter.downloadUrl)
                    put("description", filter.description)
                    put("version", filter.version)
                }
                db.insertOrThrow("managed_groups", null, filterValues)
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return sourceId
    }

    @Synchronized
    fun getPremadeSourceGroups(): List<ManagedGroup> = getGroups(null).filter { it.type == GroupType.SOURCE }

    @Synchronized
    fun getSourceFilterGroups(sourceId: Long): List<ManagedGroup> = getGroups(sourceId)
        .filter { it.type == GroupType.CATEGORY }
        .flatMap { category -> getGroups(category.id).filter { it.type == GroupType.FILTER } }

    @Synchronized
    fun addAdGuardFilters(
        sourceId: Long,
        filters: Collection<FilterCatalogEntry>,
        parsedFilters: Map<Int, ParsedFilter>,
        updatedAt: Long
    ): GroupUpdateDifference {
        requireGroupType(sourceId, GroupType.SOURCE)
        require(filters.isNotEmpty()) { "Choose at least one new filter" }
        val additions = filters.distinctBy { it.filterId }
        val parsedIds = parsedFilters.keys
        require(additions.all { it.filterId in parsedIds }) { "Every added filter must be downloaded and parsed first" }
        val existingIds = getSourceFilterGroups(sourceId).mapNotNull { it.filterId }.toSet()
        require(additions.none { it.filterId in existingIds }) { "A selected filter is already in this source" }
        val oldDomains = getDescendantDomains(sourceId)
        val db = writableDatabase
        db.beginTransaction()
        try {
            val categoryIds = getGroups(sourceId)
                .filter { it.type == GroupType.CATEGORY }
                .mapNotNull { category -> category.registryGroupId?.let { it to category.id } }
                .toMap()
                .toMutableMap()
            for (filter in additions) {
                val categoryId = categoryIds[filter.registryGroupId] ?: run {
                    val categoryValues = ContentValues().apply {
                        put("parent_id", sourceId)
                        put("name", filter.registryGroupName)
                        put("type", GroupType.CATEGORY)
                        put("enabled", 1)
                        put("registry_group_id", filter.registryGroupId)
                    }
                    db.insertOrThrow("managed_groups", null, categoryValues).also {
                        categoryIds[filter.registryGroupId] = it
                    }
                }
                val groupValues = ContentValues().apply {
                    put("parent_id", categoryId)
                    put("name", filter.name)
                    put("type", GroupType.FILTER)
                    put("enabled", 1)
                    put("filter_id", filter.filterId)
                    put("download_url", filter.downloadUrl)
                    put("description", filter.description)
                    put("version", filter.version)
                }
                val filterGroupId = db.insertOrThrow("managed_groups", null, groupValues)
                insertParsedFilter(db, filterGroupId, parsedFilters.getValue(filter.filterId), updatedAt)
            }
            db.execSQL("UPDATE managed_groups SET updated_at = ? WHERE id = ?", arrayOf(updatedAt, sourceId))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        deleteEmptyRows()
        val newDomains = getDescendantDomains(sourceId)
        return GroupUpdateDifference(
            addedDomains = (newDomains - oldDomains).size,
            removedDomains = 0,
            unchangedDomains = oldDomains.size,
            importedDomains = (newDomains - oldDomains).size,
            ignoredRuleCount = additions.sumOf { parsedFilters.getValue(it.filterId).ignoredRuleCount }
        )
    }

    @Synchronized
    fun updateAdGuardGroup(sourceId: Long, parsedFilters: Map<Int, ParsedFilter>, updatedAt: Long): GroupUpdateDifference {
        requireGroupType(sourceId, GroupType.SOURCE)
        val sourceFilters = getSourceFilterGroups(sourceId)
        val expectedFilterIds = sourceFilters.mapNotNull { it.filterId }.toSet()
        require(expectedFilterIds.isNotEmpty() && parsedFilters.keys.containsAll(expectedFilterIds)) {
            "Every selected AdGuard list must download and parse before updating the source"
        }
        val oldDomains = getDescendantDomains(sourceId)
        val db = writableDatabase
        var ignored = 0
        db.beginTransaction()
        try {
            sourceFilters.forEach { filter ->
                db.delete("group_domains", "group_id = ?", arrayOf(filter.id.toString()))
            }
            for (filter in sourceFilters) {
                val parsed = parsedFilters.getValue(filter.filterId!!)
                ignored += parsed.ignoredRuleCount
                insertParsedFilter(db, filter.id, parsed, updatedAt)
            }
            db.execSQL("UPDATE managed_groups SET updated_at = ? WHERE id = ?", arrayOf(updatedAt, sourceId))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        deleteEmptyRows()
        val newDomains = getDescendantDomains(sourceId)
        return GroupUpdateDifference(
            addedDomains = (newDomains - oldDomains).size,
            removedDomains = (oldDomains - newDomains).size,
            unchangedDomains = (oldDomains intersect newDomains).size,
            importedDomains = newDomains.size,
            ignoredRuleCount = ignored
        )
    }

    @Synchronized
    fun loadHidden(): Set<String> = load("hidden = 1")

    @Synchronized
    fun loadCandidates(): List<String> {
        val values = mutableListOf<String>()
        readableDatabase.query(
            "domains",
            arrayOf("domain"),
            "suggested_at IS NOT NULL AND blocked = 0 AND hidden = 0 " +
                "AND NOT EXISTS (SELECT 1 FROM group_domains WHERE group_domains.domain = domains.domain)",
            null,
            null,
            null,
            "suggested_at DESC"
        ).use { cursor ->
            while (cursor.moveToNext()) values.add(cursor.getString(0))
        }
        return values
    }

    @Synchronized
    fun addCandidate(domain: String): Boolean {
        val values = ContentValues().apply {
            put("domain", domain)
        }
        writableDatabase.insertWithOnConflict("domains", null, values, SQLiteDatabase.CONFLICT_IGNORE)
        val candidateValues = ContentValues().apply {
            put("suggested_at", System.currentTimeMillis())
        }
        return writableDatabase.update(
            "domains",
            candidateValues,
            "domain = ? AND blocked = 0 AND hidden = 0 AND suggested_at IS NULL " +
                "AND NOT EXISTS (SELECT 1 FROM group_domains WHERE group_domains.domain = domains.domain)",
            arrayOf(domain)
        ) > 0
    }

    @Synchronized
    fun addRule(domain: String, blocked: Boolean) {
        if (blocked) {
            addManualDomain(MANUAL_ROOT_ID, domain)
            return
        }
        val db = writableDatabase
        db.beginTransaction()
        try {
            db.execSQL(
                "INSERT OR IGNORE INTO domains(domain) VALUES (?)",
                arrayOf(domain)
            )
            db.execSQL(
                "UPDATE domains SET hidden = 1, suggested_at = NULL WHERE domain = ?",
                arrayOf(domain)
            )
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun addRules(domains: Collection<String>, blocked: Boolean): Int {
        if (domains.isEmpty()) return 0
        val db = writableDatabase
        if (blocked) {
            db.beginTransaction()
            try {
                for (domain in domains) {
                    val values = ContentValues().apply {
                        put("domain", domain)
                        put("blocked", 0)
                        put("suggested_at", null as Long?)
                    }
                    db.insertWithOnConflict("domains", null, values, SQLiteDatabase.CONFLICT_IGNORE)
                    db.execSQL("INSERT OR IGNORE INTO group_domains(group_id, domain) VALUES (?, ?)", arrayOf(MANUAL_ROOT_ID, domain))
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
            return domains.size
        }
        val column = if (blocked) "blocked" else "hidden"
        var imported = 0
        db.beginTransaction()
        try {
            for (domain in domains) {
                db.execSQL("INSERT OR IGNORE INTO domains(domain) VALUES (?)", arrayOf(domain))
                val values = ContentValues().apply {
                    put(column, 1)
                    put("suggested_at", null as Long?)
                }
                imported += db.update("domains", values, "domain = ?", arrayOf(domain))
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return imported
    }

    @Synchronized
    fun importLists(blockedDomains: Collection<String>, ignoredDomains: Collection<String>): Int {
        if (blockedDomains.isEmpty() && ignoredDomains.isEmpty()) return 0
        val db = writableDatabase
        var imported = 0
        db.beginTransaction()
        try {
            imported += importRules(db, blockedDomains, "blocked")
            imported += importRules(db, ignoredDomains, "hidden")
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return imported
    }

    @Synchronized
    fun removeRule(domain: String, blocked: Boolean) {
        if (blocked) {
            writableDatabase.execSQL("DELETE FROM group_domains WHERE group_id = ? AND domain = ?", arrayOf(MANUAL_ROOT_ID, domain))
            writableDatabase.execSQL("UPDATE domains SET blocked = 0 WHERE domain = ?", arrayOf(domain))
        } else {
            writableDatabase.execSQL("UPDATE domains SET hidden = 0 WHERE domain = ?", arrayOf(domain))
        }
        deleteEmptyRows()
    }

    @Synchronized
    fun removeCandidate(domain: String) {
        writableDatabase.execSQL("UPDATE domains SET suggested_at = NULL WHERE domain = ?", arrayOf(domain))
        deleteEmptyRows()
    }

    @Synchronized
    fun hideAllCandidates() {
        writableDatabase.execSQL(
            "UPDATE domains SET hidden = 1, suggested_at = NULL " +
                "WHERE suggested_at IS NOT NULL AND blocked = 0 AND hidden = 0"
        )
    }

    private fun load(selection: String): Set<String> {
        val values = LinkedHashSet<String>()
        readableDatabase.query("domains", arrayOf("domain"), selection, null, null, null, null).use { cursor ->
            while (cursor.moveToNext()) values.add(cursor.getString(0))
        }
        return values
    }

    private fun deleteEmptyRows() {
        writableDatabase.execSQL(
            "DELETE FROM domains WHERE blocked = 0 AND hidden = 0 AND suggested_at IS NULL " +
                "AND NOT EXISTS (SELECT 1 FROM group_domains WHERE group_domains.domain = domains.domain)"
        )
    }

    private fun importRules(db: SQLiteDatabase, domains: Collection<String>, column: String): Int {
        var imported = 0
        for (domain in domains) {
            if (column == "blocked") {
                val domainValues = ContentValues().apply {
                    put("domain", domain)
                    put("blocked", 0)
                    put("suggested_at", null as Long?)
                }
                db.insertWithOnConflict("domains", null, domainValues, SQLiteDatabase.CONFLICT_IGNORE)
                db.execSQL("INSERT OR IGNORE INTO group_domains(group_id, domain) VALUES (?, ?)", arrayOf(MANUAL_ROOT_ID, domain))
                imported++
            } else {
                db.execSQL("INSERT OR IGNORE INTO domains(domain) VALUES (?)", arrayOf(domain))
                val values = ContentValues().apply {
                    put(column, 1)
                    put("suggested_at", null as Long?)
                }
                imported += db.update("domains", values, "domain = ?", arrayOf(domain))
            }
        }
        return imported
    }

    private fun createGroupTables(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS managed_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_id INTEGER REFERENCES managed_groups(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                source_key TEXT,
                registry_group_id INTEGER,
                filter_id INTEGER,
                download_url TEXT,
                description TEXT,
                version TEXT,
                updated_at INTEGER,
                domain_count INTEGER NOT NULL DEFAULT 0,
                ignored_rule_count INTEGER NOT NULL DEFAULT 0
            )"""
        )
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS group_domains (
                group_id INTEGER NOT NULL REFERENCES managed_groups(id) ON DELETE CASCADE,
                domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
                PRIMARY KEY(group_id, domain)
            )"""
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS managed_groups_parent_idx ON managed_groups(parent_id, type, name)")
        db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS managed_groups_filter_idx ON managed_groups(parent_id, filter_id) WHERE filter_id IS NOT NULL")
        db.execSQL("CREATE INDEX IF NOT EXISTS group_domains_domain_idx ON group_domains(domain)")
        db.execSQL(
            "INSERT OR IGNORE INTO managed_groups(id, parent_id, name, type, enabled) VALUES (?, NULL, 'Manual', ?, 1)",
            arrayOf(MANUAL_ROOT_ID, GroupType.MANUAL)
        )
    }

    private fun snapshotGroup(group: ManagedGroup): DomainGroupSnapshot {
        val sourceKey = if (group.type == GroupType.SOURCE) ADGUARD_SOURCE_KEY else null
        return DomainGroupSnapshot(
            name = group.name,
            type = group.type,
            enabled = group.enabled,
            sourceKey = sourceKey,
            registryGroupId = group.registryGroupId,
            filterId = group.filterId,
            downloadUrl = group.downloadUrl,
            description = group.description,
            version = group.version,
            updatedAt = group.updatedAt,
            domainCount = group.domainCount,
            ignoredRuleCount = group.ignoredRuleCount,
            domains = getGroupDomains(group.id),
            children = getGroups(group.id).map(::snapshotGroup)
        )
    }

    private fun importGroupTree(db: SQLiteDatabase, groups: Collection<DomainGroupSnapshot>) {
        groups.forEach { group ->
            if (group.type == GroupType.MANUAL && group.name.equals("Manual", ignoreCase = true)) {
                db.execSQL(
                    "UPDATE managed_groups SET enabled = ? WHERE id = ?",
                    arrayOf(if (group.enabled) 1 else 0, MANUAL_ROOT_ID)
                )
                importSnapshotContents(db, MANUAL_ROOT_ID, group)
            } else if (group.type == GroupType.MANUAL) {
                val id = insertGroupFromSnapshot(db, MANUAL_ROOT_ID, group)
                importSnapshotContents(db, id, group)
            } else {
                val id = insertGroupFromSnapshot(db, null, group)
                importSnapshotContents(db, id, group)
            }
        }
    }

    private fun importCandidateRows(db: SQLiteDatabase, candidates: Collection<String>): Int {
        var imported = 0
        for (domain in candidates) {
            val values = ContentValues().apply {
                put("domain", domain)
                put("blocked", 0)
            }
            db.insertWithOnConflict("domains", null, values, SQLiteDatabase.CONFLICT_IGNORE)
            val candidateValues = ContentValues().apply {
                put("suggested_at", System.currentTimeMillis())
            }
            imported += db.update(
                "domains",
                candidateValues,
                "domain = ? AND blocked = 0 AND hidden = 0 AND suggested_at IS NULL " +
                    "AND NOT EXISTS (SELECT 1 FROM group_domains WHERE group_domains.domain = domains.domain)",
                arrayOf(domain)
            )
        }
        return imported
    }

    private fun importSnapshotContents(db: SQLiteDatabase, groupId: Long, snapshot: DomainGroupSnapshot) {
        for (domain in snapshot.domains) {
            val values = ContentValues().apply {
                put("domain", domain)
                put("blocked", 0)
                put("suggested_at", null as Long?)
            }
            db.insertWithOnConflict("domains", null, values, SQLiteDatabase.CONFLICT_IGNORE)
            db.execSQL("INSERT OR IGNORE INTO group_domains(group_id, domain) VALUES (?, ?)", arrayOf(groupId, domain))
        }
        for (child in snapshot.children) {
            val childId = insertGroupFromSnapshot(db, groupId, child)
            importSnapshotContents(db, childId, child)
        }
    }

    private fun insertGroupFromSnapshot(db: SQLiteDatabase, parentId: Long?, snapshot: DomainGroupSnapshot): Long {
        require(snapshot.type in setOf(GroupType.MANUAL, GroupType.SOURCE, GroupType.CATEGORY, GroupType.FILTER)) {
            "Unknown folder type in imported JSON"
        }
        if (snapshot.type == GroupType.SOURCE && snapshot.sourceKey != ADGUARD_SOURCE_KEY) {
            throw IllegalArgumentException("Unsupported pre-made source in imported JSON")
        }
        when (snapshot.type) {
            GroupType.MANUAL -> if (parentId != null) requireParentType(db, parentId, GroupType.MANUAL)
            GroupType.SOURCE -> require(parentId == null) { "Source groups must be top-level" }
            GroupType.CATEGORY -> requireParentType(db, parentId, GroupType.SOURCE)
            GroupType.FILTER -> {
                requireParentType(db, parentId, GroupType.CATEGORY)
                require(snapshot.filterId != null) { "Filter list ID is missing" }
                require(snapshot.downloadUrl?.startsWith("https://filters.adtidy.org/android/filters/") == true) {
                    "Unsupported filter feed URL"
                }
            }
        }
        val existingId = findMatchingGroup(db, parentId, snapshot)
        val values = ContentValues().apply {
            if (parentId == null) putNull("parent_id") else put("parent_id", parentId)
            put("name", snapshot.name)
            put("type", snapshot.type)
            put("enabled", if (snapshot.enabled) 1 else 0)
            put("source_key", snapshot.sourceKey)
            put("registry_group_id", snapshot.registryGroupId)
            put("filter_id", snapshot.filterId)
            put("download_url", snapshot.downloadUrl)
            put("description", snapshot.description)
            put("version", snapshot.version)
            put("updated_at", snapshot.updatedAt)
            put("domain_count", snapshot.domainCount)
            put("ignored_rule_count", snapshot.ignoredRuleCount)
        }
        return if (existingId == null) {
            db.insertOrThrow("managed_groups", null, values)
        } else {
            db.update("managed_groups", values, "id = ?", arrayOf(existingId.toString()))
            existingId
        }
    }

    private fun requireParentType(db: SQLiteDatabase, parentId: Long?, expectedType: String) {
        require(parentId != null) { "Folder parent is missing" }
        db.query("managed_groups", arrayOf("type"), "id = ?", arrayOf(parentId.toString()), null, null, null).use { cursor ->
            require(cursor.moveToFirst() && cursor.getString(0) == expectedType) { "Invalid folder nesting" }
        }
    }

    private fun findMatchingGroup(db: SQLiteDatabase, parentId: Long?, snapshot: DomainGroupSnapshot): Long? {
        val selection: String
        val args: Array<String>?
        when (snapshot.type) {
            GroupType.SOURCE -> {
                selection = if (parentId == null) {
                    "parent_id IS NULL AND type = ? AND source_key = ? AND name = ? COLLATE NOCASE"
                } else {
                    "parent_id = ? AND type = ? AND source_key = ? AND name = ? COLLATE NOCASE"
                }
                args = if (parentId == null) {
                    arrayOf(GroupType.SOURCE, snapshot.sourceKey ?: ADGUARD_SOURCE_KEY, snapshot.name)
                } else {
                    arrayOf(parentId.toString(), GroupType.SOURCE, snapshot.sourceKey ?: ADGUARD_SOURCE_KEY, snapshot.name)
                }
            }
            GroupType.CATEGORY -> {
                selection = if (parentId == null) "parent_id IS NULL AND type = ? AND registry_group_id = ?" else
                    "parent_id = ? AND type = ? AND registry_group_id = ?"
                args = if (parentId == null) arrayOf(GroupType.CATEGORY, snapshot.registryGroupId.toString()) else
                    arrayOf(parentId.toString(), GroupType.CATEGORY, snapshot.registryGroupId.toString())
            }
            GroupType.FILTER -> {
                selection = if (parentId == null) "parent_id IS NULL AND type = ? AND filter_id = ?" else
                    "parent_id = ? AND type = ? AND filter_id = ?"
                args = if (parentId == null) arrayOf(GroupType.FILTER, snapshot.filterId.toString()) else
                    arrayOf(parentId.toString(), GroupType.FILTER, snapshot.filterId.toString())
            }
            else -> {
                selection = if (parentId == null) "parent_id IS NULL AND type = ? AND name = ? COLLATE NOCASE" else
                    "parent_id = ? AND type = ? AND name = ? COLLATE NOCASE"
                args = if (parentId == null) arrayOf(GroupType.MANUAL, snapshot.name) else
                    arrayOf(parentId.toString(), GroupType.MANUAL, snapshot.name)
            }
        }
        return db.query("managed_groups", arrayOf("id"), selection, args, null, null, null).use { cursor ->
            if (cursor.moveToFirst()) cursor.getLong(0) else null
        }
    }

    private fun requireGroupType(groupId: Long, expectedType: String) {
        require(getGroup(groupId)?.type == expectedType) { "Operation is not valid for this folder" }
    }

    private fun insertParsedFilter(db: SQLiteDatabase, groupId: Long, parsed: ParsedFilter, updatedAt: Long) {
        for (domain in parsed.domains) {
            val domainValues = ContentValues().apply {
                put("domain", domain)
                put("blocked", 0)
            }
            db.insertWithOnConflict("domains", null, domainValues, SQLiteDatabase.CONFLICT_IGNORE)
            db.execSQL("INSERT OR IGNORE INTO group_domains(group_id, domain) VALUES (?, ?)", arrayOf(groupId, domain))
        }
        val filterValues = ContentValues().apply {
            put("version", parsed.sourceVersion)
            put("updated_at", updatedAt)
            put("domain_count", parsed.domains.size)
            put("ignored_rule_count", parsed.ignoredRuleCount)
        }
        db.update("managed_groups", filterValues, "id = ?", arrayOf(groupId.toString()))
    }

    private fun getDescendantDomains(groupId: Long): Set<String> {
        val domains = LinkedHashSet<String>()
        readableDatabase.rawQuery(
            """WITH RECURSIVE group_tree(id) AS (
                SELECT id FROM managed_groups WHERE id = ?
                UNION ALL SELECT child.id FROM managed_groups child JOIN group_tree parent ON child.parent_id = parent.id
            ) SELECT DISTINCT gd.domain FROM group_domains gd JOIN group_tree tree ON gd.group_id = tree.id""",
            arrayOf(groupId.toString())
        ).use { cursor -> while (cursor.moveToNext()) domains.add(cursor.getString(0)) }
        return domains
    }

    private fun getDescendantIgnoredRuleCount(groupId: Long): Int = readableDatabase.rawQuery(
        """WITH RECURSIVE group_tree(id) AS (
            SELECT id FROM managed_groups WHERE id = ?
            UNION ALL SELECT child.id FROM managed_groups child JOIN group_tree parent ON child.parent_id = parent.id
        ) SELECT COALESCE(SUM(g.ignored_rule_count), 0) FROM managed_groups g JOIN group_tree tree ON g.id = tree.id""",
        arrayOf(groupId.toString())
    ).use { cursor -> if (cursor.moveToFirst()) cursor.getInt(0) else 0 }

    private fun android.database.Cursor.toManagedGroup(): ManagedGroup = ManagedGroup(
        id = getLong(0),
        parentId = if (isNull(1)) null else getLong(1),
        name = getString(2),
        type = getString(3),
        enabled = getInt(4) == 1,
        registryGroupId = if (isNull(5)) null else getInt(5),
        filterId = if (isNull(6)) null else getInt(6),
        downloadUrl = if (isNull(7)) null else getString(7),
        description = if (isNull(8)) null else getString(8),
        version = if (isNull(9)) null else getString(9),
        updatedAt = if (isNull(10)) null else getLong(10),
        domainCount = getInt(11),
        ignoredRuleCount = getInt(12)
    )

    companion object {
        const val MANUAL_ROOT_ID = 1L
        const val ADGUARD_SOURCE_KEY = "adguard-filters"
        private val GROUP_COLUMNS = arrayOf(
            "id", "parent_id", "name", "type", "enabled", "registry_group_id", "filter_id",
            "download_url", "description", "version", "updated_at", "domain_count", "ignored_rule_count"
        )
    }
}