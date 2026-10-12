package com.kurori.dns

import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ResolveInfo
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.ViewGroup
import android.view.WindowInsets
import android.widget.FrameLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import com.kurori.dns.dns.DnsVpnService
import com.kurori.dns.rules.AdGuardFilters
import com.kurori.dns.rules.DomainGroupSnapshot
import com.kurori.dns.rules.DomainMatcher
import com.kurori.dns.rules.DomainStore
import com.kurori.dns.rules.FilterCatalogEntry
import com.kurori.dns.rules.GroupType
import com.kurori.dns.rules.GroupUpdateDifference
import com.kurori.dns.rules.ManagedGroup
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private data class AppChoice(val packageName: String, val label: String, val icon: android.graphics.drawable.Drawable)

    private val colorBackground: Int get() = if (darkMode) DARK_BACKGROUND else LIGHT_BACKGROUND
    private val colorSurface: Int get() = if (darkMode) DARK_SURFACE else LIGHT_SURFACE
    private val colorText: Int get() = if (darkMode) DARK_TEXT else LIGHT_TEXT
    private val colorMuted: Int get() = if (darkMode) DARK_MUTED else LIGHT_MUTED
    private val colorAccent: Int get() = if (darkMode) DARK_ACCENT else LIGHT_ACCENT
    private val colorOnAccent: Int get() = if (darkMode) DARK_ON_ACCENT else LIGHT_ON_ACCENT
    private lateinit var store: DomainStore
    private lateinit var statusText: TextView
    private lateinit var protectionButton: Button
    private lateinit var domainInput: EditText
    private lateinit var searchInput: EditText
    private lateinit var content: LinearLayout
    private lateinit var listContent: LinearLayout
    private lateinit var tabBar: LinearLayout
    private lateinit var rootContainer: FrameLayout
    private lateinit var menuButton: Button
    private lateinit var backButton: Button
    private lateinit var excludedAppsButton: Button
    private lateinit var folderActions: LinearLayout
    private val databaseExecutor = Executors.newSingleThreadExecutor()
    private var displayedCandidates: List<String> = emptyList()
    private var displayedBlocked: List<String> = emptyList()
    private var displayedHidden: List<String> = emptyList()
    private var selectedList = LIST_CANDIDATES
    private var visibleDomainLimit = PAGE_SIZE
    private var selectedPage = PAGE_HOME
    private val folderStack = mutableListOf<Long>()
    private var darkMode = true
    private var receiverRegistered = false
    private var loadingOverlay: View? = null
    private var currentFolder: ManagedGroup? = null
    private var folderGroups: List<ManagedGroup> = emptyList()
    private var folderDomains: List<String> = emptyList()
    private var viewingCandidates = false
    private var viewingIgnored = false
    private var folderLoadGeneration = 0
    private var currentSourceId: Long? = null
    private val serviceEventsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                DnsVpnService.ACTION_STATE_CHANGED -> updateStatus()
                DnsVpnService.ACTION_CANDIDATES_CHANGED -> refreshScreen()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        darkMode = resolveDarkMode()
        setTheme(if (darkMode) R.style.AppTheme else R.style.AppTheme_Light)
        super.onCreate(savedInstanceState)
        savedInstanceState?.let {
            selectedList = it.getInt(STATE_SELECTED_LIST, LIST_CANDIDATES)
            selectedPage = it.getInt(STATE_SELECTED_PAGE, PAGE_HOME)
            it.getLongArray(STATE_FOLDER_STACK)?.let { ids -> folderStack.addAll(ids.toList()) }
        }
        store = DomainStore(applicationContext)
        buildScreen()
        refreshScreen()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt(STATE_SELECTED_LIST, selectedList)
        outState.putInt(STATE_SELECTED_PAGE, selectedPage)
        outState.putLongArray(STATE_FOLDER_STACK, folderStack.toLongArray())
        super.onSaveInstanceState(outState)
    }

    override fun onResume() {
        super.onResume()
        if (::statusText.isInitialized) {
            updateStatus()
            refreshScreen()
        }
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter().apply {
            addAction(DnsVpnService.ACTION_STATE_CHANGED)
            addAction(DnsVpnService.ACTION_CANDIDATES_CHANGED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(serviceEventsReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(serviceEventsReceiver, filter)
        }
        receiverRegistered = true
    }

    override fun onStop() {
        if (receiverRegistered) {
            unregisterReceiver(serviceEventsReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    override fun onDestroy() {
        databaseExecutor.shutdown()
        super.onDestroy()
    }

    @Deprecated("Use the back dispatcher on newer Android versions")
    override fun onBackPressed() {
        if (selectedPage != PAGE_HOME || folderStack.isNotEmpty()) handleBackNavigation() else super.onBackPressed()
    }

    private fun buildScreen() {
        rootContainer = FrameLayout(this).apply {
            setBackgroundColor(colorBackground)
        }
        val scroll = ScrollView(this)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(68), dp(20), dp(24))
            setBackgroundColor(colorBackground)
        }
        scroll.addView(content)
        rootContainer.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
        ))
        menuButton = Button(this).apply {
            text = "☰"
            textSize = 24f
            contentDescription = "Open navigation menu"
            styleButton(this)
            elevation = dp(6).toFloat()
            setOnClickListener { showNavigationMenu(this) }
        }
        rootContainer.addView(menuButton, FrameLayout.LayoutParams(dp(56), dp(52), Gravity.TOP or Gravity.END).apply {
            topMargin = dp(4)
            marginEnd = dp(12)
        })
        backButton = Button(this).apply {
            text = "<"
            textSize = 24f
            contentDescription = "Go back"
            styleButton(this)
            elevation = dp(6).toFloat()
            setOnClickListener { handleBackNavigation() }
        }
        rootContainer.addView(backButton, FrameLayout.LayoutParams(dp(56), dp(52), Gravity.TOP or Gravity.END).apply {
            topMargin = dp(4)
            marginEnd = dp(72)
        })
        rootContainer.setOnApplyWindowInsetsListener { view, insets ->
            val topInset: Int
            val bottomInset: Int
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars())
                topInset = bars.top
                bottomInset = bars.bottom
            } else {
                @Suppress("DEPRECATION")
                val top = insets.systemWindowInsetTop
                @Suppress("DEPRECATION")
                val bottom = insets.systemWindowInsetBottom
                topInset = top
                bottomInset = bottom
            }
            view.setPadding(0, topInset, 0, bottomInset)
            insets
        }
        setContentView(rootContainer)
        window.statusBarColor = colorBackground
        window.navigationBarColor = colorBackground
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = if (darkMode) 0 else
            android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or android.view.View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        renderPage()
        rootContainer.requestApplyInsets()
    }

    private fun renderPage() {
        content.removeAllViews()
        backButton.visibility = if (selectedPage == PAGE_HOME && folderStack.isEmpty()) View.GONE else View.VISIBLE
        when (selectedPage) {
            PAGE_LISTS -> buildListsPage()
            PAGE_SETTINGS -> buildSettingsPage()
            else -> buildHomePage()
        }
    }

    private fun buildHomePage() {
        addPageHeader("Kurori", "DNS filter")
        statusText = TextView(this).apply {
            textSize = 15f
            setTextColor(colorMuted)
        }
        content.addView(statusText, spacedParams())

        val summary = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(14), dp(16), dp(14), dp(16))
            setBackgroundColor(colorSurface)
        }
        summary.addView(metricView(displayedBlocked.size, "Blocked"),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        summary.addView(metricView(displayedCandidates.size, "To review"),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        content.addView(summary, spacedParams())
        content.addView(Button(this).apply {
            text = "Update all block lists"
            styleButton(this)
            setOnClickListener { updateAllAdGuardGroups() }
        }, spacedParams())
        val buttonContainer = FrameLayout(this).apply {
            minimumHeight = dp(360)
        }
        protectionButton = Button(this).apply {
            textSize = 30f
            minHeight = dp(152)
            setPadding(dp(28), dp(24), dp(28), dp(24))
            setOnClickListener { toggleProtection() }
            styleProtectionButton(this)
        }
        val buttonParams = FrameLayout.LayoutParams(dp(240), dp(160), Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL).apply {
            bottomMargin = dp(24)
        }
        buttonContainer.addView(protectionButton, buttonParams)
        content.addView(buttonContainer, spacedParams())
        updateStatus()
    }

    private fun buildListsPage() {
        addPageHeader("Block list", "Review domains and manage your lists")
        val transferButtons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        transferButtons.addView(Button(this).apply {
            text = "Import JSON"
            styleButton(this)
            setOnClickListener { chooseImportTarget() }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        transferButtons.addView(Button(this).apply {
            text = "Export JSON"
            styleButton(this)
            setOnClickListener { chooseExportTarget() }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        content.addView(transferButtons, spacedParams())

        folderActions = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        content.addView(folderActions, spacedParams())
        domainInput = EditText(this).apply {
            hint = "Add manual domain"
            setSingleLine(true)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI
            styleField(this)
        }
        searchInput = EditText(this).apply {
            hint = "Filter domains"
            setSingleLine(true)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            styleField(this)
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    visibleDomainLimit = PAGE_SIZE
                    renderFolderContents()
                }
                override fun afterTextChanged(s: Editable?) = Unit
            })
        }
        content.addView(searchInput, spacedParams())
        listContent = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(listContent, spacedParams())
        refreshFolderContents()
    }

    private fun refreshFolderContents() {
        val generation = ++folderLoadGeneration
        val requestedPath = folderStack.toList()
        databaseExecutor.execute {
            try {
                val validPath = mutableListOf<Long>()
                var parentId: Long? = null
                var folder: ManagedGroup? = null
                for (id in requestedPath) {
                    val next = store.getGroup(id) ?: break
                    if (next.parentId != parentId) break
                    validPath.add(id)
                    folder = next
                    parentId = id
                }
                val groups = store.getGroups(parentId)
                val domains = if (folder?.type == GroupType.MANUAL || folder?.type == GroupType.FILTER) {
                    store.getGroupDomains(folder.id)
                } else {
                    emptyList()
                }
                val sourceId = when (folder?.type) {
                    GroupType.SOURCE -> folder.id
                    GroupType.CATEGORY -> folder.parentId
                    GroupType.FILTER -> folder.parentId?.let(store::getGroup)?.parentId
                    else -> null
                }
                runOnUiThread {
                    if (!isFinishing && !isDestroyed && selectedPage == PAGE_LISTS && generation == folderLoadGeneration) {
                        folderStack.clear()
                        folderStack.addAll(validPath)
                        currentFolder = folder
                        currentSourceId = sourceId
                        folderGroups = groups
                        folderDomains = domains
                        backButton.visibility = View.VISIBLE
                        configureFolderActions()
                        renderFolderContents()
                    }
                }
            } catch (_: Exception) {
                runOnUiThread {
                    if (!isFinishing && !isDestroyed && generation == folderLoadGeneration) {
                        Toast.makeText(this, "Could not open this folder", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun configureFolderActions() {
        folderActions.removeAllViews()
        val folder = currentFolder
        if (folder == null) {
            addActionButton("New manual folder") { addManualFolder() }
            addActionButton("Add AdGuard source") { beginAddAdGuardGroup() }
            return
        }
        when (folder.type) {
            GroupType.MANUAL -> {
                val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                actions.addView(Button(this).apply {
                    text = "New subfolder"
                    styleButton(this)
                    setOnClickListener { addManualFolder() }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                if (folder.id != DomainStore.MANUAL_ROOT_ID) {
                    actions.addView(Button(this).apply {
                        text = "Rename"
                        styleButton(this)
                        setOnClickListener { renameGroup(folder) }
                    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                    actions.addView(Button(this).apply {
                        text = "Delete"
                        styleButton(this)
                        setOnClickListener { confirmDeleteGroup(folder) }
                    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                }
                folderActions.addView(actions, spacedParams())
                addManualDomainRow()
            }
            GroupType.SOURCE -> {
                val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                actions.addView(Button(this).apply {
                    text = "Update"
                    styleButton(this, primary = true)
                    setOnClickListener { updateAdGuardSource(folder.id) }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                actions.addView(Button(this).apply {
                    text = "Add lists"
                    styleButton(this)
                    setOnClickListener { beginAddFiltersToSource(folder.id) }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                actions.addView(Button(this).apply {
                    text = "Rename"
                    styleButton(this)
                    setOnClickListener { renameGroup(folder) }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                actions.addView(Button(this).apply {
                    text = "Delete"
                    styleButton(this)
                    setOnClickListener { confirmDeleteGroup(folder) }
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                folderActions.addView(actions, spacedParams())
                val metadata = folder.updatedAt?.let { "Updated ${android.text.format.DateFormat.format("yyyy-MM-dd", it)}" }
                    ?: "Not downloaded yet"
                addMutedLabel(metadata)
            }
            GroupType.CATEGORY, GroupType.FILTER -> {
                val sourceId = currentSourceId
                if (sourceId != null) {
                    val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                    actions.addView(Button(this).apply {
                        text = "Update"
                        styleButton(this)
                        setOnClickListener { updateAdGuardSource(sourceId) }
                    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                    actions.addView(Button(this).apply {
                        text = "Rename"
                        styleButton(this)
                        setOnClickListener { renameGroup(folder) }
                    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                    actions.addView(Button(this).apply {
                        text = "Remove"
                        styleButton(this)
                        setOnClickListener { confirmDeleteGroup(folder) }
                    }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                    folderActions.addView(actions, spacedParams())
                }
                if (folder.type == GroupType.FILTER) {
                    val metadata = folder.version?.let { "Version $it" } ?: "Not downloaded yet"
                    addMutedLabel("$metadata · ${folder.domainCount} domains · ${folder.ignoredRuleCount} rules skipped")
                }
            }
        }
    }

    private fun addManualDomainRow() {
        val addRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        (domainInput.parent as? ViewGroup)?.removeView(domainInput)
        addRow.addView(domainInput, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addRow.addView(Button(this).apply {
            text = "Add"
            styleButton(this, primary = true)
            setOnClickListener { addManualDomainToCurrentFolder() }
        })
        folderActions.addView(addRow, spacedParams())
    }

    private fun addManualDomainToCurrentFolder() {
        val domain = DomainMatcher.normalize(domainInput.text.toString())
        if (domain == null) {
            Toast.makeText(this, "Enter a valid domain name", Toast.LENGTH_SHORT).show()
            return
        }
        val groupId = currentFolder?.id ?: DomainStore.MANUAL_ROOT_ID
        databaseExecutor.execute {
            store.addManualDomain(groupId, domain)
            DnsVpnService.reloadActiveRules(this)
            runOnUiThread {
                domainInput.text.clear()
                refreshScreen()
            }
        }
    }

    private fun addManualFolder() {
        val activeFolder = currentFolder
        val parentId = if (activeFolder?.type == GroupType.MANUAL) activeFolder.id else DomainStore.MANUAL_ROOT_ID
        val input = EditText(this).apply {
            hint = "Folder name"
            setSingleLine(true)
            styleField(this)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("New manual folder")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Create", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val name = input.text.toString().trim()
                if (name.isEmpty()) {
                    input.error = "Enter a folder name"
                    return@setOnClickListener
                }
                databaseExecutor.execute {
                    store.addManualFolder(parentId, name)
                    runOnUiThread {
                        dialog.dismiss()
                        refreshFolderContents()
                    }
                }
            }
        }
        dialog.show()
    }

    private fun confirmDeleteGroup(group: ManagedGroup) {
        AlertDialog.Builder(this)
            .setTitle("Delete ${group.name}?")
            .setMessage("Its folder contents and downloaded rules will be removed.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ ->
                databaseExecutor.execute {
                    store.deleteGroup(group.id)
                    DnsVpnService.reloadActiveRules(this)
                    runOnUiThread {
                        if (folderStack.lastOrNull() == group.id) folderStack.removeAt(folderStack.lastIndex)
                        refreshScreen()
                    }
                }
            }
            .show()
    }

    private fun renameGroup(group: ManagedGroup) {
        val input = EditText(this).apply {
            setText(group.name)
            setSingleLine(true)
            styleField(this)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Rename folder")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val name = input.text.toString().trim()
                if (name.isEmpty()) {
                    input.error = "Enter a folder name"
                    return@setOnClickListener
                }
                databaseExecutor.execute {
                    store.renameGroup(group.id, name)
                    runOnUiThread {
                        dialog.dismiss()
                        refreshFolderContents()
                    }
                }
            }
        }
        dialog.show()
    }

    private fun addActionButton(label: String, action: () -> Unit) {
        folderActions.addView(Button(this).apply {
            text = label
            styleButton(this)
            setOnClickListener { action() }
        }, spacedParams())
    }

    private fun addMutedLabel(text: String) {
        folderActions.addView(TextView(this).apply {
            this.text = text
            textSize = 13f
            setTextColor(colorMuted)
        }, spacedParams())
    }

    private fun beginAddAdGuardGroup() {
        showLoadingOverlay("Loading AdGuard filter catalog...")
        databaseExecutor.execute {
            val catalog = try {
                AdGuardFilters.loadCatalog()
            } catch (_: Exception) {
                null
            }
            runOnUiThread {
                hideAppLoadingOverlay()
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (catalog == null) {
                    Toast.makeText(this, "Could not load the AdGuard filter catalog", Toast.LENGTH_LONG).show()
                } else {
                    showAdGuardCatalogPicker(catalog)
                }
            }
        }
    }

    private fun beginAddFiltersToSource(sourceId: Long) {
        showLoadingOverlay("Loading AdGuard filter catalog...")
        databaseExecutor.execute {
            val result = try {
                AdGuardFilters.loadCatalog() to store.getSourceFilterGroups(sourceId).mapNotNull { it.filterId }.toSet()
            } catch (_: Exception) {
                null
            }
            runOnUiThread {
                hideAppLoadingOverlay()
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (result == null) {
                    Toast.makeText(this, "Could not load AdGuard filter lists", Toast.LENGTH_LONG).show()
                } else {
                    showAdGuardCatalogPicker(result.first, sourceId, result.second)
                }
            }
        }
    }

    private fun showAdGuardCatalogPicker(
        catalog: List<FilterCatalogEntry>,
        existingSourceId: Long? = null,
        existingFilterIds: Set<Int> = emptySet()
    ) {
        val selectedIds = if (existingSourceId == null) mutableSetOf(2, 3, 11) else mutableSetOf()
        val nameInput = EditText(this).apply {
            setText("AdGuard Filters")
            setSingleLine(true)
            styleField(this)
        }
        val search = EditText(this).apply {
            hint = "Search filters"
            setSingleLine(true)
            styleField(this)
        }
        val filterRows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val pickerContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(4), dp(20), 0)
        }
        val groupNameLabel = TextView(this).apply {
            text = "Source group name"
            setTextColor(colorMuted)
            textSize = 13f
            if (existingSourceId != null) visibility = View.GONE
        }
        pickerContent.addView(groupNameLabel, spacedParams())
        val sourceNameInput = nameInput
        if (existingSourceId != null) sourceNameInput.visibility = View.GONE
        pickerContent.addView(nameInput, spacedParams())
        pickerContent.addView(search, spacedParams())
        pickerContent.addView(TextView(this).apply {
            text = "Choose lists. Deprecated feeds are marked; only host-wide DNS rules are applied."
            setTextColor(colorMuted)
            textSize = 13f
        }, spacedParams())
        val scroll = ScrollView(this).apply { addView(filterRows) }
        pickerContent.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(380)
        ).apply { topMargin = dp(8) })
        var visibleLimit = CATALOG_PAGE_SIZE

        fun renderCatalog(query: String) {
            filterRows.removeAllViews()
            val matching = catalog.filter {
                it.name.contains(query, ignoreCase = true) ||
                    it.description.contains(query, ignoreCase = true) ||
                    it.registryGroupName.contains(query, ignoreCase = true)
            }
            var previousCategory = -1
            matching.take(visibleLimit).forEach { filter ->
                if (filter.registryGroupId != previousCategory) {
                    previousCategory = filter.registryGroupId
                    filterRows.addView(TextView(this).apply {
                        text = filter.registryGroupName
                        textSize = 17f
                        setTextColor(colorText)
                        setTypeface(typeface, android.graphics.Typeface.BOLD)
                        setPadding(0, dp(12), 0, dp(4))
                    }, spacedParams())
                }
                val checkBox = CheckBox(this).apply {
                    text = filter.name + if (filter.deprecated) " (deprecated)" else ""
                    isChecked = filter.filterId in existingFilterIds || filter.filterId in selectedIds
                    isEnabled = filter.filterId !in existingFilterIds
                    setTextColor(colorText)
                    buttonTintList = ColorStateList.valueOf(if (filter.deprecated) colorMuted else colorAccent)
                    setOnCheckedChangeListener { _, checked ->
                        if (checked) selectedIds.add(filter.filterId) else selectedIds.remove(filter.filterId)
                    }
                    contentDescription = "${filter.name}. ${filter.description}"
                }
                filterRows.addView(checkBox, spacedParams())
            }
            if (matching.isEmpty()) {
                filterRows.addView(TextView(this).apply {
                    text = "No matching AdGuard lists"
                    setTextColor(colorMuted)
                }, spacedParams())
            } else if (visibleLimit < matching.size) {
                filterRows.addView(Button(this).apply {
                    text = "Show next ${minOf(CATALOG_PAGE_SIZE, matching.size - visibleLimit)} filters"
                    styleButton(this)
                    setOnClickListener {
                        visibleLimit += CATALOG_PAGE_SIZE
                        renderCatalog(search.text.toString())
                    }
                }, spacedParams())
            }
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                visibleLimit = CATALOG_PAGE_SIZE
                renderCatalog(s?.toString().orEmpty())
            }
            override fun afterTextChanged(s: Editable?) = Unit
        })
        renderCatalog("")

        val dialog = AlertDialog.Builder(this)
            .setTitle(if (existingSourceId == null) "Add AdGuard source" else "Add AdGuard lists")
            .setView(pickerContent)
            .setNegativeButton("Cancel", null)
            .setPositiveButton(if (existingSourceId == null) "Add and download" else "Add selected lists", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val selected = catalog.filter { it.filterId in selectedIds }
                val groupName = sourceNameInput.text.toString().trim()
                if (existingSourceId == null && groupName.isEmpty()) {
                    sourceNameInput.error = "Enter a source group name"
                    return@setOnClickListener
                }
                if (selected.isEmpty()) {
                    Toast.makeText(this, "Choose at least one filter", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                dialog.dismiss()
                if (existingSourceId == null) createAndDownloadAdGuardGroup(groupName, selected)
                else addFiltersToAdGuardGroup(existingSourceId, selected)
            }
        }
        dialog.show()
    }

    private fun createAndDownloadAdGuardGroup(name: String, filters: List<FilterCatalogEntry>) {
        showLoadingOverlay("Downloading and parsing ${filters.size} AdGuard lists...")
        databaseExecutor.execute {
            var sourceId: Long? = null
            try {
                val parsed = filters.associate { filter ->
                    filter.filterId to AdGuardFilters.downloadAndParse(filter)
                }
                sourceId = store.createAdGuardGroup(name, filters)
                val difference = store.updateAdGuardGroup(sourceId, parsed, System.currentTimeMillis())
                DnsVpnService.reloadActiveRules(this)
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, updateSummary(name, difference), Toast.LENGTH_LONG).show()
                    refreshScreen()
                }
            } catch (_: Exception) {
                sourceId?.let { runCatching { store.deleteGroup(it) } }
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, "Could not create the AdGuard group; no source folders were added", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun addFiltersToAdGuardGroup(sourceId: Long, filters: List<FilterCatalogEntry>) {
        showLoadingOverlay("Downloading and parsing ${filters.size} AdGuard lists...")
        databaseExecutor.execute {
            try {
                val parsed = filters.associate { filter ->
                    filter.filterId to AdGuardFilters.downloadAndParse(filter)
                }
                val difference = store.addAdGuardFilters(sourceId, filters, parsed, System.currentTimeMillis())
                DnsVpnService.reloadActiveRules(this)
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, updateSummary("AdGuard lists added", difference), Toast.LENGTH_LONG).show()
                    refreshScreen()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, "Could not add these lists; the source was unchanged", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun updateAdGuardSource(sourceId: Long) {
        val source = currentFolder?.takeIf { it.id == sourceId } ?: folderStack
            .asReversed().firstNotNullOfOrNull { id -> store.getGroup(id)?.takeIf { it.id == sourceId } }
        val sourceName = source?.name ?: "AdGuard Filters"
        showLoadingOverlay("Updating $sourceName...")
        databaseExecutor.execute {
            try {
                val filters = store.getSourceFilterGroups(sourceId).map { group ->
                    val category = group.parentId?.let(store::getGroup)
                    FilterCatalogEntry(
                        filterId = group.filterId ?: throw IOException("Missing AdGuard filter ID"),
                        name = group.name,
                        description = group.description.orEmpty(),
                        registryGroupId = category?.registryGroupId ?: 0,
                        registryGroupName = category?.name ?: "Other",
                        downloadUrl = group.downloadUrl ?: throw IOException("Missing AdGuard feed URL"),
                        version = group.version.orEmpty(),
                        deprecated = false
                    )
                }
                if (filters.isEmpty()) throw IOException("This source has no selected lists")
                val parsed = filters.associate { filter ->
                    filter.filterId to AdGuardFilters.downloadAndParse(filter)
                }
                val difference = store.updateAdGuardGroup(sourceId, parsed, System.currentTimeMillis())
                DnsVpnService.reloadActiveRules(this)
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, updateSummary(sourceName, difference), Toast.LENGTH_LONG).show()
                    refreshScreen()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, "Update failed; the existing source lists were kept", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun updateAllAdGuardGroups() {
        showLoadingOverlay("Updating all block lists...")
        databaseExecutor.execute {
            var updated = 0
            var failed = 0
            var added = 0
            var removed = 0
            var unchanged = 0
            var ignored = 0
            try {
                val sources = store.getPremadeSourceGroups()
                if (sources.isEmpty()) {
                    runOnUiThread {
                        hideAppLoadingOverlay()
                        Toast.makeText(this, "Add a pre-made source from Block list first", Toast.LENGTH_LONG).show()
                    }
                    return@execute
                }
                for (source in sources) {
                    try {
                        val filters = store.getSourceFilterGroups(source.id).map { group ->
                            val category = group.parentId?.let(store::getGroup)
                            FilterCatalogEntry(
                                filterId = group.filterId ?: throw IOException("Missing filter ID"),
                                name = group.name,
                                description = group.description.orEmpty(),
                                registryGroupId = category?.registryGroupId ?: 0,
                                registryGroupName = category?.name ?: "Other",
                                downloadUrl = group.downloadUrl ?: throw IOException("Missing feed URL"),
                                version = group.version.orEmpty(),
                                deprecated = false
                            )
                        }
                        val parsed = filters.associate { it.filterId to AdGuardFilters.downloadAndParse(it) }
                        val result = store.updateAdGuardGroup(source.id, parsed, System.currentTimeMillis())
                        updated++
                        added += result.addedDomains
                        removed += result.removedDomains
                        unchanged += result.unchangedDomains
                        ignored += result.ignoredRuleCount
                    } catch (_: Exception) {
                        failed++
                    }
                }
                if (updated > 0) DnsVpnService.reloadActiveRules(this)
                runOnUiThread {
                    hideAppLoadingOverlay()
                    val summary = "Updated $updated source groups: +$added, -$removed, $unchanged unchanged; $ignored non-DNS rules skipped" +
                        if (failed > 0) "; $failed failed and kept unchanged" else ""
                    Toast.makeText(this, summary, Toast.LENGTH_LONG).show()
                    refreshScreen()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    hideAppLoadingOverlay()
                    Toast.makeText(this, "Could not update block lists", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun updateSummary(name: String, difference: GroupUpdateDifference): String =
        "$name updated: +${difference.addedDomains}, -${difference.removedDomains}, " +
            "${difference.unchangedDomains} unchanged; ${difference.ignoredRuleCount} non-DNS rules skipped"


    private fun buildSettingsPage() {
        addPageHeader("Settings", "Appearance, language, and discovery")
        addSectionTitle("Appearance", content)
        val themeButtons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(colorSurface)
        }
        listOf("system", "light", "dark").forEach { mode ->
            themeButtons.addView(Button(this).apply {
                text = mode.replaceFirstChar { it.uppercase() }
                minWidth = 0
                styleButton(this, primary = getThemeMode() == mode)
                setOnClickListener {
                    getSharedPreferences(PREFERENCES, MODE_PRIVATE).edit()
                        .putString(THEME_MODE, mode)
                        .apply()
                    recreate()
                }
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
        content.addView(themeButtons, spacedParams())

        addSectionTitle("Language", content)
        content.addView(TextView(this).apply {
                text = "English is available. Choose the system default or app language below."
            textSize = 14f
            setTextColor(colorMuted)
        }, spacedParams())
        content.addView(Button(this).apply {
            text = "Open app language settings"
            styleButton(this)
            isEnabled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
            setOnClickListener {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val intent = Intent(Settings.ACTION_APP_LOCALE_SETTINGS).apply {
                        data = android.net.Uri.fromParts("package", packageName, null)
                    }
                    startActivity(intent)
                }
            }
        }, spacedParams())

        addSectionTitle("Domain discovery", content)
        content.addView(Switch(this).apply {
            text = "Suggest newly discovered domains"
            setTextColor(colorText)
            buttonTintList = ColorStateList.valueOf(colorAccent)
            isChecked = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
                .getBoolean(COLLECT_CANDIDATES, true)
            setOnCheckedChangeListener { _, enabled ->
                getSharedPreferences(PREFERENCES, MODE_PRIVATE).edit()
                    .putBoolean(COLLECT_CANDIDATES, enabled)
                    .apply()
            }
        }, spacedParams())

        addSectionTitle("App exclusions", content)
        content.addView(TextView(this).apply {
            text = "Excluded apps use normal networking. Their DNS bypasses Kurori, so ads may appear in those apps."
            textSize = 14f
            setTextColor(colorMuted)
        }, spacedParams())
        excludedAppsButton = Button(this).apply {
            text = "Choose apps to exclude (${loadExcludedPackages().size})"
            styleButton(this)
            setOnClickListener { loadAppsForExclusionPicker() }
        }
        content.addView(excludedAppsButton, spacedParams())
    }

    private fun loadAppsForExclusionPicker() {
        showAppLoadingOverlay()
        databaseExecutor.execute {
            val apps = try {
                val packageManager = packageManager
                val launchIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                packageManager.queryIntentActivities(launchIntent, 0)
                    .asSequence()
                    .mapNotNull { it.activityInfo?.applicationInfo }
                    .filter { it.packageName != packageName }
                    .distinctBy { it.packageName }
                    .mapNotNull { application ->
                        try {
                            AppChoice(
                                application.packageName,
                                packageManager.getApplicationLabel(application).toString(),
                                packageManager.getApplicationIcon(application)
                            )
                        } catch (_: Exception) {
                            null
                        }
                    }
                    .sortedBy { it.label.lowercase() }
                    .toList()
            } catch (_: Exception) {
                null
            }
            runOnUiThread {
                hideAppLoadingOverlay()
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (apps == null) {
                    Toast.makeText(this, "Could not load installed apps", Toast.LENGTH_LONG).show()
                } else {
                    showAppExclusionPicker(apps)
                }
            }
        }
    }

    private fun showAppLoadingOverlay() {
        showLoadingOverlay("Loading installed apps...")
    }

    private fun showLoadingOverlay(message: String) {
        if (loadingOverlay != null) return
        val overlay = FrameLayout(this).apply {
            setBackgroundColor(if (darkMode) 0xB8000000.toInt() else 0x88000000.toInt())
            isClickable = true
            isFocusable = true
        }
        val panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(28), dp(24), dp(28), dp(24))
            setBackgroundColor(colorSurface)
        }
        panel.addView(ProgressBar(this), LinearLayout.LayoutParams(dp(40), dp(40)))
        panel.addView(TextView(this).apply {
            text = message
            setTextColor(colorText)
            textSize = 15f
        }, spacedParams())
        overlay.addView(panel, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER
        ))
        loadingOverlay = overlay
        rootContainer.addView(overlay, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT
        ))
    }

    private fun hideAppLoadingOverlay() {
        loadingOverlay?.let(rootContainer::removeView)
        loadingOverlay = null
    }

    private fun showAppExclusionPicker(apps: List<AppChoice>) {
        val selectedPackages = loadExcludedPackages().toMutableSet()
        val pickerContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        val search = EditText(this).apply {
            hint = "Search installed apps"
            setSingleLine(true)
            styleField(this)
        }
        pickerContent.addView(search, spacedParams())
        pickerContent.addView(TextView(this).apply {
            text = "Excluded apps bypass DNS filtering and may show ads."
            textSize = 13f
            setTextColor(colorMuted)
        }, spacedParams())
        val appRows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val appScroll = ScrollView(this).apply { addView(appRows) }
        pickerContent.addView(appScroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(380)
        ).apply { topMargin = dp(8) })
        var visibleAppLimit = APP_PAGE_SIZE

        val dialog = AlertDialog.Builder(this)
            .setTitle("Exclude apps")
            .setView(pickerContent)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Apply", null)
            .create()

        fun renderApps(query: String) {
            appRows.removeAllViews()
            val matching = apps.filter {
                it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
            }
            matching.take(visibleAppLimit).forEach { app ->
                val row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(0, dp(4), 0, dp(4))
                }
                row.addView(ImageView(this).apply {
                    setImageDrawable(app.icon)
                    contentDescription = null
                }, LinearLayout.LayoutParams(dp(40), dp(40)))
                val toggle = Switch(this).apply {
                    text = app.label
                    setTextColor(colorText)
                    buttonTintList = ColorStateList.valueOf(colorAccent)
                    isChecked = app.packageName in selectedPackages
                    setOnCheckedChangeListener { _, checked ->
                        if (checked) selectedPackages.add(app.packageName) else selectedPackages.remove(app.packageName)
                    }
                }
                row.addView(toggle, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                row.setOnClickListener { toggle.isChecked = !toggle.isChecked }
                appRows.addView(row, spacedParams())
            }
            if (matching.isEmpty()) {
                appRows.addView(TextView(this).apply {
                    text = "No matching launchable apps"
                    setTextColor(colorMuted)
                }, spacedParams())
            } else if (visibleAppLimit < matching.size) {
                appRows.addView(Button(this).apply {
                    text = "Show next ${minOf(APP_PAGE_SIZE, matching.size - visibleAppLimit)} apps"
                    styleButton(this)
                    setOnClickListener {
                        visibleAppLimit += APP_PAGE_SIZE
                        renderApps(search.text.toString())
                    }
                }, spacedParams())
            }
        }

        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                visibleAppLimit = APP_PAGE_SIZE
                renderApps(s?.toString().orEmpty())
            }
            override fun afterTextChanged(s: Editable?) = Unit
        })
        renderApps("")
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val previous = loadExcludedPackages()
                val updated = selectedPackages.toSet()
                getSharedPreferences(PREFERENCES, MODE_PRIVATE).edit()
                    .putStringSet(EXCLUDED_PACKAGES, updated)
                    .apply()
                excludedAppsButton.text = "Choose apps to exclude (${updated.size})"
                if (previous != updated && DnsVpnService.isActive()) {
                    startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_RECONFIGURE))
                    Toast.makeText(this, "Updating DNS protection...", Toast.LENGTH_SHORT).show()
                }
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun loadExcludedPackages(): Set<String> = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
        .getStringSet(EXCLUDED_PACKAGES, emptySet())?.toSet().orEmpty()

    private fun showNavigationMenu(anchor: View) {
        PopupMenu(this, anchor).apply {
            menu.add(0, MENU_BLOCK_LIST, 0, "Block list")
            menu.add(0, MENU_SETTINGS, 1, "Settings")
            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    MENU_BLOCK_LIST -> navigateTo(PAGE_LISTS)
                    MENU_SETTINGS -> navigateTo(PAGE_SETTINGS)
                }
                true
            }
            show()
        }
    }

    private fun navigateTo(page: Int) {
        if (selectedPage == page) return
        selectedPage = page
        folderStack.clear()
        viewingCandidates = false
        viewingIgnored = false
        renderPage()
    }

    private fun handleBackNavigation() {
        when {
            viewingCandidates || viewingIgnored -> {
                viewingCandidates = false
                viewingIgnored = false
                refreshFolderContents()
            }
            selectedPage == PAGE_LISTS && folderStack.isNotEmpty() -> {
                folderStack.removeAt(folderStack.lastIndex)
                refreshFolderContents()
            }
            selectedPage != PAGE_HOME -> navigateTo(PAGE_HOME)
        }
    }

    private fun addPageHeader(title: String, subtitle: String) {
        content.addView(TextView(this).apply {
            text = title
            textSize = 27f
            setTextColor(colorText)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        content.addView(TextView(this).apply {
            text = subtitle
            textSize = 14f
            setTextColor(colorMuted)
        }, spacedParams())
    }

    private fun metricView(value: Int, label: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@MainActivity).apply {
            text = value.toString()
            textSize = 24f
            setTextColor(colorText)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        addView(TextView(this@MainActivity).apply {
            text = label
            textSize = 13f
            setTextColor(colorMuted)
        })
    }

    private fun getThemeMode(): String = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
        .getString(THEME_MODE, THEME_SYSTEM) ?: THEME_SYSTEM

    private fun resolveDarkMode(): Boolean = when (getThemeMode()) {
        THEME_DARK -> true
        THEME_LIGHT -> false
        else -> resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK ==
            Configuration.UI_MODE_NIGHT_YES
    }

    private fun applyThemeColors(view: android.view.View) {
        view.setBackgroundColor(colorBackground)
    }

    private fun refreshScreen() {
        databaseExecutor.execute {
            val candidates = store.loadCandidates()
            val blocked = store.loadBlocked().sorted()
            val hidden = store.loadHidden().sorted()
            runOnUiThread {
                if (!isFinishing && !isDestroyed) {
                    displayedCandidates = candidates
                    displayedBlocked = blocked
                    displayedHidden = hidden
                    when (selectedPage) {
                        PAGE_HOME -> renderPage()
                        PAGE_LISTS -> refreshFolderContents()
                    }
                }
            }
        }
    }

    private fun renderFolderContents() {
        listContent.removeAllViews()
        val query = searchInput.text.toString().trim().lowercase()
        val title = when {
            viewingCandidates -> "Suggestions"
            viewingIgnored -> "Ignored suggestions"
            currentFolder != null -> currentFolder!!.name
            else -> "Groups"
        }
        addSectionTitle(title)

        when {
            viewingCandidates -> renderDomainPage(displayedCandidates.filter { it.contains(query) }, query, PAGE_CANDIDATES)
            viewingIgnored -> renderDomainPage(displayedHidden.filter { it.contains(query) }, query, PAGE_IGNORED)
            else -> {
                val groups = folderGroups.filter { it.name.contains(query, ignoreCase = true) }
                groups.forEach(::addGroupRow)
                val domains = folderDomains.filter { it.contains(query, ignoreCase = true) }
                val visibleDomains = domains.take(visibleDomainLimit)
                visibleDomains.forEach { domain ->
                    if (currentFolder?.type == GroupType.MANUAL) {
                        addManualDomainRuleRow(currentFolder!!.id, domain)
                    } else {
                        addReadOnlyDomainRow(domain)
                    }
                }
                if (folderStack.isEmpty() && query.isEmpty()) {
                    addSpecialFolderRow("Suggestions", "${displayedCandidates.size} new domains", PAGE_CANDIDATES)
                    addSpecialFolderRow("Ignored suggestions", "${displayedHidden.size} hidden", PAGE_IGNORED)
                }
                if (groups.isEmpty() && domains.isEmpty() && folderStack.isNotEmpty()) {
                    addEmptyLabel("This folder is empty")
                }
                addShowMore(domains.size, visibleDomains.size)
            }
        }
        updateStatus()
    }

    private fun renderDomainPage(domains: List<String>, query: String, kind: Int) {
        val visible = domains.take(visibleDomainLimit)
        if (visible.isEmpty()) {
            addEmptyLabel(if (query.isEmpty()) "Nothing here yet" else "No matching domains")
        } else if (kind == PAGE_CANDIDATES) {
            visible.forEach(::addCandidateRow)
        } else {
            visible.forEach { domain ->
                addDomainRow(domain, firstAction = "Unhide", firstBlocked = null, hiddenRule = true)
            }
        }
        addShowMore(domains.size, visible.size)
    }

    private fun addShowMore(total: Int, visible: Int) {
        if (visible >= total) return
        listContent.addView(Button(this).apply {
            text = "Show next ${minOf(PAGE_SIZE, total - visible)}"
            styleButton(this)
            setOnClickListener {
                visibleDomainLimit += PAGE_SIZE
                renderFolderContents()
            }
        }, spacedParams())
    }

    private fun addSpecialFolderRow(name: String, subtitle: String, page: Int) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(12), dp(12), dp(12))
            setBackgroundColor(colorSurface)
            setOnClickListener {
                viewingCandidates = page == PAGE_CANDIDATES
                viewingIgnored = page == PAGE_IGNORED
                visibleDomainLimit = PAGE_SIZE
                backButton.visibility = View.VISIBLE
                renderFolderContents()
            }
        }
        row.addView(TextView(this).apply {
            text = "▸"
            textSize = 20f
            setTextColor(colorAccent)
        })
        val labels = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        labels.addView(TextView(this).apply {
            text = name
            setTextColor(colorText)
            textSize = 15f
        })
        labels.addView(TextView(this).apply {
            text = subtitle
            setTextColor(colorMuted)
            textSize = 12f
        })
        row.addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(TextView(this).apply { text = "›"; setTextColor(colorMuted); textSize = 22f })
        listContent.addView(row, spacedParams())
    }

    private fun addGroupRow(group: ManagedGroup) {
        val row = FrameLayout(this)
        val onLabel = TextView(this).apply {
            text = "O\nN"
            gravity = Gravity.CENTER
            textSize = 10f
            setTextColor(Color.WHITE)
            setBackgroundColor(ACTIVE_GREEN)
        }
        val offLabel = TextView(this).apply {
            text = "O\nF\nF"
            gravity = Gravity.CENTER
            textSize = 9f
            setTextColor(Color.WHITE)
            setBackgroundColor(SWIPE_IGNORE_GRAY)
        }
        row.addView(onLabel, FrameLayout.LayoutParams(dp(ACTION_REVEAL_DP), dp(72), Gravity.START))
        row.addView(offLabel, FrameLayout.LayoutParams(dp(ACTION_REVEAL_DP), dp(72), Gravity.END))
        val foreground = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(10), dp(12), dp(10))
            setBackgroundColor(colorSurface)
        }
        foreground.addView(TextView(this).apply {
            text = "▸"
            textSize = 21f
            setTextColor(colorAccent)
        })
        val labels = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        labels.addView(TextView(this).apply {
            text = group.name
            textSize = 15f
            setTextColor(colorText)
        })
        val detail = when (group.type) {
            GroupType.SOURCE -> "AdGuard source"
            GroupType.CATEGORY -> "Category"
            GroupType.FILTER -> "${group.domainCount} domains · ${if (group.enabled) "On" else "Off"}"
            else -> "Manual folder · ${if (group.enabled) "On" else "Off"}"
        }
        labels.addView(TextView(this).apply {
            text = detail
            textSize = 12f
            setTextColor(colorMuted)
        })
        foreground.addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        foreground.addView(TextView(this).apply { text = "›"; setTextColor(colorMuted); textSize = 22f })
        row.addView(foreground, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(72)))
        attachGroupSwipe(group, row, foreground)
        listContent.addView(row, spacedParams())
    }

    private fun attachGroupSwipe(group: ManagedGroup, row: FrameLayout, foreground: View) {
        var startX = 0f
        var startY = 0f
        var dragging = false
        val touchSlop = ViewConfiguration.get(this).scaledTouchSlop
        val revealDistance = dp(ACTION_REVEAL_DP)
        foreground.setOnTouchListener { target, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    startX = event.rawX
                    startY = event.rawY
                    dragging = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = event.rawX - startX
                    val dy = event.rawY - startY
                    if (kotlin.math.abs(dx) > touchSlop && kotlin.math.abs(dx) > kotlin.math.abs(dy) * SWIPE_AXIS_RATIO) {
                        dragging = true
                        target.parent.requestDisallowInterceptTouchEvent(true)
                        foreground.translationX = dx.coerceIn(-revealDistance.toFloat(), revealDistance.toFloat())
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    val dx = foreground.translationX
                    if (dragging && kotlin.math.abs(dx) >= dp(SWIPE_COMMIT_DP)) {
                        val enabled = dx > 0
                        foreground.animate().translationX(0f).setDuration(SWIPE_SETTLE_MS).withEndAction {
                            setGroupEnabled(group, enabled)
                        }.start()
                    } else if (dragging) {
                        foreground.animate().translationX(0f).setDuration(SWIPE_SETTLE_MS).start()
                    } else {
                        folderStack.add(group.id)
                        viewingCandidates = false
                        viewingIgnored = false
                        backButton.visibility = View.VISIBLE
                        visibleDomainLimit = PAGE_SIZE
                        refreshFolderContents()
                    }
                    target.parent.requestDisallowInterceptTouchEvent(false)
                    true
                }
                MotionEvent.ACTION_CANCEL -> {
                    foreground.animate().translationX(0f).setDuration(SWIPE_SETTLE_MS).start()
                    target.parent.requestDisallowInterceptTouchEvent(false)
                    true
                }
                else -> true
            }
        }
    }

    private fun setGroupEnabled(group: ManagedGroup, enabled: Boolean) {
        databaseExecutor.execute {
            store.setGroupEnabled(group.id, enabled)
            DnsVpnService.reloadActiveRules(this)
            runOnUiThread {
                Toast.makeText(this, "${group.name} ${if (enabled) "enabled" else "disabled"}", Toast.LENGTH_SHORT).show()
                refreshScreen()
            }
        }
    }

    private fun addManualDomainRuleRow(groupId: Long, domain: String) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(4), dp(4), dp(4))
            setBackgroundColor(colorSurface)
        }
        row.addView(TextView(this).apply {
            text = domain
            textSize = 14f
            setTextColor(colorText)
            contentDescription = "$domain. Tap to copy."
            setOnClickListener { copyDomain(domain) }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(Button(this).apply {
            text = "Remove"
            styleButton(this)
            setOnClickListener {
                databaseExecutor.execute {
                    store.removeManualDomain(groupId, domain)
                    DnsVpnService.reloadActiveRules(this@MainActivity)
                    runOnUiThread { refreshScreen() }
                }
            }
        })
        listContent.addView(row, spacedParams())
    }

    private fun addReadOnlyDomainRow(domain: String) {
        listContent.addView(TextView(this).apply {
            text = domain
            textSize = 14f
            setTextColor(colorText)
            setPadding(dp(12), dp(12), dp(8), dp(12))
            setBackgroundColor(colorSurface)
            contentDescription = "$domain. Tap to copy."
            setOnClickListener { copyDomain(domain) }
        }, spacedParams())
    }

    private fun addCandidateRow(domain: String) {
        val row = FrameLayout(this).apply {
            minimumHeight = dp(76)
        }
        val blockAction = TextView(this).apply {
            text = "B\nL\nO\nC\nK"
            gravity = Gravity.CENTER
            textSize = 9f
            setTextColor(Color.WHITE)
            setBackgroundColor(SWIPE_BLOCK_RED)
        }
        row.addView(blockAction, FrameLayout.LayoutParams(dp(ACTION_REVEAL_DP), dp(76), Gravity.START))
        val ignoreAction = TextView(this).apply {
            text = "I\nG\nN\nO\nR\nE"
            gravity = Gravity.CENTER
            textSize = 9f
            setTextColor(Color.WHITE)
            setBackgroundColor(SWIPE_IGNORE_GRAY)
        }
        row.addView(ignoreAction, FrameLayout.LayoutParams(dp(ACTION_REVEAL_DP), dp(76), Gravity.END))
        val foreground = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(4), dp(4), dp(4))
            setBackgroundColor(colorSurface)
            setOnClickListener { copyDomain(domain) }
        }
        val name = TextView(this).apply {
            text = domain
            textSize = 14f
            setTextColor(colorText)
            setPadding(0, dp(12), dp(8), dp(12))
            isClickable = true
            isFocusable = true
            contentDescription = "$domain. Tap to copy. Swipe right to block or left to ignore."
        }
        foreground.addView(name, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(foreground, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(76)
        ))
        attachCandidateSwipe(name, domain, foreground)
        listContent.addView(row, spacedParams())
    }

    private fun attachCandidateSwipe(view: View, domain: String, foreground: View) {
        var startX = 0f
        var startY = 0f
        var dragging = false
        val touchSlop = ViewConfiguration.get(this).scaledTouchSlop
        val revealDistance = dp(ACTION_REVEAL_DP)
        view.setOnTouchListener { target, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    startX = event.rawX
                    startY = event.rawY
                    dragging = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val deltaX = event.rawX - startX
                    val deltaY = event.rawY - startY
                    if (kotlin.math.abs(deltaX) > touchSlop &&
                        kotlin.math.abs(deltaX) > kotlin.math.abs(deltaY) * SWIPE_AXIS_RATIO
                    ) {
                        dragging = true
                        target.parent.requestDisallowInterceptTouchEvent(true)
                        foreground.translationX = deltaX.coerceIn(-revealDistance.toFloat(), revealDistance.toFloat())
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    val distance = foreground.translationX
                    val commit = kotlin.math.abs(distance) >= dp(SWIPE_COMMIT_DP)
                    if (dragging && commit) {
                        val block = distance > 0
                        foreground.animate()
                            .translationX(if (block) rowWidth(foreground) else -rowWidth(foreground))
                            .alpha(0f)
                            .setDuration(SWIPE_SETTLE_MS)
                            .withEndAction {
                                updateStore { store.addRule(domain, blocked = block) }
                            }
                            .start()
                    } else if (dragging) {
                        foreground.animate().translationX(0f).setDuration(SWIPE_SETTLE_MS).start()
                    } else {
                        foreground.performClick()
                    }
                    target.parent.requestDisallowInterceptTouchEvent(false)
                    true
                }
                MotionEvent.ACTION_CANCEL -> {
                    foreground.animate().translationX(0f).setDuration(SWIPE_SETTLE_MS).start()
                    target.parent.requestDisallowInterceptTouchEvent(false)
                    true
                }
                else -> true
            }
        }
    }

    private fun rowWidth(view: View): Float = view.width.toFloat()

    private fun showCandidateActions(domain: String) {
        AlertDialog.Builder(this)
            .setTitle(domain)
            .setItems(arrayOf("Add to blocklist", "Ignore future suggestions")) { _, choice ->
                updateStore { store.addRule(domain, blocked = choice == 0) }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun addDomainRow(
        domain: String,
        firstAction: String,
        firstBlocked: Boolean?,
        hiddenRule: Boolean = false
    ) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(TextView(this).apply {
            text = domain
            textSize = 14f
            setTextColor(colorText)
            contentDescription = "$domain. Tap to copy."
            setOnClickListener { copyDomain(domain) }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(Button(this).apply {
            text = firstAction
            styleButton(this)
            setOnClickListener {
                updateStore {
                    when {
                        firstBlocked == true -> store.addRule(domain, blocked = true)
                        firstAction == "Unblock" -> store.removeRule(domain, blocked = true)
                        hiddenRule -> store.removeRule(domain, blocked = false)
                        else -> store.removeCandidate(domain)
                    }
                }
            }
        })
        if (firstBlocked == true) {
            row.addView(Button(this).apply {
                text = "Hide"
                styleButton(this)
                setOnClickListener { updateStore { store.addRule(domain, blocked = false) } }
            })
        }
        row.setPadding(dp(12), dp(4), dp(4), dp(4))
        row.setBackgroundColor(colorSurface)
        listContent.addView(row, spacedParams())
    }

    private fun copyDomain(domain: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Domain", domain))
        Toast.makeText(this, "Copied $domain", Toast.LENGTH_SHORT).show()
    }

    private fun addRule(blocked: Boolean) {
        val domain = DomainMatcher.normalize(domainInput.text.toString())
        if (domain == null) {
            Toast.makeText(this, "Enter a valid domain name", Toast.LENGTH_SHORT).show()
            return
        }
        domainInput.text.clear()
        updateStore { store.addRule(domain, blocked) }
    }

    private fun updateStore(action: () -> Unit) {
        databaseExecutor.execute {
            action()
            DnsVpnService.reloadActiveRules(this)
            runOnUiThread {
                if (!isFinishing && !isDestroyed) refreshScreen()
            }
        }
    }

    private fun requestVpnPermission() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent == null) startProtection()
        else startActivityForResult(permissionIntent, VPN_PERMISSION_REQUEST)
    }

    private fun toggleProtection() {
        if (DnsVpnService.isActive() || DnsVpnService.isStarting()) {
            if (::statusText.isInitialized && selectedPage == PAGE_HOME) statusText.text = "Stopping protection..."
            if (::protectionButton.isInitialized) protectionButton.isEnabled = false
            startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
        } else {
            requestVpnPermission()
        }
    }

    @Deprecated("VPN consent uses the activity result API on newer Android versions")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_PERMISSION_REQUEST && resultCode == RESULT_OK) {
            startProtection()
            return
        }
        if (resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        when (requestCode) {
            IMPORT_REQUEST -> importDomains(uri)
            EXPORT_REQUEST -> exportDomains(uri)
        }
    }

    private fun chooseImportTarget() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
        }
        startActivityForResult(intent, IMPORT_REQUEST)
    }

    private fun chooseExportTarget() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, "kurori-domain-lists.json")
        }
        startActivityForResult(intent, EXPORT_REQUEST)
    }

    private fun importDomains(uri: android.net.Uri) {
        databaseExecutor.execute {
            try {
                val json = readJsonFile(uri)
                val root = JSONObject(json)
                if (root.optString("format") != JSON_FORMAT) {
                    throw IOException("Unsupported domain list format")
                }
                val version = root.optInt("version", -1)
                val importedCount = when (version) {
                    JSON_LEGACY_VERSION -> {
                        val blocked = parseDomainArray(root.getJSONArray("blockedDomains"))
                        val ignored = parseDomainArray(root.getJSONArray("ignoredDomains"))
                        store.importLists(blocked, ignored)
                        blocked.size + ignored.size
                    }
                    JSON_VERSION -> {
                        val groups = parseGroupSnapshots(root.getJSONArray("groups"))
                        val ignored = parseDomainArray(root.optJSONArray("ignoredDomains") ?: JSONArray())
                        val candidates = parseDomainArray(root.optJSONArray("candidateDomains") ?: JSONArray())
                        if (countGroupDomains(groups) + ignored.size + candidates.size > MAX_IMPORT_DOMAINS) {
                            throw IOException("Too many total domains in JSON")
                        }
                        store.importBackup(groups, ignored, candidates)
                        countGroupDomains(groups) + ignored.size + candidates.size
                    }
                    else -> throw IOException("Unsupported domain list version")
                }
                DnsVpnService.reloadActiveRules(this)
                runOnUiThread {
                    Toast.makeText(this, "Imported $importedCount domain entries and folders", Toast.LENGTH_LONG).show()
                    refreshScreen()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Could not import this file", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun exportDomains(uri: android.net.Uri) {
        databaseExecutor.execute {
            try {
                val groupTree = store.exportGroupTree()
                val groupedDomainCount = countGroupDomains(groupTree)
                val groups = JSONArray().apply { groupTree.forEach { put(groupSnapshotToJson(it)) } }
                val ignored = JSONArray(store.loadHidden().sorted())
                val candidates = JSONArray(store.loadCandidates().sorted())
                val json = JSONObject()
                    .put("format", JSON_FORMAT)
                    .put("version", JSON_VERSION)
                    .put("groups", groups)
                    .put("ignoredDomains", ignored)
                    .put("candidateDomains", candidates)
                contentResolver.openOutputStream(uri, "wt")?.bufferedWriter(Charsets.UTF_8)?.use { writer ->
                    writer.write(json.toString(2))
                } ?: throw IOException("Unable to create selected file")
                runOnUiThread {
                    Toast.makeText(this, "Exported $groupedDomainCount grouped domains, " +
                        "${ignored.length()} ignored, and ${candidates.length()} suggestions", Toast.LENGTH_LONG).show()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Could not export this list", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun groupSnapshotToJson(group: DomainGroupSnapshot): JSONObject = JSONObject()
        .put("name", group.name)
        .put("type", group.type)
        .put("enabled", group.enabled)
        .put("sourceKey", group.sourceKey ?: JSONObject.NULL)
        .put("registryGroupId", group.registryGroupId ?: JSONObject.NULL)
        .put("filterId", group.filterId ?: JSONObject.NULL)
        .put("downloadUrl", group.downloadUrl ?: JSONObject.NULL)
        .put("description", group.description ?: JSONObject.NULL)
        .put("version", group.version ?: JSONObject.NULL)
        .put("updatedAt", group.updatedAt ?: JSONObject.NULL)
        .put("domainCount", group.domainCount)
        .put("ignoredRuleCount", group.ignoredRuleCount)
        .put("domains", JSONArray(group.domains))
        .put("children", JSONArray().apply { group.children.forEach { put(groupSnapshotToJson(it)) } })

    private fun parseGroupSnapshots(array: JSONArray): List<DomainGroupSnapshot> {
        val budget = JsonImportBudget()
        val groups = ArrayList<DomainGroupSnapshot>(array.length())
        for (index in 0 until array.length()) {
            groups.add(parseGroupSnapshot(array.getJSONObject(index), 0, budget))
        }
        return groups
    }

    private fun parseGroupSnapshot(group: JSONObject, depth: Int, budget: JsonImportBudget): DomainGroupSnapshot {
        if (depth > MAX_GROUP_DEPTH) throw IOException("Folder nesting exceeds the supported limit")
        budget.groupCount++
        if (budget.groupCount > MAX_IMPORT_GROUPS) throw IOException("Too many folders in JSON")
        val name = group.optString("name").trim()
        val type = group.optString("type")
        if (name.isEmpty()) throw IOException("Folder name is missing")
        if (type !in GROUP_TYPES) throw IOException("Unknown folder type")
        val domains = parseDomainArray(group.optJSONArray("domains") ?: JSONArray())
        budget.domainCount += domains.size
        if (budget.domainCount > MAX_IMPORT_DOMAINS) throw IOException("Too many domains in JSON")
        val childrenArray = group.optJSONArray("children") ?: JSONArray()
        val children = ArrayList<DomainGroupSnapshot>(childrenArray.length())
        for (index in 0 until childrenArray.length()) {
            children.add(parseGroupSnapshot(childrenArray.getJSONObject(index), depth + 1, budget))
        }
        return DomainGroupSnapshot(
            name = name,
            type = type,
            enabled = group.optBoolean("enabled", true),
            sourceKey = group.optString("sourceKey").takeIf { it.isNotEmpty() && it != "null" },
            registryGroupId = group.optInt("registryGroupId").takeIf { group.has("registryGroupId") && !group.isNull("registryGroupId") },
            filterId = group.optInt("filterId").takeIf { group.has("filterId") && !group.isNull("filterId") },
            downloadUrl = group.optString("downloadUrl").takeIf { it.isNotEmpty() && it != "null" },
            description = group.optString("description").takeIf { it.isNotEmpty() && it != "null" },
            version = group.optString("version").takeIf { it.isNotEmpty() && it != "null" },
            updatedAt = group.optLong("updatedAt").takeIf { group.has("updatedAt") && !group.isNull("updatedAt") },
            domainCount = group.optInt("domainCount", domains.size),
            ignoredRuleCount = group.optInt("ignoredRuleCount", 0),
            domains = domains.toList(),
            children = children
        )
    }

    private fun countGroupDomains(groups: Collection<DomainGroupSnapshot>): Int =
        groups.sumOf { it.domains.size + countGroupDomains(it.children) }

    private fun readJsonFile(uri: android.net.Uri): String {
        val input = contentResolver.openInputStream(uri) ?: throw IOException("Unable to open selected file")
        val output = ByteArrayOutputStream()
        input.use { stream ->
            val buffer = ByteArray(8192)
            var totalBytes = 0
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                totalBytes += count
                if (totalBytes > MAX_IMPORT_JSON_BYTES) throw IOException("JSON file exceeds the size limit")
                output.write(buffer, 0, count)
            }
        }
        return output.toString(Charsets.UTF_8.name())
    }

    private class JsonImportBudget(var groupCount: Int = 0, var domainCount: Int = 0)

    private fun parseDomainArray(array: JSONArray): Set<String> {
        if (array.length() > MAX_IMPORT_DOMAINS) throw IOException("Too many domains in file")
        val domains = LinkedHashSet<String>()
        for (index in 0 until array.length()) {
            val value = array.optString(index, "")
            val domain = DomainMatcher.normalize(value) ?: throw IOException("Invalid domain in file")
            domains.add(domain)
        }
        return domains
    }

    private fun startProtection() {
        val intent = Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
        if (::statusText.isInitialized && selectedPage == PAGE_HOME) statusText.text = "Starting protection..."
        if (::protectionButton.isInitialized) {
            protectionButton.text = "START"
            protectionButton.isEnabled = false
        }
    }

    private fun updateStatus() {
        when {
            DnsVpnService.isStarting() -> {
                if (::statusText.isInitialized) statusText.text = "Starting protection..."
                if (::protectionButton.isInitialized) {
                    protectionButton.text = "START"
                    styleProtectionButton(protectionButton, running = false)
                    protectionButton.isEnabled = false
                }
            }
            DnsVpnService.isActive() -> {
                if (::statusText.isInitialized) statusText.text = "Protection active"
                if (::protectionButton.isInitialized) {
                    protectionButton.text = "STOP"
                    styleProtectionButton(protectionButton, running = true)
                    protectionButton.isEnabled = true
                }
            }
            else -> {
                if (::statusText.isInitialized) statusText.text = "Protection stopped"
                if (::protectionButton.isInitialized) {
                    protectionButton.text = "START"
                    styleProtectionButton(protectionButton, running = false)
                    protectionButton.isEnabled = true
                }
            }
        }
    }

    private fun addSectionTitle(title: String, parent: LinearLayout = listContent) {
        parent.addView(TextView(this).apply {
            text = title
            textSize = 20f
            setTextColor(colorText)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }, spacedParams())
    }

    private fun addEmptyLabel(text: String) {
        listContent.addView(TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(colorMuted)
            setPadding(dp(4), dp(12), dp(4), dp(20))
        }, spacedParams())
    }

    private fun styleButton(button: Button, primary: Boolean = false) {
        button.isAllCaps = false
        button.textSize = 14f
        button.backgroundTintList = ColorStateList.valueOf(if (primary) colorAccent else colorSurface)
        button.setTextColor(if (primary) colorOnAccent else colorText)
    }

    private fun styleProtectionButton(button: Button, running: Boolean = false) {
        button.isAllCaps = true
        button.textSize = 30f
        button.backgroundTintList = ColorStateList.valueOf(if (running) ACTIVE_GREEN else colorSurface)
        button.setTextColor(if (running) COLOR_DARK_INK else colorText)
        button.elevation = dp(8).toFloat()
    }

    private fun styleField(field: EditText) {
        field.setTextColor(colorText)
        field.setHintTextColor(colorMuted)
        field.backgroundTintList = ColorStateList.valueOf(colorAccent)
        field.setPadding(dp(12), dp(12), dp(12), dp(12))
    }

    private fun spacedParams() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = dp(8) }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val VPN_PERMISSION_REQUEST = 1001
        private const val IMPORT_REQUEST = 1002
        private const val EXPORT_REQUEST = 1003
        private const val MAX_IMPORT_DOMAINS = 250_000
        private const val MAX_IMPORT_JSON_BYTES = 100 * 1024 * 1024
        private const val MAX_IMPORT_GROUPS = 10_000
        private const val MAX_GROUP_DEPTH = 32
        private const val APP_PAGE_SIZE = 200
        private const val CATALOG_PAGE_SIZE = 200
        private const val PAGE_SIZE = 200
        private const val LIST_CANDIDATES = 0
        private const val LIST_BLOCKED = 1
        private const val LIST_HIDDEN = 2
        private const val PAGE_HOME = 0
        private const val PAGE_LISTS = 1
        private const val PAGE_SETTINGS = 2
        private const val PAGE_CANDIDATES = 3
        private const val PAGE_IGNORED = 4
        private const val SWIPE_DISTANCE_DP = 72
        private const val SWIPE_AXIS_RATIO = 1.25f
        private const val ACTION_REVEAL_DP = 88
        private const val SWIPE_COMMIT_DP = 62
        private const val SWIPE_SETTLE_MS = 180L
        private const val MENU_BLOCK_LIST = 1
        private const val MENU_SETTINGS = 2
        private const val SWIPE_BLOCK_RED = 0xFFC74444.toInt()
        private const val SWIPE_IGNORE_GRAY = 0xFF68757B.toInt()
        private const val JSON_FORMAT = "kurori-domain-lists"
        private const val JSON_VERSION = 2
        private const val JSON_LEGACY_VERSION = 1
        private val GROUP_TYPES = setOf(GroupType.MANUAL, GroupType.SOURCE, GroupType.CATEGORY, GroupType.FILTER)
        private const val PREFERENCES = "kurori-settings"
        private const val COLLECT_CANDIDATES = "collect-candidates"
        private const val EXCLUDED_PACKAGES = "excluded-packages"
        private const val THEME_MODE = "theme-mode"
        private const val THEME_SYSTEM = "system"
        private const val THEME_LIGHT = "light"
        private const val THEME_DARK = "dark"
        private const val STATE_SELECTED_LIST = "selected-list"
        private const val STATE_SELECTED_PAGE = "selected-page"
        private const val STATE_FOLDER_STACK = "folder-stack"
        private const val ACTIVE_GREEN = 0xFF9BE56D.toInt()
        private const val COLOR_DARK_INK = 0xFF11200D.toInt()
        private const val DARK_BACKGROUND = 0xFF0B1113.toInt()
        private const val DARK_SURFACE = 0xFF161F22.toInt()
        private const val DARK_TEXT = 0xFFEBF2EF.toInt()
        private const val DARK_MUTED = 0xFF99ABA7.toInt()
        private const val DARK_ACCENT = 0xFF79DCC4.toInt()
        private const val DARK_ON_ACCENT = 0xFF091F1C.toInt()
        private const val LIGHT_BACKGROUND = 0xFFF4F7F6.toInt()
        private const val LIGHT_SURFACE = 0xFFFFFFFF.toInt()
        private const val LIGHT_TEXT = 0xFF172321.toInt()
        private const val LIGHT_MUTED = 0xFF5C706B.toInt()
        private const val LIGHT_ACCENT = 0xFF137C68.toInt()
        private const val LIGHT_ON_ACCENT = 0xFFFFFFFF.toInt()
    }
}