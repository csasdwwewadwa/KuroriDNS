# Kurori DNS

Kurori DNS is an Android DNS-filtering prototype built around `VpnService`.

## Open and build

Open this folder in Android Studio and allow Gradle sync to finish. The project uses Android Gradle Plugin 8.13.2, Kotlin 2.2.21, compile SDK 36, and minimum SDK 26. Build the debug APK with **Build > Build Bundle(s) / APK(s) > Build APK(s)**.

## Current behavior

- Starts a user-approved, foreground VPN service that routes its local IPv4 DNS endpoint into the app.
- Returns NXDOMAIN for blacklist matches and forwards other supported DNS requests to `1.1.1.1` over UDP.
- Stores a permanent Manual group, nested manual folders, pre-made source groups, their category/filter folders, ignored suggestions, and candidate domains in SQLite. Active blocking is the union of domains owned by every enabled folder.
- Swiping a folder right enables it and left disables it. The same folder row opens the folder when tapped. Manual folders support adding, removing, and renaming domains/folders; pre-made source groups support adding/removing filter folders and updates.
- Adds AdGuard sources from the live official Android filter registry (`filters.adtidy.org/android/filters.json`), with category folders and current feed URLs. Deprecated catalog entries are labeled.
- Updates a source only after every selected feed downloads and parses successfully, then replaces that source's rule memberships in one transaction while preserving each folder's enabled state. Reports added, removed, and unchanged domain counts. Home can update all source groups.
- Parses DNS-compatible host-wide domain rules (`||domain^`), DNS-wide `dnsrewrite=NXDOMAIN`, and common null-route hosts-file entries. It applies same-feed host exceptions. URL/path rules, third-party/app-scoped rules, cosmetic/HTML/scriptlet rules, and other request-context rules are skipped and counted because Kurori currently only sees DNS names.
- Presents Home, Block list, and Settings pages with a fixed top-right navigation menu; secondary pages include a Back button and return Home with system Back.
- Places a large START/STOP control low on Home; STOP is highlighted while protection is active.
- Provides searchable Review, Blocked, and Ignored domain lists, paged in groups of up to 200.
- Lets users swipe a review candidate right to block it or left to ignore it. Rows physically track the swipe, reveal red BLOCK or gray IGNORE labels, then animate away or back; tapping opens the same actions.
- Imports and exports a versioned JSON backup containing the full group tree, each group's owned domains and enabled state, ignored domains, and pending suggestions. Version-1 flat `blockedDomains`/`ignoredDomains` files remain importable; version-2 restores are idempotent and merge matching folders/lists.
- Offers light, dark, and system appearance modes, plus Android's per-app language settings entry.
- Lets users exclude selected launchable apps from the VPN. Android sends excluded apps over normal networking, so their DNS is not filtered and their ads may load.
- Shows a blocking loading overlay while the installed-app exclusion list is prepared.
- Rebuilds the VPN interface when app exclusions change; the replacement interface is established before retiring the previous one.
- Matches a rule against the exact domain and its subdomains. Matching is case-insensitive and supports IDN normalization.
- Keeps domain collection configurable. Turning it off stops adding new candidate domains; existing candidates remain until acted on.
- Performs database operations away from the DNS packet thread and Android UI thread.

## Prototype limitations

This is an initial prototype, not yet suitable as a complete daily-use DNS firewall. It currently handles IPv4 UDP DNS only; IPv6, DNS-over-TCP, fragmented DNS packets, resolver configuration, robust reconnect behavior, and broader integration tests still need implementation. Upstream DNS is plain UDP, not encrypted. Apps that use their own encrypted DNS may bypass filtering. Android permits only one active VPN per user/profile.

Battery use should be low while idle because the service waits for packets instead of polling, but needs measurement on devices. Lists are stored in SQLite, indexed in memory for DNS decisions, and displayed in pages of up to 200 domains.