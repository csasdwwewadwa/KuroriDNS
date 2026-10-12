package com.kurori.dns.dns

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.content.pm.ServiceInfo
import com.kurori.dns.MainActivity
import com.kurori.dns.rules.DomainMatcher
import com.kurori.dns.rules.DomainStore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.concurrent.thread

class DnsVpnService : VpnService() {
    @Volatile private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var running = false
    @Volatile private var starting = false
    @Volatile private var tunnelGeneration = 0
    @Volatile private var blockedDomains = DomainMatcher(emptyList())
    @Volatile private var hiddenDomains = DomainMatcher(emptyList())
    private val candidateDomains = ConcurrentHashMap.newKeySet<String>()
    private val databaseExecutor = Executors.newSingleThreadExecutor()
    private lateinit var store: DomainStore

    override fun onCreate() {
        super.onCreate()
        store = DomainStore(applicationContext)
        synchronized(this) { activeService = this }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProtection()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> {
                reloadRulesAsync()
                return START_STICKY
            }
            ACTION_RECONFIGURE -> {
                reconfigureTunnel()
                return START_STICKY
            }
        }

        startAsForegroundService()
        val shouldStart = synchronized(this) {
            if (!running && !starting) {
                starting = true
                true
            } else {
                false
            }
        }
        if (shouldStart) {
            sendStateChanged()
            databaseExecutor.execute {
                try {
                    loadRules()
                    if (starting) establishTunnel()
                } catch (_: Exception) {
                    stopSelf()
                } finally {
                    starting = false
                    sendStateChanged()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        closeTunnel()
        databaseExecutor.shutdown()
        synchronized(this) { if (activeService === this) activeService = null }
        sendStateChanged()
        super.onDestroy()
    }

    private fun stopProtection() {
        starting = false
        closeTunnel()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        sendStateChanged()
        stopSelf()
    }

    private fun closeTunnel() {
        val previous = synchronized(this) {
            running = false
            starting = false
            tunnelGeneration += 1
            tunnel.also { tunnel = null }
        }
        previous?.close()
    }

    private fun establishTunnel() {
        val builder = Builder()
            .setSession("Kurori DNS")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(VIRTUAL_ADDRESS, 32)
            .addDnsServer(DNS_ADDRESS)
            .addRoute(DNS_ADDRESS, 32)
        val excludedPackages = getSharedPreferences(PREFERENCES, MODE_PRIVATE)
            .getStringSet(EXCLUDED_PACKAGES, emptySet())
            .orEmpty()
        for (packageName in excludedPackages) {
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: PackageManager.NameNotFoundException) {
                Unit
            }
        }
        val descriptor = builder.establish()

        if (descriptor == null) {
            stopSelf()
            return
        }

        var previous: ParcelFileDescriptor? = null
        val generation = synchronized(this) {
            if (!starting) {
                descriptor.close()
                return
            }
            tunnelGeneration += 1
            previous = tunnel
            tunnel = descriptor
            running = true
            starting = false
            tunnelGeneration
        }
        previous?.close()
        sendStateChanged()
        thread(name = "KuroriDnsPackets") { processPackets(descriptor, generation) }
    }

    private fun reconfigureTunnel() {
        val previous = synchronized(this) {
            if (!running || starting) return
            starting = true
        }
        sendStateChanged()
        databaseExecutor.execute {
            try {
                loadRules()
                if (starting) establishTunnel()
            } catch (_: Exception) {
                stopSelf()
            } finally {
                starting = false
                sendStateChanged()
            }
        }
    }

    private fun processPackets(descriptor: ParcelFileDescriptor, generation: Int) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val packetBuffer = ByteArray(32767)
        val upstream = DatagramSocket()
        try {
            if (!protect(upstream)) return
            upstream.soTimeout = UPSTREAM_TIMEOUT_MS
            val upstreamAddress = InetAddress.getByName(UPSTREAM_ADDRESS)

            while (isCurrentGeneration(generation)) {
                val packetLength = input.read(packetBuffer)
                if (packetLength <= 0) continue
                val query = DnsPacket.parseIpv4Udp(packetBuffer, packetLength) ?: continue
                val domain = DomainMatcher.normalize(query.domain) ?: continue

                val response = if (blockedDomains.matches(domain)) {
                    DnsPacket.errorResponse(query.dnsMessage, RCODE_NXDOMAIN)
                } else {
                    rememberCandidate(domain)
                    forwardQuery(upstream, upstreamAddress, query.dnsMessage)
                        ?: DnsPacket.errorResponse(query.dnsMessage, RCODE_SERVFAIL)
                }

                if (response != null && isCurrentGeneration(generation)) {
                    val responsePacket = DnsPacket.responsePacket(query, response)
                    output.write(responsePacket)
                }
            }
        } catch (_: IOException) {
            if (isCurrentGeneration(generation)) stopSelf()
        } finally {
            upstream.close()
        }
    }

    private fun isCurrentGeneration(generation: Int): Boolean = running && tunnelGeneration == generation

    private fun forwardQuery(
        socket: DatagramSocket,
        address: InetAddress,
        dnsMessage: ByteArray
    ): ByteArray? {
        return try {
            socket.send(DatagramPacket(dnsMessage, dnsMessage.size, address, UPSTREAM_PORT))
            val responseBuffer = ByteArray(MAX_DNS_MESSAGE_SIZE)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            responseBuffer.copyOf(responsePacket.length)
        } catch (_: IOException) {
            null
        }
    }

    private fun rememberCandidate(domain: String) {
        if (!getSharedPreferences(PREFERENCES, MODE_PRIVATE).getBoolean(COLLECT_CANDIDATES, true)) return
        if (hiddenDomains.matches(domain) || !candidateDomains.add(domain)) return
        databaseExecutor.execute {
            if (store.addCandidate(domain)) {
                sendBroadcast(Intent(ACTION_CANDIDATES_CHANGED).setPackage(packageName))
            }
        }
    }

    private fun loadRules() {
        blockedDomains = DomainMatcher(store.loadBlocked())
        hiddenDomains = DomainMatcher(store.loadHidden())
        candidateDomains.clear()
        candidateDomains.addAll(store.loadCandidates())
    }

    private fun reloadRulesAsync() {
        databaseExecutor.execute { loadRules() }
    }

    private fun sendStateChanged() {
        sendBroadcast(Intent(ACTION_STATE_CHANGED).setPackage(packageName))
    }

    private fun startAsForegroundService() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "DNS protection", NotificationManager.IMPORTANCE_LOW)
            )
        }

        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Kurori DNS is active")
            .setContentText("Filtering DNS requests on this device")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        const val ACTION_START = "com.kurori.dns.START"
        const val ACTION_STOP = "com.kurori.dns.STOP"
        const val ACTION_RELOAD = "com.kurori.dns.RELOAD"
        const val ACTION_RECONFIGURE = "com.kurori.dns.RECONFIGURE"
        const val ACTION_STATE_CHANGED = "com.kurori.dns.STATE_CHANGED"
        const val ACTION_CANDIDATES_CHANGED = "com.kurori.dns.CANDIDATES_CHANGED"
        private const val CHANNEL_ID = "dns-protection"
        private const val NOTIFICATION_ID = 1
        private const val UPSTREAM_ADDRESS = "1.1.1.1"
        private const val UPSTREAM_PORT = 53
        private const val UPSTREAM_TIMEOUT_MS = 2500
        private const val MAX_DNS_MESSAGE_SIZE = 4096
        private const val RCODE_NXDOMAIN = 3
        private const val RCODE_SERVFAIL = 2
        private const val PREFERENCES = "kurori-settings"
        private const val COLLECT_CANDIDATES = "collect-candidates"
        private const val EXCLUDED_PACKAGES = "excluded-packages"
        private const val VIRTUAL_ADDRESS = "10.111.0.2"
        private const val DNS_ADDRESS = "10.111.0.1"

        @Volatile private var activeService: DnsVpnService? = null

        fun isActive(): Boolean = activeService?.running == true

        fun isStarting(): Boolean = activeService?.starting == true

        fun reloadActiveRules(context: android.content.Context) {
            val service = activeService
            service?.reloadRulesAsync()
        }
    }
}