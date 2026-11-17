package com.example.vpn.engine

import android.content.Context
import com.example.data.AppLogger
import com.example.model.TrafficStats
import hev.htproxy.TProxyService
import java.io.File
import java.io.FileOutputStream

object HevTunnelManager {
    private const val TAG = "HevTunnel"
    private var lastRxBytes = 0L
    private var lastTxBytes = 0L
    private var lastTimestamp = 0L

    fun buildConfigYaml(
        socksAddress: String = "127.0.0.1",
        socksPort: Int = 10808,
        udpMode: String = "udp",
        mapDnsAddress: String = "",
        enableIpv6: Boolean = false
    ): String {
        val normalizedUdp = if (udpMode == "udp" || udpMode == "tcp") udpMode else "udp"

        // HEV expects tunnel, socks5, mapdns and misc as sibling YAML sections.
        // Building the document line-by-line avoids accidental indentation that
        // nests socks5 under tunnel and silently prevents TUN traffic forwarding.
        return buildString {
            appendLine("tunnel:")
            appendLine("  name: tun0")
            appendLine("  mtu: 1500")
            appendLine("  multi-queue: false")
            appendLine("  ipv4: 198.18.0.1")
            if (enableIpv6) {
                appendLine("  ipv6: 'fd00::1'")
            }

            appendLine("socks5:")
            appendLine("  port: $socksPort")
            appendLine("  address: '$socksAddress'")
            appendLine("  udp: '$normalizedUdp'")

            if (mapDnsAddress.isNotBlank()) {
                appendLine("mapdns:")
                appendLine("  address: ${mapDnsAddress.trim()}")
                appendLine("  port: 53")
                appendLine("  network: 240.0.0.0")
                appendLine("  netmask: 240.0.0.0")
                appendLine("  cache-size: 10000")
            }

            appendLine("misc:")
            appendLine("  task-stack-size: 81920")
            appendLine("  tcp-buffer-size: 65536")
            appendLine("  udp-recv-buffer-size: 524288")
            appendLine("  udp-copy-buffer-nums: 16")
            appendLine("  connect-timeout: 8000")
            appendLine("  tcp-read-write-timeout: 120000")
            appendLine("  udp-read-write-timeout: 30000")
            appendLine("  limit-nofile: 65535")
            append("  log-level: warn")
        }
    }

    fun start(
        context: Context,
        tunFd: Int,
        socksAddress: String = "127.0.0.1",
        socksPort: Int = 10808,
        udpMode: String = "tcp",
        mapDnsAddress: String = "",
        enableIpv6: Boolean = false
    ): Boolean {
        return try {
            lastRxBytes = 0L
            lastTxBytes = 0L
            lastTimestamp = 0L
            val configFile = File(context.cacheDir, "hev_socks5.yml")
            val yamlConfig = buildConfigYaml(socksAddress, socksPort, udpMode, mapDnsAddress, enableIpv6)

            FileOutputStream(configFile).use { it.write(yamlConfig.toByteArray()) }

            AppLogger.i(TAG, "Starting HEV SOCKS5 Tunnel forwarder pointing to $socksAddress:$socksPort (udp=$udpMode, tunFd=$tunFd)")
            val success = TProxyService.TProxyStartService(configFile.absolutePath, tunFd)
            if (success) {
                AppLogger.i(TAG, "HEV SOCKS5 Tunnel forwarder started successfully")
            } else {
                AppLogger.e(TAG, "HEV SOCKS5 Tunnel failed to start via JNI")
            }
            success
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Exception starting HEV SOCKS5 Tunnel", e)
            false
        }
    }

    fun isRunning(): Boolean {
        return try {
            TProxyService.TProxyIsRunning()
        } catch (e: Throwable) {
            false
        }
    }

    fun stop() {
        try {
            if (isRunning()) {
                AppLogger.i(TAG, "Stopping HEV SOCKS5 Tunnel forwarder")
                TProxyService.TProxyStopService()
            }
            lastRxBytes = 0L
            lastTxBytes = 0L
            lastTimestamp = 0L
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Exception stopping HEV SOCKS5 Tunnel", e)
        }
    }

    fun getStats(): TrafficStats {
        return try {
            val stats = TProxyService.TProxyGetStats()
            if (stats != null && stats.size >= 4) {
                val txPackets = stats[0]
                val txBytes = stats[1]
                val rxPackets = stats[2]
                val rxBytes = stats[3]

                val now = System.currentTimeMillis()
                val elapsedSec = if (lastTimestamp > 0) (now - lastTimestamp).coerceAtLeast(1) / 1000.0 else 1.0
                val speedIn = if (lastRxBytes > 0 && rxBytes >= lastRxBytes) ((rxBytes - lastRxBytes) / elapsedSec).toLong() else 0L
                val speedOut = if (lastTxBytes > 0 && txBytes >= lastTxBytes) ((txBytes - lastTxBytes) / elapsedSec).toLong() else 0L

                lastRxBytes = rxBytes
                lastTxBytes = txBytes
                lastTimestamp = now

                TrafficStats(
                    bytesIn = rxBytes,
                    bytesOut = txBytes,
                    speedInBytesPerSec = speedIn,
                    speedOutBytesPerSec = speedOut,
                    packetsIn = rxPackets,
                    packetsOut = txPackets
                )
            } else {
                TrafficStats()
            }
        } catch (e: Throwable) {
            TrafficStats()
        }
    }
}
