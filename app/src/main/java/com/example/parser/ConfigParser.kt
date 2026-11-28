package com.example.parser

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.example.model.ProtocolType
import com.example.model.SshTunnelMode
import com.example.model.VpnProfile
import com.example.security.CtpConfigCrypto
import com.example.security.CtpDecryptResult
import com.example.security.CtpExportOptions
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.UUID

sealed class ParseResult {
    data class Success(val profile: VpnProfile) : ParseResult()
    data class Failure(
        val reason: String,
        val details: String? = null,
        val requiresPassword: Boolean = false
    ) : ParseResult()
}

object ConfigParser {

    data class BatchParseResult(val profiles: List<VpnProfile>, val failures: List<String>)


    fun parse(
        rawInput: String,
        unlockPassword: String = "",
        context: Context? = null
    ): ParseResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return ParseResult.Failure("Empty configuration string")
        }

        val normalizedUri = if (!trimmed.startsWith("{") && !CtpConfigCrypto.isCtpContent(trimmed)) {
            trimmed.replace("\r", "").replace("\n", "").trim()
        } else {
            trimmed
        }

        return try {
            when {
                CtpConfigCrypto.isCtpContent(trimmed) -> parseCtp(trimmed, unlockPassword, context)
                normalizedUri.startsWith("vmess://", ignoreCase = true) -> parseVmess(normalizedUri)
                normalizedUri.startsWith("vless://", ignoreCase = true) -> parseVless(normalizedUri)
                normalizedUri.startsWith("trojan://", ignoreCase = true) -> parseTrojan(normalizedUri)
                normalizedUri.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(normalizedUri)
                normalizedUri.startsWith("socks5://", ignoreCase = true) || normalizedUri.startsWith("socks://", ignoreCase = true) -> parseSocksUri(normalizedUri)
                normalizedUri.startsWith("ssh://", ignoreCase = true) -> parseSshUri(normalizedUri)
                trimmed.startsWith("{") -> parseJson(trimmed)
                normalizedUri.contains("@") && !normalizedUri.contains("://") -> parseSshUri(normalizedUri)
                else -> ParseResult.Failure("Unsupported format. Expected .ctp file, vmess://, vless://, trojan://, ss://, ssh://, or Xray JSON.")
            }
        } catch (e: Exception) {
            ParseResult.Failure("Failed to parse configuration: ${e.message}", e.stackTraceToString())
        }
    }


    fun parseMultiple(
        rawInput: String,
        unlockPassword: String = "",
        context: Context? = null,
        maxProfiles: Int = 100
    ): BatchParseResult {
        val raw = rawInput.trim()
        if (raw.isEmpty()) return BatchParseResult(emptyList(), listOf("Empty configuration input"))
        if (CtpConfigCrypto.isCtpContent(raw) || raw.startsWith("{")) {
            return when (val result = parse(raw, unlockPassword, context)) {
                is ParseResult.Success -> BatchParseResult(listOf(result.profile), emptyList())
                is ParseResult.Failure -> BatchParseResult(emptyList(), listOf(result.reason))
            }
        }
        val pattern = Regex("(?im)^\\s*(vmess|vless|trojan|ss|socks5?|ssh)://")
        val decoded = if (!pattern.containsMatchIn(raw)) tryDecodeBase64Utf8(raw) else null
        val source = if (decoded != null && pattern.containsMatchIn(decoded)) decoded else raw
        val lines = source.lineSequence().map { it.trim().removePrefix("\uFEFF") }
            .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("//") }.toList()
        if (lines.size <= 1) {
            return when (val result = parse(lines.firstOrNull() ?: source, unlockPassword, context)) {
                is ParseResult.Success -> BatchParseResult(listOf(result.profile), emptyList())
                is ParseResult.Failure -> BatchParseResult(emptyList(), listOf(result.reason))
            }
        }
        val limit = maxProfiles.coerceIn(1, 500)
        val profiles = mutableListOf<VpnProfile>()
        val failures = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        lines.take(limit).forEachIndexed { index, line ->
            when (val result = parse(line, unlockPassword, context)) {
                is ParseResult.Success -> {
                    val profile = result.profile
                    val key = duplicateKey(profile)
                    if (seen.add(key)) profiles.add(profile)
                }
                is ParseResult.Failure -> failures.add("Line ${index + 1}: ${result.reason}")
            }
        }
        if (lines.size > limit) failures.add("Only the first $limit entries were checked (subscription limit)")
        return BatchParseResult(profiles, failures)
    }

    /**
     * Stable identity for imported connection profiles. Display names, generated IDs,
     * timestamps and ping history are intentionally excluded. Every connection-affecting
     * field is included so nodes that differ only by SNI, Host, REALITY keys, credentials,
     * SSH transport/proxy settings or DNS/routing options are not accidentally collapsed.
     */
    private fun duplicateKey(profile: VpnProfile): String {
        val fields = listOf(
            profile.protocol.name,
            profile.server.trim().trimEnd('.').lowercase(),
            profile.port.toString(),
            profile.password,
            profile.socksUsername,
            profile.security.lowercase(),
            profile.network.lowercase(),
            profile.kcpSeed,
            profile.path,
            profile.sni.lowercase(),
            profile.wsHost.lowercase(),
            profile.headerType.lowercase(),
            profile.grpcMode.lowercase(),
            profile.grpcAuthority.lowercase(),
            profile.publicKey,
            profile.shortId.lowercase(),
            profile.spiderX,
            profile.fingerprint.lowercase(),
            profile.alpn.lowercase(),
            profile.flow,
            profile.encryption.lowercase(),
            profile.sshUsername,
            profile.sshPayload,
            profile.sshMode.name,
            profile.proxyHost.trim().lowercase(),
            profile.proxyPort.toString(),
            profile.sshPrivateKey,
            profile.sshPassphrase,
            profile.sshProxyUser,
            profile.sshProxyPass,
            profile.sshSni.lowercase(),
            profile.sshWsPath,
            profile.sshCustomHeaders,
            profile.sshChainProxyHost.trim().lowercase(),
            profile.sshChainProxyPort.toString(),
            profile.sshChainProxyType.uppercase(),
            profile.sshLocalForwardPort.toString(),
            profile.sshRemoteForwardHost.trim().lowercase(),
            profile.sshRemoteForwardPort.toString(),
            profile.sshRemoteListenPort.toString(),
            profile.allowInsecureSsl.toString(),
            profile.dnsPrimary.trim().lowercase(),
            profile.dnsSecondary.trim().lowercase(),
            profile.blockIpv6.toString(),
            profile.bypassLan.toString(),
            profile.perAppProxy.toString(),
            profile.selectedApps.sorted().joinToString(",")
        )
        return buildString {
            fields.forEach { value ->
                append(value.length).append(':').append(value)
            }
        }
    }

    private fun parseCtp(
        rawCtp: String,
        unlockPassword: String,
        context: Context?
    ): ParseResult {
        return when (val decrypted = CtpConfigCrypto.decryptCtpToProfileJson(rawCtp, unlockPassword, context)) {
            is CtpDecryptResult.Success -> {
                val parsed = parseJson(decrypted.profileJson)
                if (parsed is ParseResult.Success) {
                    // Always assign a fresh local ID on import if needed or keep profile fields
                    ParseResult.Success(parsed.profile)
                } else {
                    parsed
                }
            }
            is CtpDecryptResult.PasswordRequired -> {
                ParseResult.Failure(
                    reason = decrypted.hint,
                    requiresPassword = true
                )
            }
            is CtpDecryptResult.Failure -> {
                ParseResult.Failure(reason = decrypted.reason)
            }
        }
    }

    private fun tryDecodeBase64Utf8(raw: String): String? {
        val cleaned = raw.replace("\\s+".toRegex(), "")
        if (cleaned.isEmpty()) return null
        return try {
            val bytes = Base64.decode(cleaned, Base64.DEFAULT or Base64.URL_SAFE)
            if (bytes.isEmpty()) return null
            String(bytes, StandardCharsets.UTF_8).trim()
        } catch (e: Exception) {
            null
        }
    }

    private fun parseVmess(uriStr: String): ParseResult {
        val afterScheme = uriStr.substring(8).trim()
        if (afterScheme.isEmpty()) {
            return ParseResult.Failure("Empty VMess URI payload")
        }

        val outerFragment = if (afterScheme.contains("#")) {
            decodeUrlComponent(afterScheme.substringAfter("#")).trim()
        } else ""
        val withoutOuterFragment = afterScheme.substringBefore("#").trim()

        // 1. Check if the entire body (before optional #fragment) decodes from Base64
        val fullDecoded = if (!withoutOuterFragment.contains("@")) {
            tryDecodeBase64Utf8(withoutOuterFragment)
        } else null

        if (fullDecoded != null && fullDecoded.startsWith("{")) {
            val json = JSONObject(fullDecoded)
            val server = json.optString("add").trim()
            val port = json.optString("port").trim().toIntOrNull() ?: json.optInt("port", 0)
            val id = json.optString("id").trim()

            if (server.isEmpty()) return ParseResult.Failure("VMess config is missing server address ('add')")
            if (port !in 1..65535) return ParseResult.Failure("VMess invalid port: $port")
            if (id.isEmpty()) return ParseResult.Failure("VMess config is missing UUID ('id')")

            val name = json.optString("ps", "").trim().ifEmpty {
                outerFragment.ifEmpty { "VMess-$server:$port" }
            }
            val rawNet = json.optString("net", "tcp").trim().lowercase().ifEmpty { "tcp" }
            val network = when (rawNet) {
                "websocket" -> "ws"
                "gun" -> "grpc"
                "splithttp" -> "xhttp"
                "http" -> "h2"
                else -> rawNet
            }
            val rawTls = json.optString("tls", "none").trim().lowercase()
            val security = if (rawTls == "tls" || rawTls == "1" || rawTls == "true") "tls" else if (rawTls == "reality") "reality" else "none"
            val wsHost = json.optString("host", "").trim()
            val sni = json.optString("sni", "").trim().ifBlank { if (security == "tls") server else "" }
            val path = json.optString("path", "").trim()
            val alpn = json.optString("alpn", "").trim()
            val fp = json.optString("fp", "chrome").trim().ifBlank { "chrome" }
            val headerType = json.optString("type", "none").trim().ifBlank { "none" }
            val kcpSeed = json.optString("seed", "").trim()
            val cipher = json.optString("scy", "auto").trim().ifBlank { "auto" }
            val allowInsecure = json.optBoolean("allowInsecure", false) ||
                json.optString("allowInsecure").equals("1") ||
                json.optString("allowInsecure").equals("true", ignoreCase = true)

            val profile = VpnProfile(
                id = UUID.randomUUID().toString(),
                name = name,
                protocol = ProtocolType.VMESS,
                server = server,
                port = port,
                password = id,
                security = security,
                network = network,
                kcpSeed = kcpSeed,
                path = path,
                sni = sni,
                wsHost = wsHost,
                headerType = headerType,
                fingerprint = fp,
                alpn = alpn,
                encryption = cipher,
                allowInsecureSsl = allowInsecure
            )
            return ParseResult.Success(profile)
        }

        // 2. Handle URI / Query-based VMess formats:
        //    a) Base64-encoded URI/query string (e.g. "v:vmess@host:443?type=ws&path=/vmess&security=tls&uuid=...")
        //    b) Shadowrocket mixed Base64 + query (e.g. "vmess://BASE64(auto:uuid@host:port)?obfs=websocket&path=/vmess&tls=1")
        //    c) Standard plain VMess URI (e.g. "vmess://uuid@host:443?type=ws&security=tls&path=/vmess#remark")
        val uriLikeCandidate = when {
            fullDecoded != null && (fullDecoded.contains("@") || fullDecoded.contains(":")) -> fullDecoded
            !withoutOuterFragment.substringBefore("?").contains("@") && withoutOuterFragment.contains("?") -> {
                val base64Part = withoutOuterFragment.substringBefore("?")
                val queryPart = withoutOuterFragment.substringAfter("?")
                val decodedPrefix = tryDecodeBase64Utf8(base64Part)
                if (decodedPrefix != null) "$decodedPrefix?$queryPart" else withoutOuterFragment
            }
            else -> withoutOuterFragment
        }

        return parseVmessUriLike(uriLikeCandidate, outerFragment)
    }

    private fun parseVmessUriLike(rawCandidate: String, outerFragment: String): ParseResult {
        val innerFragment = if (rawCandidate.contains("#")) {
            decodeUrlComponent(rawCandidate.substringAfter("#")).trim()
        } else ""
        val remark = innerFragment.ifEmpty { outerFragment }

        val withoutFragment = rawCandidate.substringBefore("#").trim().removePrefix("vmess://")
        val queryStr = if (withoutFragment.contains("?")) withoutFragment.substringAfter("?") else ""
        val queryParams = parseQueryParams(queryStr)
        val endpointPart = withoutFragment.substringBefore("?").trim()

        val userInfoPart = if (endpointPart.contains("@")) endpointPart.substringBeforeLast("@").trim() else ""
        val hostPortRaw = if (endpointPart.contains("@")) endpointPart.substringAfterLast("@").trim() else endpointPart

        // Clean any non-printable ASCII control bytes from host:port
        val cleanedHostPort = hostPortRaw.filter { it.code in 33..126 }.removeSuffix("/")
        if (cleanedHostPort.isEmpty()) {
            return ParseResult.Failure("Invalid VMess URI: missing server host and port")
        }

        val server: String
        val port: Int
        if (cleanedHostPort.startsWith("[")) {
            val closeBracket = cleanedHostPort.indexOf(']')
            if (closeBracket <= 1) return ParseResult.Failure("Invalid VMess IPv6 host format")
            server = cleanedHostPort.substring(1, closeBracket)
            val portStr = cleanedHostPort.substring(closeBracket + 1).removePrefix(":")
            port = portStr.toIntOrNull() ?: 443
        } else if (cleanedHostPort.contains(":")) {
            server = cleanedHostPort.substringBeforeLast(":").trim()
            port = cleanedHostPort.substringAfterLast(":").trim().toIntOrNull() ?: 0
        } else {
            server = cleanedHostPort
            port = queryParams["port"]?.toIntOrNull() ?: 443
        }

        if (server.isEmpty()) return ParseResult.Failure("VMess config is missing server address")
        if (port !in 1..65535) return ParseResult.Failure("VMess invalid port: $port")

        val queryUuid = (queryParams["uuid"] ?: queryParams["id"] ?: "").trim()
        val cleanedUserInfo = userInfoPart.filter { it.code in 33..126 }
        val userUuidCandidate = if (cleanedUserInfo.contains(":")) {
            val afterColon = cleanedUserInfo.substringAfter(":").trim()
            if (afterColon.equals("vmess", ignoreCase = true)) "" else afterColon
        } else {
            cleanedUserInfo
        }
        val uuid = queryUuid.ifEmpty { userUuidCandidate }
        if (uuid.isEmpty()) {
            return ParseResult.Failure("VMess config is missing UUID ('uuid' or user info)")
        }

        val userCipherCandidate = if (cleanedUserInfo.contains(":")) {
            val beforeColon = cleanedUserInfo.substringBefore(":").trim()
            if (beforeColon.equals("v", ignoreCase = true) || beforeColon.equals("vmess", ignoreCase = true)) "" else beforeColon
        } else ""
        val cipher = (queryParams["encryption"] ?: queryParams["scy"] ?: queryParams["cipher"] ?: userCipherCandidate.ifEmpty { "auto" }).trim().ifEmpty { "auto" }

        val rawNetwork = (queryParams["type"] ?: queryParams["net"] ?: queryParams["network"] ?: queryParams["obfs"] ?: "tcp").trim().lowercase()
        val network = when (rawNetwork) {
            "", "none", "tcp" -> "tcp"
            "ws", "websocket" -> "ws"
            "grpc", "gun" -> "grpc"
            "httpupgrade" -> "httpupgrade"
            "xhttp", "splithttp" -> "xhttp"
            "h2", "http" -> "h2"
            "kcp" -> "kcp"
            else -> rawNetwork
        }

        val rawSecurity = (queryParams["security"] ?: queryParams["tls"] ?: "").trim().lowercase()
        val security = when (rawSecurity) {
            "tls", "1", "true" -> "tls"
            "reality" -> "reality"
            else -> "none"
        }

        val wsHost = (queryParams["host"] ?: queryParams["obfsParam"] ?: "").trim()
        val sni = (queryParams["sni"] ?: queryParams["peer"] ?: "").trim().ifEmpty {
            if (security == "tls") server else ""
        }
        val path = (queryParams["path"] ?: queryParams["serviceName"] ?: "").trim()
        val alpn = (queryParams["alpn"] ?: "").trim()
        val fp = (queryParams["fp"] ?: "chrome").trim().ifEmpty { "chrome" }
        val headerType = (queryParams["headerType"] ?: "none").trim().ifEmpty { "none" }
        val kcpSeed = (queryParams["seed"] ?: queryParams["kcpSeed"] ?: "").trim()
        val allowInsecure = listOf("allowInsecure", "insecure", "allow_insecure").any { key ->
            val v = queryParams[key]?.trim()
            v == "1" || v.equals("true", ignoreCase = true)
        }
        val name = remark.ifEmpty {
            (queryParams["remarks"] ?: queryParams["ps"] ?: "").trim().ifEmpty { "VMess-$server:$port" }
        }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.VMESS,
            server = server,
            port = port,
            password = uuid,
            security = security,
            network = network,
            kcpSeed = kcpSeed,
            path = path,
            sni = sni,
            wsHost = wsHost,
            headerType = headerType,
            fingerprint = fp,
            alpn = alpn,
            encryption = cipher,
            allowInsecureSsl = allowInsecure
        )
        return ParseResult.Success(profile)
    }

    private val SUPPORTED_VLESS_NETWORKS = setOf(
        "tcp", "raw", "ws", "websocket", "grpc", "gun", "httpupgrade", "xhttp", "splithttp", "kcp"
    )
    private val SUPPORTED_VLESS_SECURITIES = setOf("none", "tls", "reality", "")

    private fun parseVless(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val rawUserInfo = uri.encodedUserInfo?.let { decodeUrlComponent(it) } ?: uri.userInfo
        val uuid = rawUserInfo?.trim() ?: ""
        if (uuid.isEmpty()) {
            return ParseResult.Failure("VLESS missing UUID in user info")
        }

        val rawHost = uri.host?.trim()?.removePrefix("[")?.removeSuffix("]") ?: ""
        if (rawHost.isEmpty()) {
            return ParseResult.Failure("VLESS missing server hostname")
        }

        val port = uri.port
        if (port !in 1..65535) {
            return ParseResult.Failure("VLESS invalid port: $port")
        }

        val rawQuery = uriStr.substringAfter("?", "").substringBefore("#")
        val queryParams = parseQueryParams(rawQuery.ifEmpty { uri. encodedQuery })
        val rawFragment = if (uriStr.contains("#")) uriStr.substringAfter("#") else null
        val name = rawFragment?.let { decodeUrlComponent(it) }?.ifBlank { null } ?: "VLESS-$rawHost:$port"

        val encryption = (queryParams["encryption"] ?: "none").trim().ifEmpty { "none" }
        if (!encryption.equals("none", ignoreCase = true)) {
            return ParseResult.Failure("Unsupported VLESS encryption '$encryption' (VLESS standard requires encryption=none)")
        }

        val rawSecurity = (queryParams["security"] ?: "none").trim().lowercase().ifEmpty { "none" }
        if (rawSecurity !in SUPPORTED_VLESS_SECURITIES) {
            return ParseResult.Failure("Unsupported VLESS security mode: '$rawSecurity'")
        }
        val security = if (rawSecurity.isEmpty()) "none" else rawSecurity

        val rawNetwork = (queryParams["type"] ?: queryParams["network"] ?: "tcp").trim().lowercase().ifEmpty { "tcp" }
        if (rawNetwork !in SUPPORTED_VLESS_NETWORKS) {
            return ParseResult.Failure("Unsupported VLESS transport type: '$rawNetwork'")
        }
        val network = when (rawNetwork) {
            "raw" -> "tcp"
            "websocket" -> "ws"
            "gun" -> "grpc"
            "splithttp" -> "xhttp"
            else -> rawNetwork
        }

        val wsHost = (queryParams["host"] ?: "").trim()
        val sni = (queryParams["sni"] ?: queryParams["peer"] ?: "").trim().ifEmpty {
            if (security == "tls" || security == "reality") rawHost else ""
        }
        val headerType = (queryParams["headerType"] ?: "none").trim().ifEmpty { "none" }
        val grpcMode = (queryParams["mode"] ?: "gun").trim().ifEmpty { "gun" }
        val grpcAuthority = (queryParams["authority"] ?: "").trim()

        val rawPath = when (network) {
            "grpc" -> (queryParams["serviceName"] ?: queryParams["path"] ?: "").trim()
            else -> (queryParams["path"] ?: queryParams["serviceName"] ?: "").trim()
        }
        val path = if (rawPath.contains("%2F", ignoreCase = true) || rawPath.contains("%3F", ignoreCase = true)) {
            decodeUrlComponent(rawPath)
        } else {
            rawPath
        }

        val pbk = (queryParams["pbk"] ?: "").trim()
        val sid = (queryParams["sid"] ?: "").trim()
        val spx = (queryParams["spx"] ?: "").trim()
        val fp = (queryParams["fp"] ?: "chrome").trim().ifEmpty { "chrome" }
        val alpn = (queryParams["alpn"] ?: "").trim()
        val flow = (queryParams["flow"] ?: "").trim()

        if (security == "reality" && pbk.isEmpty()) {
            return ParseResult.Failure("VLESS REALITY configuration is missing required public key ('pbk')")
        }

        val allowInsecure = listOf("allowInsecure", "insecure", "allow_insecure").any { key ->
            val v = queryParams[key]?.trim()
            v == "1" || v.equals("true", ignoreCase = true)
        }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.VLESS,
            server = rawHost,
            port = port,
            password = uuid,
            security = security,
            network = network,
            path = path,
            sni = sni,
            wsHost = wsHost,
            headerType = headerType,
            grpcMode = grpcMode,
            grpcAuthority = grpcAuthority,
            publicKey = pbk,
            shortId = sid,
            spiderX = spx,
            fingerprint = fp,
            alpn = alpn,
            flow = flow,
            encryption = "none",
            allowInsecureSsl = allowInsecure
        )
        return ParseResult.Success(profile)
    }

    private fun parseTrojan(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val password = uri.encodedUserInfo?.let { decodeUrlComponent(it) } ?: uri.userInfo
            ?: return ParseResult.Failure("Trojan missing password")
        val host = uri.host?.trim()?.removePrefix("[")?.removeSuffix("]")
            ?: return ParseResult.Failure("Trojan missing host")
        val port = uri.port
        if (port !in 1..65535) return ParseResult.Failure("Trojan invalid port: $port")

        val rawQuery = uriStr.substringAfter("?", "").substringBefore("#")
        val queryParams = parseQueryParams(rawQuery.ifEmpty { uri.encodedQuery })
        val name = uri.fragment?.let { decodeUrlComponent(it) } ?: "Trojan-$host:$port"
        val wsHost = (queryParams["host"] ?: "").trim()
        val sni = (queryParams["sni"] ?: queryParams["peer"] ?: "").trim().ifEmpty { host }
        val network = (queryParams["type"] ?: "tcp").trim().lowercase().ifEmpty { "tcp" }
        val path = (queryParams["path"] ?: queryParams["serviceName"] ?: "").trim()
        val security = (queryParams["security"] ?: "tls").trim().lowercase().ifEmpty { "tls" }
        val alpn = (queryParams["alpn"] ?: "").trim()
        val fp = (queryParams["fp"] ?: "chrome").trim().ifEmpty { "chrome" }
        val allowInsecure = listOf("allowInsecure", "insecure", "allow_insecure").any { key ->
            val v = queryParams[key]?.trim()
            v == "1" || v.equals("true", ignoreCase = true)
        }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.TROJAN,
            server = host,
            port = port,
            password = password,
            security = security,
            network = network,
            path = path,
            sni = sni,
            wsHost = wsHost,
            fingerprint = fp,
            alpn = alpn,
            allowInsecureSsl = allowInsecure
        )
        return ParseResult.Success(profile)
    }

    private fun parseShadowsocks(uriStr: String): ParseResult {
        // SIP002 and legacy Shadowsocks URIs, including bracketed IPv6 endpoints.
        val body = uriStr.substringAfter("ss://", "")
        val mainPart = body.substringBefore("#").substringBefore("?")
        val name = decodeUrlComponent(body.substringAfter("#", "Shadowsocks").substringBefore("?"))
        val at = mainPart.lastIndexOf('@')
        val userInfo: String
        val endpoint: String
        if (at >= 0) {
            val rawUser = mainPart.substring(0, at)
            userInfo = try { String(Base64.decode(rawUser, Base64.DEFAULT or Base64.URL_SAFE), StandardCharsets.UTF_8) }
                catch (_: Exception) { decodeUrlComponent(rawUser) }
            endpoint = mainPart.substring(at + 1)
        } else {
            val decoded = try { String(Base64.decode(mainPart, Base64.DEFAULT or Base64.URL_SAFE), StandardCharsets.UTF_8) }
                catch (e: Exception) { return ParseResult.Failure("Invalid Shadowsocks Base64 string", e.message) }
            val split = decoded.lastIndexOf('@')
            if (split <= 0) return ParseResult.Failure("Malformed Shadowsocks URI: missing method/password or endpoint")
            userInfo = decoded.substring(0, split)
            endpoint = decoded.substring(split + 1)
        }
        if (userInfo.isBlank() || !userInfo.contains(':')) return ParseResult.Failure("Shadowsocks URI is missing method:password")
        val (host, port) = parseShadowsocksEndpoint(endpoint) ?: return ParseResult.Failure("Invalid Shadowsocks host or port")
        return ParseResult.Success(VpnProfile(id = UUID.randomUUID().toString(), name = name.ifBlank { "Shadowsocks-$host:$port" }, protocol = ProtocolType.SHADOWSOCKS, server = host, port = port, password = userInfo))
    }

    private fun parseShadowsocksEndpoint(raw: String): Pair<String, Int>? {
        val value = raw.trim()
        if (value.isEmpty()) return null
        val host: String
        val port: Int
        if (value.startsWith("[")) {
            val close = value.indexOf(']')
            if (close <= 1) return null
            host = value.substring(1, close)
            val suffix = value.substring(close + 1)
            port = when {
                suffix.isEmpty() -> 8388
                suffix.startsWith(":") -> suffix.substring(1).toIntOrNull() ?: return null
                else -> return null
            }
        } else if (value.count { it == ':' } == 1) {
            host = value.substringBeforeLast(':').trim()
            port = value.substringAfterLast(':').toIntOrNull() ?: return null
        } else {
            host = value
            port = 8388
        }
        if (host.isBlank() || port !in 1..65535) return null
        return host to port
    }

    private fun parseSocksUri(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val host = uri.host?.trim()?.removePrefix("[")?.removeSuffix("]") ?: ""
        if (host.isBlank()) return ParseResult.Failure("SOCKS5 URI is missing server host")
        val port = uri.port
        if (port !in 1..65535) return ParseResult.Failure("SOCKS5 URI has invalid port: $port")
        val userInfo = uri.encodedUserInfo?.let { decodeUrlComponent(it) } ?: uri.userInfo.orEmpty()
        val username = userInfo.substringBefore(":", "").trim()
        val password = if (userInfo.contains(":")) userInfo.substringAfter(":") else ""
        return ParseResult.Success(VpnProfile(id = UUID.randomUUID().toString(), name = uri.fragment?.let { decodeUrlComponent(it) }?.ifBlank { null } ?: "SOCKS5-$host:$port", protocol = ProtocolType.SOCKS5, server = host, port = port, socksUsername = username, password = password))
    }

    private fun parseSshUri(uriStr: String): ParseResult {
        val targetInfo = SshTargetParser.parse(uriStr)
        val host = targetInfo?.host ?: ""
        if (host.isEmpty()) return ParseResult.Failure("SSH configuration missing host")
        val port = targetInfo?.port ?: 22
        val username = targetInfo?.username?.ifBlank { "root" } ?: "root"
        val password = targetInfo?.password ?: ""

        val queryParams = if (uriStr.contains("?")) {
            val queryStr = uriStr.substringAfter("?").substringBefore("#")
            parseQueryParams(queryStr)
        } else emptyMap()

        val name = targetInfo?.name ?: (if (uriStr.contains("#")) {
            decodeUrlComponent(uriStr.substringAfter("#"))
        } else "SSH-$host:$port")
        val payload = queryParams["payload"] ?: ""
        val proxyHost = queryParams["proxy_host"] ?: ""
        val proxyPort = queryParams["proxy_port"]?.toIntOrNull() ?: 0
        val modeStr = queryParams["mode"] ?: "DIRECT"
        val sshMode = try {
            SshTunnelMode.valueOf(modeStr.uppercase())
        } catch (e: Exception) {
            SshTunnelMode.DIRECT
        }
        val sni = queryParams["sni"] ?: ""
        val wsPath = queryParams["ws_path"] ?: "/ssh"
        val proxyUser = queryParams["proxy_user"] ?: ""
        val proxyPass = queryParams["proxy_pass"] ?: ""
        val chainHost = queryParams["chain_host"] ?: ""
        val chainPort = queryParams["chain_port"]?.toIntOrNull() ?: 0
        val chainType = queryParams["chain_type"] ?: "SOCKS5"
        val localFwdPort = queryParams["local_fwd_port"]?.toIntOrNull() ?: 10880
        val remoteFwdHost = queryParams["remote_fwd_host"] ?: "127.0.0.1"
        val remoteFwdPort = queryParams["remote_fwd_port"]?.toIntOrNull() ?: 80
        val remoteListenPort = queryParams["remote_listen_port"]?.toIntOrNull() ?: 8080

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.SSH,
            server = host,
            port = port,
            sshUsername = username,
            password = password,
            sshPayload = payload,
            proxyHost = proxyHost,
            proxyPort = proxyPort,
            sshMode = sshMode,
            sshSni = sni,
            sshWsPath = wsPath,
            sshProxyUser = proxyUser,
            sshProxyPass = proxyPass,
            sshChainProxyHost = chainHost,
            sshChainProxyPort = chainPort,
            sshChainProxyType = chainType,
            sshLocalForwardPort = localFwdPort,
            sshRemoteForwardHost = remoteFwdHost,
            sshRemoteForwardPort = remoteFwdPort,
            sshRemoteListenPort = remoteListenPort
        )
        return ParseResult.Success(profile)
    }

    private fun parseJson(jsonStr: String): ParseResult {
        val root = JSONObject(jsonStr)
        // Check if Custom Tunnel Pro profile export
        if (root.has("protocol") && root.has("server")) {
            val proto = try {
                ProtocolType.valueOf(root.getString("protocol"))
            } catch (e: Exception) {
                return ParseResult.Failure("Unsupported Custom Tunnel Pro protocol: ${root.optString("protocol")}")
            }
            return ParseResult.Success(
                VpnProfile(
                    id = root.optString("id", UUID.randomUUID().toString()),
                    name = root.optString("name", "Imported Profile"),
                    protocol = proto,
                    server = root.getString("server"),
                    port = root.getInt("port"),
                    password = root.optString("password", ""),
                    socksUsername = root.optString("socksUsername", ""),
                    security = root.optString("security", "none"),
                    network = root.optString("network", "tcp"),
                    kcpSeed = root.optString("kcpSeed", ""),
                    path = root.optString("path", ""),
                    sni = root.optString("sni", ""),
                    wsHost = root.optString("wsHost", ""),
                    headerType = root.optString("headerType", "none"),
                    grpcMode = root.optString("grpcMode", "gun"),
                    grpcAuthority = root.optString("grpcAuthority", ""),
                    publicKey = root.optString("publicKey", ""),
                    shortId = root.optString("shortId", ""),
                    spiderX = root.optString("spiderX", ""),
                    fingerprint = root.optString("fingerprint", "chrome"),
                    alpn = root.optString("alpn", ""),
                    flow = root.optString("flow", ""),
                    encryption = root.optString("encryption", "none"),
                    sshUsername = root.optString("sshUsername", ""),
                    sshPayload = root.optString("sshPayload", ""),
                    proxyHost = root.optString("proxyHost", ""),
                    proxyPort = root.optInt("proxyPort", 0),
                    sshMode = try {
                        SshTunnelMode.valueOf(root.optString("sshMode", SshTunnelMode.DIRECT.name))
                    } catch (e: Exception) {
                        SshTunnelMode.DIRECT
                    },
                    sshPrivateKey = root.optString("sshPrivateKey", ""),
                    sshPassphrase = root.optString("sshPassphrase", ""),
                    sshProxyUser = root.optString("sshProxyUser", ""),
                    sshProxyPass = root.optString("sshProxyPass", ""),
                    sshSni = root.optString("sshSni", ""),
                    sshWsPath = root.optString("sshWsPath", "/ssh"),
                    sshCustomHeaders = root.optString("sshCustomHeaders", ""),
                    sshChainProxyHost = root.optString("sshChainProxyHost", ""),
                    sshChainProxyPort = root.optInt("sshChainProxyPort", 0),
                    sshChainProxyType = root.optString("sshChainProxyType", "SOCKS5"),
                    sshLocalForwardPort = root.optInt("sshLocalForwardPort", 10880),
                    sshRemoteForwardHost = root.optString("sshRemoteForwardHost", "127.0.0.1"),
                    sshRemoteForwardPort = root.optInt("sshRemoteForwardPort", 80),
                    sshRemoteListenPort = root.optInt("sshRemoteListenPort", 8080),
                    allowInsecureSsl = root.optBoolean("allowInsecureSsl", false),
                    dnsPrimary = root.optString("dnsPrimary", ""),
                    dnsSecondary = root.optString("dnsSecondary", ""),
                    blockIpv6 = root.optBoolean("blockIpv6", true),
                    bypassLan = root.optBoolean("bypassLan", true),
                    isLocked = root.optBoolean("isLocked", false),
                    lockPasswordHash = root.optString("lockPasswordHash", ""),
                    expiresAtMillis = root.optLong("expiresAtMillis", 0L),
                    lockedHwid = root.optString("lockedHwid", ""),
                    blockRoot = root.optBoolean("blockRoot", false),
                    creatorMessage = root.optString("creatorMessage", "")
                )
            )
        }

        // sing-box JSON uses "type"/"server" fields rather than Xray's
        // "protocol"/"settings" schema. Convert supported outbound types into
        // the app's canonical profile model without silently changing credentials.
        val singBoxResult = parseSingBoxJson(root)
        if (singBoxResult != null) return singBoxResult

        // Standard Xray/V2Ray inbound/outbound JSON
        val outbounds = root.optJSONArray("outbounds")
        if (outbounds != null && outbounds.length() > 0) {
            val supportedProtocols = mapOf("VMESS" to ProtocolType.VMESS, "VLESS" to ProtocolType.VLESS, "TROJAN" to ProtocolType.TROJAN, "SHADOWSOCKS" to ProtocolType.SHADOWSOCKS, "SOCKS" to ProtocolType.SOCKS5)
            var selectedOutbound: JSONObject? = null
            var selectedProtocol: ProtocolType? = null
            for (index in 0 until outbounds.length()) {
                val candidate = outbounds.optJSONObject(index) ?: continue
                val candidateProtocol = supportedProtocols[candidate.optString("protocol", "").uppercase()] ?: continue
                val candidateSettings = candidate.optJSONObject("settings") ?: continue
                val hasEndpoint = candidateSettings.optJSONArray("vnext")?.length()?.let { it > 0 } == true || candidateSettings.optJSONArray("servers")?.length()?.let { it > 0 } == true || candidateSettings.has("address")
                if (hasEndpoint) { selectedOutbound = candidate; selectedProtocol = candidateProtocol; break }
            }
            val firstOutbound = selectedOutbound ?: return ParseResult.Failure("Xray JSON has no supported proxy outbound (VMess, VLESS, Trojan, Shadowsocks, or SOCKS)")
            val proto = selectedProtocol ?: return ParseResult.Failure("Unsupported Xray outbound protocol")
            val settings = firstOutbound.optJSONObject("settings")
            var server = ""
            var port = 443
            var id = ""
            var flow = ""
            var encryption = "none"
            var socksUsername = ""
            if (settings != null) {
                val vnext = settings.optJSONArray("vnext")
                if (vnext != null && vnext.length() > 0) {
                    val target = vnext.getJSONObject(0)
                    server = target.optString("address", "")
                    port = target.optInt("port", 443)
                    val users = target.optJSONArray("users")
                    if (users != null && users.length() > 0) {
                        val user = users.getJSONObject(0)
                        id = user.optString("id", "")
                        flow = user.optString("flow", "")
                        encryption = user.optString("encryption", "none")
                    }
                } else if (settings.has("address")) {
                    // Xray v26 flat VLESS outbound settings
                    server = settings.optString("address", "")
                    port = settings.optInt("port", 443)
                    id = settings.optString("id", "")
                    flow = settings.optString("flow", "")
                    encryption = settings.optString("encryption", "none")
                } else if (settings.optJSONArray("servers") != null && settings.getJSONArray("servers").length() > 0) {
                    val serverEntry = settings.getJSONArray("servers").getJSONObject(0)
                    server = serverEntry.optString("address", "")
                    port = serverEntry.optInt("port", 1080)
                    val users = serverEntry.optJSONArray("users")
                    if (users != null && users.length() > 0) {
                        val user = users.getJSONObject(0)
                        socksUsername = user.optString("user", "")
                        id = user.optString("pass", "")
                    } else {
                        val rawPassword = serverEntry.optString("password", "")
                        val method = serverEntry.optString("method", "")
                        id = if (proto == ProtocolType.SHADOWSOCKS && method.isNotBlank()) "$method:$rawPassword" else rawPassword
                    }
                }
            }
            if (server.isEmpty()) return ParseResult.Failure("Cannot parse outbound server address from Xray JSON")

            val streamSettings = firstOutbound.optJSONObject("streamSettings")
            val rawNetwork = streamSettings?.optString("network", "tcp")?.lowercase() ?: "tcp"
            val network = when (rawNetwork) { "raw" -> "tcp"; "websocket" -> "ws"; "gun" -> "grpc"; "splithttp" -> "xhttp"; else -> rawNetwork }
            val security = streamSettings?.optString("security", "none")?.lowercase() ?: "none"
            val kcpSeed = streamSettings?.optJSONObject("kcpSettings")?.optString("seed", "") ?: ""

            var sni = ""
            var fingerprint = "chrome"
            var alpn = ""
            var allowInsecure = false
            var publicKey = ""
            var shortId = ""
            var spiderX = ""
            var path = ""
            var wsHost = ""
            var headerType = "none"
            var grpcMode = "gun"
            var grpcAuthority = ""

            if (security == "tls") {
                val tls = streamSettings?.optJSONObject("tlsSettings")
                if (tls != null) {
                    sni = tls.optString("serverName", "")
                    fingerprint = tls.optString("fingerprint", "chrome").ifBlank { "chrome" }
                    allowInsecure = tls.optBoolean("allowInsecure", false)
                    val alpnArr = tls.optJSONArray("alpn")
                    if (alpnArr != null && alpnArr.length() > 0) {
                        val list = mutableListOf<String>()
                        for (i in 0 until alpnArr.length()) {
                            list.add(alpnArr.getString(i))
                        }
                        alpn = list.joinToString(",")
                    }
                }
            } else if (security == "reality") {
                val reality = streamSettings?.optJSONObject("realitySettings")
                if (reality != null) {
                    sni = reality.optString("serverName", "")
                    fingerprint = reality.optString("fingerprint", "chrome").ifBlank { "chrome" }
                    publicKey = reality.optString("publicKey", "")
                    shortId = reality.optString("shortId", "")
                    spiderX = reality.optString("spiderX", "")
                }
            }

            when (network) {
                "ws" -> {
                    val ws = streamSettings?.optJSONObject("wsSettings")
                    if (ws != null) {
                        path = ws.optString("path", "")
                        wsHost = ws.optString("host", "").ifBlank { ws.optJSONObject("headers")?.optString("Host", "") ?: "" }
                    }
                }
                "grpc" -> {
                    val grpc = streamSettings?.optJSONObject("grpcSettings")
                    if (grpc != null) {
                        path = grpc.optString("serviceName", "")
                        grpcMode = if (grpc.optBoolean("multiMode", false)) "multi" else "gun"
                        grpcAuthority = grpc.optString("authority", "")
                    }
                }
                "httpupgrade" -> {
                    val upgrade = streamSettings?.optJSONObject("httpupgradeSettings")
                    if (upgrade != null) { path = upgrade.optString("path", ""); wsHost = upgrade.optString("host", "") }
                }
                "xhttp" -> {
                    val xhttp = streamSettings?.optJSONObject("xhttpSettings")
                    if (xhttp != null) { path = xhttp.optString("path", ""); wsHost = xhttp.optString("host", "") }
                }
                "kcp" -> {
                    headerType = streamSettings?.optJSONObject("kcpSettings")?.optJSONObject("header")?.optString("type", "none") ?: "none"
                }
                "tcp" -> {
                    val tcpHeader = streamSettings?.optJSONObject("tcpSettings")?.optJSONObject("header")
                    headerType = tcpHeader?.optString("type", "none") ?: "none"
                    if (headerType == "http") {
                        val request = tcpHeader?.optJSONObject("request")
                        val pathValue = request?.opt("path")
                        path = when (pathValue) { is JSONArray -> pathValue.optString(0, ""); is String -> pathValue; else -> "" }
                        val hostValue = request?.optJSONObject("headers")?.opt("Host")
                        wsHost = when (hostValue) { is JSONArray -> hostValue.optString(0, ""); is String -> hostValue; else -> "" }
                    }
                }
            }

            return ParseResult.Success(
                VpnProfile(
                    id = UUID.randomUUID().toString(),
                    name = root.optString("remarks", "Xray-$server:$port"),
                    protocol = proto,
                    server = server,
                    port = port,
                    password = id,
                    socksUsername = socksUsername,
                    security = security,
                    network = network,
                    kcpSeed = kcpSeed,
                    path = path,
                    headerType = headerType,
                    sni = sni.ifBlank { if (security == "tls" || security == "reality") server else "" },
                    wsHost = wsHost,
                    grpcMode = grpcMode,
                    grpcAuthority = grpcAuthority,
                    publicKey = publicKey,
                    shortId = shortId,
                    spiderX = spiderX,
                    fingerprint = fingerprint,
                    alpn = alpn,
                    flow = flow,
                    encryption = encryption,
                    allowInsecureSsl = allowInsecure
                )
            )
        }

        return ParseResult.Failure("JSON does not contain recognized Xray outbounds or Custom Tunnel Pro profile schema")
    }


    private fun parseSingBoxJson(root: JSONObject): ParseResult? {
        val outbounds = root.optJSONArray("outbounds") ?: return null
        if (outbounds.length() == 0) return null

        val supported = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "socks5")
        var outbound: JSONObject? = null
        var type = ""
        for (i in 0 until outbounds.length()) {
            val candidate = outbounds.optJSONObject(i) ?: continue
            val candidateType = candidate.optString("type", "").trim().lowercase()
            if (candidateType in supported) {
                outbound = candidate
                type = candidateType
                break
            }
        }
        val item = outbound ?: return null

        val server = item.optString("server", "").trim()
        val port = item.optInt("server_port", item.optInt("port", 0))
        if (server.isBlank() || port !in 1..65535) {
            return ParseResult.Failure("Invalid sing-box outbound: server or server_port is missing")
        }

        val tls = item.optJSONObject("tls")
        val tlsEnabled = tls?.optBoolean("enabled", false) == true
        val reality = tls?.optJSONObject("reality")
        val security = when {
            reality?.optBoolean("enabled", false) == true -> "reality"
            tlsEnabled -> "tls"
            else -> "none"
        }
        val utls = tls?.optJSONObject("utls")
        val fingerprint = utls?.optString("fingerprint", "chrome")?.ifBlank { "chrome" } ?: "chrome"
        val sni = tls?.optString("server_name", "")?.trim().orEmpty()
        val allowInsecure = tls?.optBoolean("insecure", false) == true
        val transport = item.optJSONObject("transport")
        val rawTransport = transport?.optString("type", "tcp")?.trim()?.lowercase() ?: "tcp"
        val network = when (rawTransport) {
            "ws", "websocket" -> "ws"
            "grpc" -> "grpc"
            "httpupgrade" -> "httpupgrade"
            "http" -> "h2"
            "tcp", "http2", "h2" -> if (rawTransport == "http2" || rawTransport == "h2") "h2" else "tcp"
            else -> rawTransport
        }
        val supportedTransports = setOf("tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp")
        if (network !in supportedTransports) {
            return ParseResult.Failure("Unsupported sing-box transport '$rawTransport'")
        }
        val headers = transport?.optJSONObject("headers")
        val wsHost = (headers?.optString("Host", "")?.trim().orEmpty()
            .ifBlank { headers?.optString("host", "")?.trim().orEmpty() })
            .ifBlank { transport?.optString("host", "")?.trim().orEmpty() }
        val path = when (network) {
            "grpc" -> transport?.optString("service_name", "")?.trim().orEmpty()
            else -> transport?.optString("path", "")?.trim().orEmpty()
        }
        val kcpSeed = transport?.optString("seed", "")?.trim().orEmpty()
        val headerType = transport?.optJSONObject("header")?.optString("type", "none")?.trim()?.ifBlank { "none" } ?: "none"
        val grpcAuthority = if (network == "grpc") {
            transport?.optString("authority", "")?.trim().orEmpty()
        } else ""
        val name = item.optString("tag", "").trim().ifBlank {
            root.optString("remarks", "").trim().ifBlank { "sing-box-" + server + ":" + port }
        }

        val protocol = when (type) {
            "vless" -> ProtocolType.VLESS
            "vmess" -> ProtocolType.VMESS
            "trojan" -> ProtocolType.TROJAN
            "shadowsocks" -> ProtocolType.SHADOWSOCKS
            "socks", "socks5" -> ProtocolType.SOCKS5
            else -> return null
        }
        val credential = when (protocol) {
            ProtocolType.VLESS, ProtocolType.VMESS -> item.optString("uuid", "").trim()
            ProtocolType.TROJAN -> item.optString("password", "").trim()
            ProtocolType.SHADOWSOCKS -> {
                val method = item.optString("method", "").trim()
                val password = item.optString("password", "").trim()
                if (method.isNotBlank() && password.isNotBlank()) "$method:$password" else password
            }
            ProtocolType.SOCKS5 -> item.optString("password", "").trim()
            else -> ""
        }
        val socksUsername = if (protocol == ProtocolType.SOCKS5) item.optString("username", "").trim() else ""
        if (protocol != ProtocolType.SOCKS5 && credential.isBlank()) {
            return ParseResult.Failure("sing-box " + type + " outbound is missing its required credential")
        }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = protocol,
            server = server,
            port = port,
            password = credential,
            socksUsername = socksUsername,
            security = security,
            network = network,
            kcpSeed = kcpSeed,
            path = path,
            headerType = headerType,
            sni = sni,
            wsHost = wsHost,
            grpcAuthority = grpcAuthority,
            fingerprint = fingerprint,
            alpn = tls?.optJSONArray("alpn")?.let { arr ->
                (0 until arr.length()).map { arr.optString(it) }.filter { it.isNotBlank() }.joinToString(",")
            }.orEmpty(),
            flow = item.optString("flow", ""),
            encryption = if (protocol == ProtocolType.VMESS) item.optString("security", "auto") else "none",
            publicKey = reality?.optString("public_key", "")?.trim().orEmpty(),
            shortId = reality?.optString("short_id", "")?.trim().orEmpty(),
            spiderX = reality?.optString("spider_x", "")?.trim().orEmpty(),
            allowInsecureSsl = allowInsecure
        )
        if (profile.security == "reality" && profile.publicKey.isBlank()) {
            return ParseResult.Failure("sing-box REALITY outbound is missing tls.reality.public_key")
        }
        return ParseResult.Success(profile)
    }

    private fun decodeUrlComponent(encoded: String): String {
        return try {
            // Preserve '+' as literal plus in query/fragment values unless %2B
            URLDecoder.decode(encoded.replace("+", "%2B"), "UTF-8")
        } catch (e: Exception) {
            encoded
        }
    }

    private fun parseQueryParams(query: String?): Map<String, String> {
        if (query.isNullOrEmpty()) return emptyMap()
        val map = mutableMapOf<String, String>()
        val pairs = query.split("&")
        for (pair in pairs) {
            val idx = pair.indexOf("=")
            if (idx > 0) {
                val key = decodeUrlComponent(pair.substring(0, idx)).trim()
                val value = decodeUrlComponent(pair.substring(idx + 1))
                map[key] = value
            }
        }
        return map
    }

    fun exportProfileToUri(profile: VpnProfile): String {
        return when (profile.protocol) {
            ProtocolType.VLESS -> {
                val params = mutableListOf<String>()
                params.add("encryption=${Uri.encode(profile.encryption.ifBlank { "none" })}")
                params.add("security=${Uri.encode(profile.security.ifBlank { "none" })}")
                params.add("type=${Uri.encode(profile.network.ifBlank { "tcp" })}")
                if (profile.sni.isNotBlank()) params.add("sni=${Uri.encode(profile.sni)}")
                if (profile.wsHost.isNotBlank()) params.add("host=${Uri.encode(profile.wsHost)}")
                if (profile.network.equals("grpc", ignoreCase = true)) {
                    if (profile.path.isNotBlank()) params.add("serviceName=${Uri.encode(profile.path)}")
                    if (profile.grpcMode.isNotBlank()) params.add("mode=${Uri.encode(profile.grpcMode)}")
                    if (profile.grpcAuthority.isNotBlank()) params.add("authority=${Uri.encode(profile.grpcAuthority)}")
                } else if (profile.path.isNotBlank()) {
                    params.add("path=${Uri.encode(profile.path)}")
                }
                if (profile.headerType.isNotBlank() && profile.headerType != "none") {
                    params.add("headerType=${Uri.encode(profile.headerType)}")
                }
                if (profile.flow.isNotBlank()) params.add("flow=${Uri.encode(profile.flow)}")
                if (profile.fingerprint.isNotBlank()) params.add("fp=${Uri.encode(profile.fingerprint)}")
                if (profile.alpn.isNotBlank()) params.add("alpn=${Uri.encode(profile.alpn)}")
                if (profile.publicKey.isNotBlank()) params.add("pbk=${Uri.encode(profile.publicKey)}")
                if (profile.shortId.isNotBlank()) params.add("sid=${Uri.encode(profile.shortId)}")
                if (profile.spiderX.isNotBlank()) params.add("spx=${Uri.encode(profile.spiderX)}")
                if (profile.allowInsecureSsl) params.add("allowInsecure=1")
                "vless://${profile.password}@${profile.server}:${profile.port}?${params.joinToString("&")}#${Uri.encode(profile.name)}"
            }
            ProtocolType.TROJAN -> {
                val params = mutableListOf("security=${Uri.encode(profile.security.ifBlank { "tls" })}", "type=${Uri.encode(profile.network.ifBlank { "tcp" })}")
                if (profile.sni.isNotBlank()) params.add("sni=${Uri.encode(profile.sni)}")
                if (profile.wsHost.isNotBlank()) params.add("host=${Uri.encode(profile.wsHost)}")
                if (profile.path.isNotBlank()) params.add("path=${Uri.encode(profile.path)}")
                if (profile.alpn.isNotBlank()) params.add("alpn=${Uri.encode(profile.alpn)}")
                if (profile.fingerprint.isNotBlank()) params.add("fp=${Uri.encode(profile.fingerprint)}")
                if (profile.allowInsecureSsl) params.add("allowInsecure=1")
                "trojan://${Uri.encode(profile.password)}@${profile.server}:${profile.port}?${params.joinToString("&")}#${Uri.encode(profile.name)}"
            }
            ProtocolType.VMESS -> {
                val json = JSONObject().apply {
                    put("v", "2")
                    put("ps", profile.name)
                    put("add", profile.server)
                    put("port", profile.port)
                    put("id", profile.password)
                    put("net", profile.network)
                    put("tls", profile.security)
                    put("sni", profile.sni)
                    put("host", profile.wsHost)
                    put("path", profile.path)
                    put("alpn", profile.alpn)
                    put("fp", profile.fingerprint)
                    put("type", profile.headerType)
                    put("scy", profile.encryption)
                    put("seed", profile.kcpSeed)
                }
                "vmess://${Base64.encodeToString(json.toString().toByteArray(), Base64.NO_WRAP)}"
            }
            ProtocolType.SSH -> {
                "ssh://${profile.sshUsername}:${profile.password}@${profile.server}:${profile.port}?mode=${profile.sshMode.name}&proxy_host=${profile.proxyHost}&proxy_port=${profile.proxyPort}&sni=${profile.sshSni}&ws_path=${profile.sshWsPath}#${Uri.encode(profile.name)}"
            }
            else -> {
                exportProfileToJson(profile)
            }
        }
    }

    fun exportProfileToJson(profile: VpnProfile): String {
        val obj = JSONObject().apply {
            put("id", profile.id)
            put("name", profile.name)
            put("protocol", profile.protocol.name)
            put("server", profile.server)
            put("port", profile.port)
            put("password", profile.password)
            put("socksUsername", profile.socksUsername)
            put("security", profile.security)
            put("network", profile.network)
            put("kcpSeed", profile.kcpSeed)
            put("path", profile.path)
            put("sni", profile.sni)
            put("wsHost", profile.wsHost)
            put("headerType", profile.headerType)
            put("grpcMode", profile.grpcMode)
            put("grpcAuthority", profile.grpcAuthority)
            put("publicKey", profile.publicKey)
            put("shortId", profile.shortId)
            put("spiderX", profile.spiderX)
            put("fingerprint", profile.fingerprint)
            put("alpn", profile.alpn)
            put("flow", profile.flow)
            put("encryption", profile.encryption)
            put("sshUsername", profile.sshUsername)
            put("sshPayload", profile.sshPayload)
            put("proxyHost", profile.proxyHost)
            put("proxyPort", profile.proxyPort)
            put("dnsPrimary", profile.dnsPrimary)
            put("dnsSecondary", profile.dnsSecondary)
            put("blockIpv6", profile.blockIpv6)
            put("bypassLan", profile.bypassLan)
            put("sshMode", profile.sshMode.name)
            put("sshPrivateKey", profile.sshPrivateKey)
            put("sshPassphrase", profile.sshPassphrase)
            put("sshProxyUser", profile.sshProxyUser)
            put("sshProxyPass", profile.sshProxyPass)
            put("sshSni", profile.sshSni)
            put("sshWsPath", profile.sshWsPath)
            put("sshCustomHeaders", profile.sshCustomHeaders)
            put("sshChainProxyHost", profile.sshChainProxyHost)
            put("sshChainProxyPort", profile.sshChainProxyPort)
            put("sshChainProxyType", profile.sshChainProxyType)
            put("sshLocalForwardPort", profile.sshLocalForwardPort)
            put("sshRemoteForwardHost", profile.sshRemoteForwardHost)
            put("sshRemoteForwardPort", profile.sshRemoteForwardPort)
            put("sshRemoteListenPort", profile.sshRemoteListenPort)
            put("allowInsecureSsl", profile.allowInsecureSsl)
            put("isLocked", profile.isLocked)
            put("lockPasswordHash", profile.lockPasswordHash)
            put("expiresAtMillis", profile.expiresAtMillis)
            put("lockedHwid", profile.lockedHwid)
            put("blockRoot", profile.blockRoot)
            put("creatorMessage", profile.creatorMessage)
        }
        return obj.toString(2)
    }

    fun exportProfileToCtp(
        profile: VpnProfile,
        options: CtpExportOptions = CtpExportOptions()
    ): String {
        val baseJson = exportProfileToJson(profile)
        return CtpConfigCrypto.encryptProfileJsonToCtp(baseJson, options)
    }
}
