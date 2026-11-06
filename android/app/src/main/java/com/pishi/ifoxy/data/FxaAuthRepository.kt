package com.pishi.ifoxy.data

import android.util.Base64
import com.pishi.ifoxy.data.model.RuntimeAuth
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val TAG = "FxaAuthRepository"

enum class SessionStatus {
    ACTIVE,
    NEEDS_LOGIN,
    UNREACHABLE,
}

class FxaApiError(message: String, val errno: Int?, val statusCode: Int?) : Exception(message)

val FxaApiError.isUnconfirmedSession: Boolean
    get() = errno == 104 || (statusCode == 400 && message?.contains("Unconfirmed session", ignoreCase = true) == true)

fun Throwable.isUnconfirmedSession(): Boolean =
    (this as? FxaApiError)?.isUnconfirmedSession == true ||
        message?.contains("Unconfirmed session", ignoreCase = true) == true

class FxaRefreshFailure(
    message: String,
    val permanent: Boolean,
    cause: Throwable? = null,
    /** True when Mozilla's bot protection (HTTP 406) blocked the
     *  renewal before FxA could evaluate the refresh token: the
     *  session itself may still be valid, and retrying the same
     *  native request on this network cannot succeed. */
    val blockedByBotProtection: Boolean = false,
) : Exception(message, cause)

/** True when this failure chain contains a Fastly bot-protection
 *  block (HTTP 406 whose challenge could not be solved natively). */
internal fun Throwable.isBotProtectionBlock(): Boolean =
    generateSequence(this) { it.cause }.take(8).any { it is FastlyBlockedException }

/** The outcome of a forced access-token renewal, keeping WHY it
 *  failed: callers must not treat a blocked or permanently rejected
 *  renewal like a transient error and carry on with a dead token. */
sealed interface AccessTokenRenewal {
    data class Renewed(val auth: RuntimeAuth) : AccessTokenRenewal
    data class Failed(
        val message: String?,
        val permanent: Boolean,
        val blockedByBotProtection: Boolean,
    ) : AccessTokenRenewal
}

/** Mozilla's bot protection (HTTP 406) could not be cleared automatically
 *  on this network; the message is user-facing and actionable. */
class FastlyBlockedException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** A fully-formed, Hawk-signed FxA /oauth/token request that a real
 *  browser context can execute on the app's behalf (see the browser
 *  sign-in screen: the page's network stack already passed Mozilla's
 *  bot protection, the native HTTP client has not). */
class BrowserTokenRequest(val url: String, val authorization: String, val bodyJson: String)

private const val FXA_AUTH_SERVER = "https://api.accounts.firefox.com/v1"
private const val FIREFOX_CLIENT_ID = "5882386c6d801776"
private const val OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
private const val PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
private const val FXA_MAX_CHALLENGE_ATTEMPTS = 5
private const val FRIENDLY_406_MESSAGE =
    "Mozilla's bot protection rejected this request (HTTP 406) and the automatic " +
        "challenge could not be completed on this network. Please switch networks " +
        "(Wi-Fi <-> mobile data) and try again."
private const val DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60

/** The FxA sign-in page in its WebChannel ("browser") context: after a
 *  successful sign-in the page posts the session token to the embedding
 *  browser via WebChannel, which the browser sign-in screen captures. */
private const val WEBCHANNEL_LOGIN_URL =
    "https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email"

private val SESSION_TOKEN_HEX = Regex("^[0-9a-f]{64}$")

private val jsonMediaType = "application/json".toMediaType()

class FxaAuthRepository(
    private val tokenStore: TokenStore,
    private val challengeSolver: FastlyChallengeSolver = FastlyChallengeSolver(ControlPlaneHttp.cookieJar),
    private val accountStore: AccountStore? = null,
) {
    companion object {
        fun normalizeEmail(email: String): String =
            email.replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "").trim().lowercase()
    }

    /** The official FxA page the in-app browser sign-in starts from. */
    fun getBrowserLoginUrl(): String = WEBCHANNEL_LOGIN_URL

    /**
     * Finish a browser sign-in. The WebChannel bridge captured the
     * session token from Mozilla's own page — where the user entered
     * their password and any verification code, neither of which ever
     * touches this app — and the rest of the flow is the same
     * session-to-OAuth exchange the old password login ended with.
     */
    suspend fun completeBrowserLogin(
        sessionToken: String,
        preExchangedToken: JSONObject? = null,
    ): Result<Unit> = runCatching {
        val clean = sessionToken.trim().replace(Regex("[\\s\"]"), "").lowercase()
        if (!SESSION_TOKEN_HEX.matches(clean)) {
            error("The sign-in page did not hand over a usable session token")
        }
        // Multi-account: stash the outgoing account's freshest tokens in
        // the vault before this sign-in replaces the live session.
        accountStore?.harvestFrom(tokenStore)
        completeLogin(clean, preExchangedToken)
    }

    suspend fun restoreSession(): SessionStatus {
        val stored = runCatching { tokenStore.loadAuth() }.getOrNull()
            ?: return SessionStatus.NEEDS_LOGIN
        if (stored.refreshToken == null && !tokenStore.hasValidAccessToken()) {
            runCatching { tokenStore.clear() }
            return SessionStatus.NEEDS_LOGIN
        }
        if (tokenStore.hasValidAccessToken()) return SessionStatus.ACTIVE

        return try {
            ensureFreshAccessToken()
            SessionStatus.ACTIVE
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: FxaRefreshFailure) {
            if (failure.permanent) {
                AppLogger.w(TAG, "FxA rejected the stored session; signing out", failure)
                runCatching { tokenStore.clear() }
                SessionStatus.NEEDS_LOGIN
            } else {
                AppLogger.w(TAG, "could not renew the session right now; staying signed in", failure)
                SessionStatus.UNREACHABLE
            }
        } catch (unexpected: Exception) {
            AppLogger.w(TAG, "unexpected error while restoring the session", unexpected)
            SessionStatus.UNREACHABLE
        }
    }

    suspend fun ensureFreshAccessToken(force: Boolean = false): RuntimeAuth {
        val current = tokenStore.loadAuth()
            ?: throw FxaRefreshFailure("Not signed in", permanent = true)
        if (!force && tokenStore.hasValidAccessToken()) return current

        val refreshToken = current.refreshToken
            ?: throw FxaRefreshFailure(
                "The stored session has no refresh token; sign in again.",
                permanent = true,
            )

        val body = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "refresh_token")
            put("refresh_token", refreshToken)
            put("scope", OAUTH_SCOPE)
        }

        val tokenData = try {
            fxaDo("POST", "/oauth/token", jsonBody = body)
        } catch (rejected: FxaApiError) {
            throw FxaRefreshFailure(
                rejected.message ?: "FxA rejected the refresh token",
                permanent = rejected.isPermanentRefreshRejection(),
                cause = rejected,
            )
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (transport: Exception) {
            throw FxaRefreshFailure(
                transport.message ?: "Could not reach the Firefox Accounts server",
                permanent = false,
                cause = transport,
                blockedByBotProtection = transport.isBotProtectionBlock(),
            )
        }

        val accessToken = tokenData.optString("access_token").takeIf { it.isNotBlank() }
            ?: throw FxaRefreshFailure(
                "FxA returned no access token for the refresh grant",
                permanent = false,
            )

        val renewed = RuntimeAuth(
            accessToken = accessToken,
            refreshToken = tokenData.optString("refresh_token", "").ifBlank { null } ?: refreshToken,
            expiresAtEpochSeconds = expiryFrom(tokenData),
        )
        runCatching { tokenStore.saveAuth(renewed) }
            .onFailure { AppLogger.w(TAG, "could not persist the renewed token", it) }
        return renewed
    }

    suspend fun currentAccessToken(): String? = try {
        ensureFreshAccessToken().accessToken
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: FxaRefreshFailure) {
        if (failure.permanent) null else tokenStore.loadAuth()?.accessToken
    }

    suspend fun refreshAccessToken(): RuntimeAuth? = try {
        ensureFreshAccessToken(force = true)
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: FxaRefreshFailure) {
        AppLogger.w(TAG, "access token renewal failed", failure)
        null
    }

    /** Forced renewal that reports WHY it failed instead of collapsing
     *  every failure to null: a renewal blocked by Mozilla's bot
     *  protection, or one FxA permanently rejected, will never succeed
     *  by retrying with the same dead token, and the connect flow
     *  fails fast on those instead of burning server attempts. */
    suspend fun renewAccessTokenDetailed(): AccessTokenRenewal = try {
        AccessTokenRenewal.Renewed(ensureFreshAccessToken(force = true))
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: FxaRefreshFailure) {
        AppLogger.w(TAG, "access token renewal failed", failure)
        AccessTokenRenewal.Failed(
            message = failure.message,
            permanent = failure.permanent,
            blockedByBotProtection = failure.blockedByBotProtection,
        )
    }

    private fun FxaApiError.isPermanentRefreshRejection(): Boolean {
        return statusCode == 400 || statusCode == 401 || statusCode == 403
    }

    private fun expiryFrom(tokenData: JSONObject): Long {
        val expiresIn = tokenData.optInt("expires_in", 0)
            .takeIf { it > 0 } ?: DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        return System.currentTimeMillis() / 1000 + expiresIn
    }

    private suspend fun completeLogin(sessionToken: String, preExchangedToken: JSONObject? = null) {
        // A token response produced inside the signed-in browser page
        // wins over the native exchange; a malformed one falls back.
        val tokenData = preExchangedToken
            ?.takeIf { it.optString("access_token").isNotBlank() }
            ?: oauthToken(sessionToken)
        val auth = RuntimeAuth(
            accessToken = tokenData.getString("access_token"),
            refreshToken = tokenData.optString("refresh_token", "").ifBlank { null },
            expiresAtEpochSeconds = expiryFrom(tokenData),
        )
        tokenStore.saveAuth(auth)
        // File the account in the multi-account vault (it becomes active).
        // The browser sign-in never learns the email upfront, so when no
        // login email is pending, ask the FxA profile endpoint whose
        // account this session belongs to. Best effort: the live session
        // above is valid either way, and the startup migration files
        // unfiled sessions the same way.
        val vault = accountStore
        if (vault != null) {
            val loginEmail = tokenStore.pendingLoginEmail
                ?: runCatching { fetchAccountEmail() }.getOrNull()
            if (loginEmail != null) {
                runCatching { vault.upsert(loginEmail, auth) }
                    .onFailure { AppLogger.w(TAG, "could not file the account in the vault", it) }
            }
        }
        tokenStore.pendingLoginEmail = null
    }

    /** The signed-in account's email, from the FxA profile endpoint.
     *  Used to migrate a pre-multi-account session into the vault. */
    suspend fun fetchAccountEmail(): String? = withContext(Dispatchers.IO) {
        val auth = ensureFreshAccessToken()
        val request = Request.Builder()
            .url("https://api.accounts.firefox.com/v1/account/profile")
            .header("Authorization", "Bearer ${auth.accessToken}")
            .applyMozillaVpnHeaders()
            .build()
        ControlPlaneHttp.client.newCall(request).execute().use { resp ->
            if (resp.code != 200) return@withContext null
            val text = resp.body?.string().orEmpty()
            runCatching { JSONObject(text).optString("email") }.getOrNull()
                ?.takeIf { it.isNotBlank() }
        }
    }

    private fun oauthTokenBody(): JSONObject = JSONObject().apply {
        put("client_id", FIREFOX_CLIENT_ID)
        put("grant_type", "fxa-credentials")
        put("scope", OAUTH_SCOPE)
        put("access_type", "offline")
    }

    private suspend fun oauthToken(sessionToken: String): JSONObject {
        return fxaDo("POST", "/oauth/token", sessionToken = sessionToken, jsonBody = oauthTokenBody())
    }

    /** Builds the Hawk-signed /oauth/token request for [sessionToken]
     *  so the signed-in browser page can execute it in its own trusted
     *  network context instead of the native client. */
    fun buildBrowserTokenRequest(sessionToken: String): BrowserTokenRequest {
        val body = oauthTokenBody()
        val bodyBytes = body.toString().toByteArray(Charsets.UTF_8)
        val url = "$FXA_AUTH_SERVER/oauth/token".toHttpUrl()
        val (tokenId, hmacKey) = deriveHawkCredentials(sessionToken)
        return BrowserTokenRequest(
            url = url.toString(),
            authorization = hawkHeader("POST", url, tokenId, hmacKey, bodyBytes),
            bodyJson = body.toString(),
        )
    }

    private suspend fun fxaDo(
        method: String,
        path: String,
        sessionToken: String? = null,
        jsonBody: JSONObject,
    ): JSONObject = withContext(Dispatchers.IO) {
        val url = "$FXA_AUTH_SERVER$path".toHttpUrl()
        val bodyBytes = jsonBody.toString().toByteArray(Charsets.UTF_8)
        var tokenId: String? = null
        var hmacKey: ByteArray? = null
        if (sessionToken != null) {
            val (id, key) = deriveHawkCredentials(sessionToken)
            tokenId = id
            hmacKey = key
        }

        fun buildRequest(): Request {
            val builder = Request.Builder().url(url).applyMozillaVpnHeaders()
            builder.header("Content-Type", "application/json")
            if (sessionToken != null) {
                builder.header("Authorization", hawkHeader(method, url, tokenId!!, hmacKey!!, bodyBytes))
            }
            builder.method(method, bodyBytes.toRequestBody(jsonMediaType))
            return builder.build()
        }

        val origin = "${url.scheme}://${url.host}"
        var response: Response = ControlPlaneHttp.client.newCall(buildRequest()).execute()
        var attempts = 1
        while (response.code == 406 && attempts < FXA_MAX_CHALLENGE_ATTEMPTS) {
            // Solve the challenge carried by THIS 406 response: fetching a
            // fresh challenge page from the host root does not clear the
            // block on flagged networks (upstream v1.0.8 finding, verified
            // on-device against iFoxy 1.0.23).
            val challengedBody = response.use { it.body?.string().orEmpty() }
            AppLogger.w(TAG, "HTTP 406 on $path; challenge body head: ${challengedBody.take(240)}")
            try {
                challengeSolver.solveAndInstall(challengedBody, origin)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (solveFailure: Exception) {
                AppLogger.w(TAG, "could not solve the Fastly challenge", solveFailure)
                throw FastlyBlockedException(FRIENDLY_406_MESSAGE, solveFailure)
            }
            response = ControlPlaneHttp.client.newCall(buildRequest()).execute()
            attempts++
        }

        response.use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code >= 400) {
                if (resp.code == 406) {
                    throw FastlyBlockedException(FRIENDLY_406_MESSAGE)
                }
                val errorBody = try {
                    JSONObject(text)
                } catch (e: Exception) {
                    JSONObject()
                }
                val errno = if (errorBody.has("errno")) errorBody.optInt("errno") else null
                val message = errorBody.optString("message", text.ifEmpty { "HTTP ${resp.code}" })
                throw FxaApiError(message, errno, resp.code)
            }
            if (text.isEmpty()) return@withContext JSONObject()
            return@withContext JSONObject(text)
        }
    }

    private fun deriveHawkCredentials(sessionTokenHex: String): Pair<String, ByteArray> {
        val sessionToken = sessionTokenHex.hexToBytes()
        val expanded = hkdf(sessionToken, "${PROTOCOL_VERSION}sessionToken", 64)
        return expanded.copyOfRange(0, 32).toHex() to expanded.copyOfRange(32, 64)
    }

    private fun hawkHeader(method: String, url: HttpUrl, tokenId: String, hmacKey: ByteArray, body: ByteArray): String {
        val ts = (System.currentTimeMillis() / 1000).toString()
        val nonceBytes = ByteArray(6).also { SecureRandom().nextBytes(it) }
        val nonce = Base64.encodeToString(nonceBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        val path = url.encodedPath + if (url.encodedQuery != null) "?${url.encodedQuery}" else ""

        var payloadHash = ""
        if (body.isNotEmpty()) {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("hawk.1.payload\napplication/json\n".toByteArray(Charsets.UTF_8))
            digest.update(body)
            digest.update("\n".toByteArray(Charsets.UTF_8))
            payloadHash = Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
        }

        val normalized = "hawk.1.header\n$ts\n$nonce\n${method.uppercase()}\n$path\n${url.host}\n${url.port}\n$payloadHash\n\n"

        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(hmacKey, "HmacSHA256")) }
        val macB64 = Base64.encodeToString(mac.doFinal(normalized.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)

        var header = "Hawk id=\"$tokenId\", ts=\"$ts\", nonce=\"$nonce\", mac=\"$macB64\""
        if (payloadHash.isNotEmpty()) header += ", hash=\"$payloadHash\""
        return header
    }
}

// TST-FX-11: internal (not public) so JVM unit tests can verify the
// hand-rolled FxA primitives against published known-answer vectors.
internal fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

internal fun hkdf(ikm: ByteArray, info: String, length: Int, salt: ByteArray = ByteArray(32)): ByteArray {
    val prk = hmacSha256(salt, ikm)
    val infoBytes = info.toByteArray(Charsets.UTF_8)
    val result = ByteArray(length)
    var previousBlock = ByteArray(0)
    var generated = 0
    var counter = 1
    while (generated < length) {
        val block = hmacSha256(prk, previousBlock + infoBytes + byteArrayOf(counter.toByte()))
        val toCopy = minOf(block.size, length - generated)
        System.arraycopy(block, 0, result, generated, toCopy)
        generated += toCopy
        previousBlock = block
        counter++
    }
    return result
}

internal fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray {
    val hLen = 32
    val numBlocks = (keyLengthBytes + hLen - 1) / hLen
    val result = ByteArray(numBlocks * hLen)
    val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
    for (blockIndex in 1..numBlocks) {
        val blockIndexBytes = ByteBuffer.allocate(4).putInt(blockIndex).array()
        var u = mac.doFinal(salt + blockIndexBytes)
        val t = u.copyOf()
        for (iter in 2..iterations) {
            u = mac.doFinal(u)
            for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
        }
        System.arraycopy(t, 0, result, (blockIndex - 1) * hLen, hLen)
    }
    return result.copyOf(keyLengthBytes)
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
