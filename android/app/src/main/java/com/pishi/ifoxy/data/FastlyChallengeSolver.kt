package com.pishi.ifoxy.data

import android.webkit.CookieManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

open class FastlyChallengeError(message: String) : Exception(message)

/** The challenge set Fastly served demands an interactive CAPTCHA:
 *  no native code can answer it — only a human in a real browser
 *  can. A distinct TYPE (never a message convention) so the
 *  sign-in UI can offer the manual verification step for exactly
 *  this failure and no other. It stays a [FastlyChallengeError], so
 *  every existing catch site keeps its current behaviour. */
class FastlyCaptchaException(message: String) : FastlyChallengeError(message)

private const val TAG = "FastlyChallengeSolver"

private const val SOLVE_TIMEOUT_SECONDS = 60L

private const val MAX_POST_BACK_ROUNDS = 8

private const val SOLVER_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

private const val POW_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

private const val HTML_ACCEPT =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

private val CHALLENGE_PREFIX_REGEX = Regex("/_fs-ch-[A-Za-z0-9]+")
private val INIT_CALL_REGEX = Regex("\\binit\\s*\\(\\s*\\[")

/** Hosts a Fastly challenge may legitimately be solved for. The
 *  solver follows challenge pages and installs the resulting
 *  clearance cookies, so the origin is validated against the FxA /
 *  Guardian hosts the app actually talks to — never an arbitrary
 *  host named by a response body. */
private val CHALLENGE_HOSTS = setOf(
    "vpn.mozilla.org",
    "api.accounts.firefox.com",
    "oauth.accounts.firefox.com",
    "accounts.firefox.com",
)

/** FxA hosts that each receive a copy of every clearance cookie, so
 *  a clearance earned while solving on one host also clears the
 *  others. Deliberately NOT a blanket firefox.com domain cookie
 *  (SEC-FX-03): the copies are scoped to the exact hosts. */
private val CLEARANCE_COOKIE_HOSTS = listOf(
    "api.accounts.firefox.com",
    "accounts.firefox.com",
    "oauth.accounts.firefox.com",
)

/** User agents the probe presents, in order: the app's native FxA
 *  identity, a mobile browser's, and a desktop browser's. All
 *  three are existing constants of this codebase (the Mozilla UA /
 *  client identity stays frozen). */
private val PROBE_USER_AGENTS = listOf(
    MOZILLA_VPN_USER_AGENT,
    FIREFOX_ANDROID_UA,
    SOLVER_USER_AGENT,
)

/**
 * Native solver for Fastly's Client Challenge, ported from upstream
 * FoxyVPN v2.0.2's design (the design this codebase's original
 * solver predated). Challenge acquisition has two routes:
 *
 * 1. The HTTP 406 response body itself is a challenge page — solve
 *    THAT page. Fetching a fresh page from the host root instead
 *    does not clear the block on flagged networks.
 * 2. The 406 body is empty (the common on-device case): probe
 *    GET / on the challenged host, then api.accounts.firefox.com,
 *    then accounts.firefox.com, under each of [PROBE_USER_AGENTS],
 *    until one serves a challenge page.
 *
 * Solving parses the challenge list out of the challenge script's
 * init() call with a real JSON tokenizer (the old single-regex
 * parser broke on real scripts whose challenge data contains ']'
 * or nested arrays), answers each challenge (SHA-256 proof-of-work,
 * PAT token request, fabricated client metrics; an interactive
 * CAPTCHA is a hard failure), and posts the answers back until
 * Fastly issues clearance cookies. The solver works in its own
 * cookie jar, EMPTY at the start of every solve (upstream parity);
 * the earned cookies are then installed into the shared
 * control-plane jar the FxA/Guardian clients retry with.
 * Acquisition and installation are logged (v1.0.35 diagnostic):
 * probe responses used to be invisible, which made a failed
 * solve impossible to tell apart from a clearance that was
 * earned but never honoured.
 */
class FastlyChallengeSolver(private val cookieJar: SimpleCookieJar) {

    private companion object {
        /** Serializes solves: concurrent 406s (an FxA call and a
         *  Guardian call racing) must not run two post-back flows
         *  against the same challenge state at once. */
        val solverMutex = Mutex()
    }

    suspend fun solveAndInstall(
        challengedBody: String? = null,
        challengedOrigin: String? = null,
    ) = solverMutex.withLock {
        withContext(Dispatchers.IO) {
            solve(challengedBody, challengedOrigin)
        }
    }

    private fun solve(challengedBody: String?, challengedOrigin: String?) {
        if (!challengedBody.isNullOrEmpty() && isChallengePage(challengedBody)) {
            val base = trustedChallengeBase(challengedOrigin)
                ?: baseFromChallengePage(challengedBody)
                ?: throw FastlyChallengeError("challenge page did not contain a usable origin")
            val rounds = solveChallengePage(challengedBody, base, MOZILLA_VPN_USER_AGENT)
            AppLogger.i(
                TAG,
                "Fastly challenge solved from the 406 response body: base=$base, " +
                    "UA=$MOZILLA_VPN_USER_AGENT, post-back rounds=$rounds",
            )
            return
        }

        val bases = listOfNotNull(
            trustedChallengeBase(challengedOrigin),
            "https://api.accounts.firefox.com",
            "https://accounts.firefox.com",
        ).distinct()
        var lastError: FastlyChallengeError? = null
        for (base in bases) {
            for (userAgent in PROBE_USER_AGENTS) {
                try {
                    if (solveChallengeOnHost(base, userAgent)) return
                } catch (e: FastlyChallengeError) {
                    lastError = preferredProbeError(lastError, e)
                } catch (e: Exception) {
                    lastError = preferredProbeError(
                        lastError,
                        FastlyChallengeError("Error probing $base: ${e.message}"),
                    )
                }
            }
        }
        throw lastError ?: FastlyChallengeError("host did not serve a Fastly challenge page")
    }

    /** "https://host" for a caller-supplied origin, but only when it
     *  is an https origin on a known FxA/Guardian host. */
    private fun trustedChallengeBase(origin: String?): String? {
        if (origin.isNullOrBlank() || !origin.startsWith("https://")) return null
        val host = origin.removePrefix("https://").substringBefore('/').substringBefore(':')
        if (host !in CHALLENGE_HOSTS) return null
        val authority = origin.removePrefix("https://").substringBefore('/')
        val port = authority.substringAfter(':', "").toIntOrNull()
        if (port != null && port != 443) return null
        return "https://$host"
    }

    private fun baseOrigin(prefixUrl: String): String {
        val idx = prefixUrl.indexOf("/_fs-ch-")
        return if (idx > 0) prefixUrl.substring(0, idx) else prefixUrl
    }

    private fun baseFromChallengePage(html: String): String? {
        val absolute = Regex("https://[A-Za-z0-9.-]+/_fs-ch-[A-Za-z0-9]+").find(html)?.value
        return absolute?.let { trustedChallengeBase(baseOrigin(it)) }
    }

    // TST-FX-12: internal (not private) so JVM unit tests can pin the
    // solver primitives against real-shaped challenge payloads.
    internal fun solvePow(base: String, targetHex: String): String? {
        val target = try {
            targetHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (e: Exception) {
            return null
        }
        if (target.size != 32) return null
        val digest = MessageDigest.getInstance("SHA-256")
        for (a in POW_ALPHABET) {
            for (b in POW_ALPHABET) {
                val suffix = "$a$b"
                val hash = digest.digest((base + suffix).toByteArray(Charsets.UTF_8))
                if (hash.contentEquals(target)) return suffix
            }
        }
        return null
    }

    /** A fetched page plus the HTTP status [fetchPage] discards:
     *  the diagnostic probe log (v1.0.35) needs the status to tell
     *  a served challenge page apart from a plain 200/403/404. */
    private data class FetchedPage(val status: Int, val body: String)

    private fun fetchPage(client: OkHttpClient, url: String, userAgent: String): String =
        fetchPageWithStatus(client, url, userAgent).body

    private fun fetchPageWithStatus(
        client: OkHttpClient,
        url: String,
        userAgent: String,
    ): FetchedPage {
        val request = Request.Builder().url(url)
            .header("User-Agent", userAgent)
            .header("Accept", HTML_ACCEPT)
            .build()
        client.newCall(request).execute().use { response ->
            return FetchedPage(response.code, response.body?.string().orEmpty())
        }
    }

    private fun fetchText(
        client: OkHttpClient,
        url: String,
        userAgent: String,
        accept: String = HTML_ACCEPT,
    ): String {
        val request = Request.Builder().url(url)
            .header("User-Agent", userAgent)
            .header("Accept", accept)
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw FastlyChallengeError("GET $url returned HTTP ${response.code}")
            return response.body?.string().orEmpty()
        }
    }

    internal fun isChallengePage(body: String): Boolean {
        if (body.length !in 1..2_000_000) return false
        if (!CHALLENGE_PREFIX_REGEX.containsMatchIn(body)) return false
        return body.contains("Client Challenge", ignoreCase = true) ||
            body.contains("script.js") ||
            body.contains("fst-post-back")
    }

    /**
     * Parses the init() call of a challenge script into its challenge
     * list and token. Ported from upstream v2.0.2: candidates are
     * tried newest-first with a JSON tokenizer; a candidate carrying
     * the script prefix as its third argument must name THIS page's
     * prefix ([prefix], e.g. "/_fs-ch-1T1wmsGaOgGaSxcX"), and the
     * two-argument legacy form is kept as a fallback.
     */
    internal fun parseChallengeInit(script: String, prefix: String = ""): Pair<JSONArray, String> {
        val matches = INIT_CALL_REGEX.findAll(script).toList().asReversed()
        var legacyResult: Pair<JSONArray, String>? = null

        for (match in matches) {
            val start = match.range.last
            val tokener = JSONTokener(script.substring(start))
            val challenges = runCatching { tokener.nextValue() as? JSONArray }.getOrNull()
            if (challenges == null || challenges.length() == 0 || challenges.length() > 16) continue
            if (tokener.nextClean() != ',') continue
            val token = runCatching { tokener.nextValue() as? String }.getOrNull()
            if (token.isNullOrBlank()) continue

            val allTyped = (0 until challenges.length()).all {
                val item = challenges.optJSONObject(it)
                item != null && item.optString("ty").isNotBlank()
            }
            val delim = tokener.nextClean()
            if (delim == ',') {
                val scriptPrefix = runCatching { tokener.nextValue() as? String }.getOrNull()
                val nextDelim = tokener.nextClean()
                val hasValidDelimiter = nextDelim == ')' || nextDelim == ','
                if (hasValidDelimiter && (prefix.isEmpty() || scriptPrefix == prefix) && allTyped) {
                    return challenges to token
                }
            } else if (delim == ')') {
                if (allTyped && legacyResult == null) {
                    legacyResult = challenges to token
                }
            }
        }

        if (legacyResult != null) return legacyResult

        throw FastlyChallengeError("Could not read the Fastly challenge")
    }

    private fun fetchPat(client: OkHttpClient, prefixUrl: String, token: String, userAgent: String): String {
        val patUrl = "$prefixUrl/pat?token=${URLEncoder.encode(token, "UTF-8")}"
        val request = Request.Builder()
            .url(patUrl)
            .header("Accept", "text/plain")
            .header("Content-Type", "application/json")
            .header("User-Agent", userAgent)
            .header("Origin", baseOrigin(prefixUrl))
            .post(ByteArray(0).toRequestBody(null))
            .build()
        client.newCall(request).execute().use { response ->
            if (response.code == 400 || response.code == 401) return ""
            if (!response.isSuccessful) throw FastlyChallengeError("PAT request returned HTTP ${response.code}")
            val json = try {
                JSONObject(response.body?.string().orEmpty())
            } catch (e: Exception) {
                throw FastlyChallengeError("could not parse PAT response: ${e.message}")
            }
            val auth = json.optString("auth", "")
            if (auth.isEmpty()) throw FastlyChallengeError("empty PAT auth token")
            return auth
        }
    }

    private fun clientMetricsAnswer(): JSONObject = JSONObject().apply {
        put("ty", "clientmetrics")
        put("webdriver", false)
        put(
            "bot_detection_result",
            JSONObject().apply {
                put("bot_detected", false)
                put("bot_kind", JSONObject.NULL)
            },
        )
        put(
            "browser_metrics",
            JSONObject().apply {
                put("client_data", "{}")
                put("error_trace", JSONObject.NULL)
            },
        )
        put("detector_results", JSONObject())
        put("v", 2)
    }

    private fun answerChallenge(
        client: OkHttpClient,
        prefixUrl: String,
        token: String,
        challenge: JSONObject,
        userAgent: String,
    ): JSONObject {
        val data = challenge.optJSONObject("data") ?: JSONObject()
        return when (val type = challenge.optString("ty")) {
            "pow" -> {
                val base = data.optString("base", "")
                val answer = solvePow(base, data.optString("hash", ""))
                    ?: throw FastlyChallengeError("no proof-of-work solution found for base $base")
                JSONObject().apply {
                    put("ty", "pow")
                    put("base", base)
                    put("answer", answer)
                    put("hmac", data.optString("hmac", ""))
                    put("expires", data.optString("expires", ""))
                }
            }
            "pat" -> JSONObject().apply {
                put("ty", "pat")
                put("auth", fetchPat(client, prefixUrl, token, userAgent))
            }
            "clientmetrics" -> clientMetricsAnswer()
            "captcha" -> throw FastlyCaptchaException(
                "Firefox Accounts requires a CAPTCHA. Sign in again to continue."
            )
            else -> throw FastlyChallengeError("unsupported Fastly challenge type '$type'")
        }
    }

    private fun installChallengeCookies(solverJar: SimpleCookieJar) {
        // The solver jar starts EMPTY (upstream parity), so every
        // cookie in it was issued or rotated by THIS solve — exactly
        // the set that may be installed. (It used to be seeded with
        // the shared jar's cookies and this step filtered the seeds
        // back out; seeding also blinded the NEXT solve, whose
        // probes presented the freshly earned clearance and were
        // served plain pages instead of a challenge page.)
        val fresh = solverJar.snapshotAll()
        if (fresh.isEmpty()) throw FastlyChallengeError("challenge completed but no cookies were issued")
        for (cookie in fresh) {
            // SEC-FX-03: keep each cookie under the domain that issued
            // it, plus one copy per FxA host (CLEARANCE_COOKIE_HOSTS)
            // so a clearance earned on one host clears the others.
            // Never a blanket firefox.com domain cookie.
            val ownDomain = cookie.domain.removePrefix(".")
            val targets = (listOf(ownDomain) + CLEARANCE_COOKIE_HOSTS)
                .filter { it.isNotBlank() }
                .distinct()
            for (domain in targets) {
                cookieJar.set(cookie.name, cookie.value, domain)
            }
            // Diagnostic (v1.0.35): cookie NAME and domains only —
            // the value is a credential and is never logged.
            AppLogger.i(
                TAG,
                "installed clearance cookie '${cookie.name}' for domains $targets " +
                    "(value length ${cookie.value.length})",
            )
            mirrorCookieToWebView(cookie.name, cookie.value, ownDomain)
            for (domain in CLEARANCE_COOKIE_HOSTS) {
                mirrorCookieToWebView(cookie.name, cookie.value, domain)
            }
        }
    }

    /** Best-effort mirror of a clearance cookie into the WebView's
     *  cookie store (upstream's syncToWebView direction), so the
     *  browser sign-in context also benefits from a native solve. */
    private fun mirrorCookieToWebView(name: String, value: String, domain: String) {
        runCatching {
            val manager = CookieManager.getInstance()
            manager.setAcceptCookie(true)
            manager.setCookie(
                "https://$domain/",
                "$name=$value; Domain=$domain; Path=/; Secure",
            )
            manager.flush()
        }
    }

    // TST-FX-13: internal (not private) so JVM unit tests can pin
    // the upstream-parity empty start.
    /** The solver's working cookie jar: EMPTY at the start of every
     *  solve (upstream v2.0.2 parity — its solver jar is a fresh
     *  SimpleCookieJar). It accumulates only the cookies this
     *  solve's own responses set; [installChallengeCookies] then
     *  installs that earned set into the shared jar. */
    internal fun newSolverJar(): SimpleCookieJar = SimpleCookieJar()

    private fun solveChallengeOnHost(base: String, userAgent: String): Boolean {
        val solverJar = newSolverJar()
        val solver = newSolverClient(solverJar)
        val fetched = try {
            fetchPageWithStatus(solver, "$base/", userAgent)
        } catch (e: Exception) {
            // Diagnostic (v1.0.35): a probe dying in transport used
            // to be indistinguishable from one served a plain page;
            // log which happened, then keep the old behaviour.
            AppLogger.w(
                TAG,
                "Fastly probe $base failed in transport " +
                    "(${e.javaClass.simpleName}: ${e.message}); UA=$userAgent",
            )
            return false
        }
        val challengePage = isChallengePage(fetched.body)
        AppLogger.i(
            TAG,
            "Fastly probe $base -> HTTP ${fetched.status}, ${fetched.body.length} bytes, " +
                "challengePage=$challengePage; UA=$userAgent; body head: ${fetched.body.take(200)}",
        )
        if (!challengePage) return false
        val rounds = solveChallengePage(fetched.body, base, userAgent, solver, solverJar)
        AppLogger.i(
            TAG,
            "Fastly challenge solved by probing: base=$base, UA=$userAgent, " +
                "post-back rounds=$rounds",
        )
        return true
    }

    private fun solveChallengePage(
        page: String,
        origin: String,
        userAgent: String = MOZILLA_VPN_USER_AGENT,
    ): Int {
        val solverJar = newSolverJar()
        return solveChallengePage(page, origin, userAgent, newSolverClient(solverJar), solverJar)
    }

    /** Solves an already-fetched challenge page; returns the number
     *  of post-back rounds the solve took (diagnostic, v1.0.35). */
    private fun solveChallengePage(
        page: String,
        origin: String,
        userAgent: String,
        solver: OkHttpClient,
        solverJar: SimpleCookieJar,
    ): Int {
        val prefixMatch = CHALLENGE_PREFIX_REGEX.find(page)
            ?: throw FastlyChallengeError("challenge asset prefix not found on $origin")
        val prefixUrl = origin + prefixMatch.value

        val script = fetchText(solver, "$prefixUrl/script.js?reload=true", userAgent)
        var (challenges, token) = parseChallengeInit(script, prefixMatch.value)

        repeat(MAX_POST_BACK_ROUNDS) { roundIndex ->
            val answers = JSONArray()
            for (i in 0 until challenges.length()) {
                answers.put(answerChallenge(solver, prefixUrl, token, challenges.getJSONObject(i), userAgent))
            }
            val postBody = JSONObject().apply {
                put("token", token)
                put("data", answers)
            }.toString().toRequestBody("application/json".toMediaType())
            val request = Request.Builder()
                .url("$prefixUrl/fst-post-back")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", userAgent)
                .header("Origin", origin)
                .post(postBody)
                .build()
            solver.newCall(request).execute().use { response ->
                if (!response.isSuccessful) throw FastlyChallengeError("challenge post-back returned HTTP ${response.code}")
                val body = JSONObject(response.body?.string().orEmpty())
                if (body.optString("status") == "success") {
                    val recheck = fetchPage(solver, "$origin/", userAgent)
                    if (isChallengePage(recheck)) {
                        throw FastlyChallengeError("challenge cookie not accepted on this exit IP")
                    }
                    installChallengeCookies(solverJar)
                    return roundIndex + 1
                }
                val nextChallenges = body.optJSONArray("ch")
                val nextToken = body.optString("tok", "")
                if (nextChallenges == null || nextChallenges.length() == 0 || nextToken.isEmpty()) {
                    throw FastlyChallengeError("unexpected post-back response: $body")
                }
                challenges = nextChallenges
                token = nextToken
            }
        }
        throw FastlyChallengeError("Fastly challenge did not complete within $MAX_POST_BACK_ROUNDS rounds")
    }

    private fun newSolverClient(solverJar: SimpleCookieJar): OkHttpClient =
        ControlPlaneHttp.client.newBuilder()
            .cookieJar(solverJar)
            .connectTimeout(SOLVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(SOLVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()
}

/** Which probe failure [FastlyChallengeSolver.solve] keeps as its
 *  lastError: a CAPTCHA verdict is the one outcome the sign-in UI
 *  can act on (present the manual verification step), so once any
 *  probe has captured one, a later probe's ordinary failure must
 *  not overwrite it — otherwise whether the user is offered the
 *  step depends on probe order. A newer CAPTCHA replaces an older
 *  non-CAPTCHA; between two ordinary failures the newest wins, as
 *  before. Pure, so the preference is unit-testable. */
internal fun preferredProbeError(
    current: FastlyChallengeError?,
    candidate: FastlyChallengeError,
): FastlyChallengeError = when {
    candidate is FastlyCaptchaException -> candidate
    current is FastlyCaptchaException -> current
    else -> candidate
}

/** Splits a CookieManager cookie string ("name=value; name=value")
 *  into its pairs. Only the FIRST '=' splits, so values may
 *  themselves contain '='; fragments without a name, without an
 *  '=', or with a blank value are dropped — CookieManager can
 *  surface valueless or cleared leftovers that are not usable
 *  cookies. Pure, so the harvest parsing is unit-testable. */
internal fun parseWebViewCookieHeader(header: String?): List<Pair<String, String>> {
    if (header.isNullOrBlank()) return emptyList()
    return header.split(';').mapNotNull { fragment ->
        val eq = fragment.indexOf('=')
        if (eq <= 0) return@mapNotNull null
        val name = fragment.substring(0, eq).trim()
        val value = fragment.substring(eq + 1).trim()
        if (name.isEmpty() || value.isEmpty()) return@mapNotNull null
        name to value
    }
}

/** Copies every cookie the sign-in WebView holds for the FxA hosts
 *  into the native shared jar — the harvest half of the manual
 *  verification step (v1.0.36): the user passes Mozilla's CAPTCHA
 *  in the real browser, and this moves whatever Fastly cookies
 *  that pass earned into the jar the native token exchange
 *  retries with. Installation mirrors the solver's own
 *  installChallengeCookies: each cookie lands under the host it
 *  was read from plus one copy per CLEARANCE_COOKIE_HOSTS entry,
 *  never a blanket firefox.com domain cookie. Cookie VALUES are
 *  never logged — names, source host, target domains and value
 *  length only, like the solver's install logging. Returns how
 *  many cookies were installed. */
internal fun harvestWebViewCookiesIntoJar(cookieJar: SimpleCookieJar): Int {
    val manager = runCatching { CookieManager.getInstance() }.getOrNull() ?: return 0
    var installed = 0
    for (host in CLEARANCE_COOKIE_HOSTS) {
        val header = runCatching { manager.getCookie("https://$host/") }.getOrNull()
        for ((name, value) in parseWebViewCookieHeader(header)) {
            val targets = (listOf(host) + CLEARANCE_COOKIE_HOSTS).distinct()
            for (domain in targets) {
                cookieJar.set(name, value, domain)
            }
            installed++
            AppLogger.i(
                TAG,
                "harvested WebView cookie '$name' from $host for domains $targets " +
                    "(value length ${value.length})",
            )
        }
    }
    AppLogger.i(TAG, "WebView cookie harvest installed $installed cookie(s) into the shared jar")
    return installed
}
