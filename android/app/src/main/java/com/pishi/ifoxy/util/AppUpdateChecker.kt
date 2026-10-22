package com.pishi.ifoxy.util

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

@Serializable
data class GhAsset(
    val name: String,
    @SerialName("browser_download_url") val downloadUrl: String,
    val size: Long = 0,
)

@Serializable
data class GhRelease(
    @SerialName("tag_name") val tagName: String,
    val draft: Boolean = false,
    val prerelease: Boolean = false,
    val assets: List<GhAsset> = emptyList(),
)

data class UpdateInfo(
    /** Version without the leading "v" (e.g. "1.0.11"). */
    val version: String,
    val tag: String,
    val assetName: String,
    val downloadUrl: String,
    val sizeBytes: Long,
)

/**
 * Finds app updates in this repository's GitHub releases. Releases are
 * combined (Windows exe + Android APK under one tag), so a release only
 * counts when it actually carries an APK asset.
 */
object AppUpdateChecker {

    private const val RELEASES_URL =
        "https://api.github.com/repos/PishiKuchulu/iFoxy/releases?per_page=30"
    private const val USER_AGENT = "iFoxy-Android-Updater"
    private val VERSION_TAG = Regex("""^v\d+\.\d+\.\d+$""")
    private val json = Json { ignoreUnknownKeys = true }

    // Dedicated clients: update traffic must not ride the VPN control-plane
    // client (Mozilla cookie jar, VPN socket protector, TLS splitting).
    val apiClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }
    val downloadClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .callTimeout(0, TimeUnit.SECONDS)
            .build()
    }

    suspend fun findUpdate(currentVersion: String): UpdateInfo? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(RELEASES_URL)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", USER_AGENT)
            .build()
        apiClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) return@withContext null
            val body = response.body?.string() ?: return@withContext null
            selectUpdate(json.decodeFromString<List<GhRelease>>(body), currentVersion)
        }
    }

    /**
     * Pure selection logic (unit-tested): among the strict `vX.Y.Z`
     * releases newer than [currentVersion] (drafts and prereleases
     * excluded), pick the highest version that carries an Android APK —
     * preferring the canonical `iFoxy-v<version>.apk` asset name. Old
     * Windows-only tags have no APK and are skipped.
     */
    fun selectUpdate(releases: List<GhRelease>, currentVersion: String): UpdateInfo? =
        releases.asSequence()
            .filter { !it.draft && !it.prerelease && VERSION_TAG.matches(it.tagName) }
            .filter { VersionNumbers.isNewer(it.tagName, currentVersion) }
            .sortedWith { a, b -> VersionNumbers.compare(b.tagName, a.tagName) }
            .mapNotNull { release ->
                val version = release.tagName.removePrefix("v")
                val asset = release.assets.firstOrNull { it.name == "iFoxy-v$version.apk" }
                    ?: release.assets.firstOrNull { it.name.endsWith(".apk", ignoreCase = true) }
                asset?.let { UpdateInfo(version, release.tagName, it.name, it.downloadUrl, it.size) }
            }
            .firstOrNull()
}
