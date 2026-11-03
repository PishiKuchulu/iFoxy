package com.pishi.ifoxy.ui.components

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.FileProvider
import com.pishi.ifoxy.BuildConfig
import com.pishi.ifoxy.data.formatBytes
import com.pishi.ifoxy.ui.theme.IFoxyErrorOnDark
import com.pishi.ifoxy.ui.theme.IFoxyInk
import com.pishi.ifoxy.ui.theme.IFoxyNeonOrange
import com.pishi.ifoxy.ui.theme.IFoxyYellow
import com.pishi.ifoxy.ui.theme.PoppinsFamily
import com.pishi.ifoxy.util.AppUpdateChecker
import com.pishi.ifoxy.util.UpdateInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Request
import java.io.File

sealed interface UpdateUiState {
    data object Idle : UpdateUiState
    data object Checking : UpdateUiState
    data object UpToDate : UpdateUiState
    data class Available(val info: UpdateInfo) : UpdateUiState
    data class Downloading(val info: UpdateInfo, val downloaded: Long, val total: Long) : UpdateUiState
    data class ReadyToInstall(val info: UpdateInfo, val file: File) : UpdateUiState
    data class Failed(val message: String) : UpdateUiState
}

/**
 * In-app update controller (same pattern as Anvex/PishiMovie): checks the
 * repository's GitHub releases on launch, offers the update in a dialog,
 * downloads the APK with progress + cancel, and hands it to the system
 * installer through the app's FileProvider.
 */
class AppUpdateController(private val appContext: Context) {

    var state: UpdateUiState by mutableStateOf(UpdateUiState.Idle)
        private set
    var dialogVisible: Boolean by mutableStateOf(false)
        private set

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var downloadJob: Job? = null

    @Volatile
    private var cancelRequested = false

    fun checkOnLaunch() {
        if (state == UpdateUiState.Idle) check()
    }

    fun check() {
        if (state is UpdateUiState.Checking || state is UpdateUiState.Downloading) return
        state = UpdateUiState.Checking
        scope.launch {
            val found = try {
                AppUpdateChecker.findUpdate(BuildConfig.VERSION_NAME)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                // A failed check is NOT "up to date": surface it so the
                // Settings row can say the check itself failed.
                state = UpdateUiState.Failed("Couldn't check for updates")
                return@launch
            }
            state = if (found != null) {
                dialogVisible = true
                UpdateUiState.Available(found)
            } else {
                UpdateUiState.UpToDate
            }
        }
    }

    fun showDialog() {
        if (state is UpdateUiState.Available ||
            state is UpdateUiState.ReadyToInstall ||
            state is UpdateUiState.Failed
        ) {
            dialogVisible = true
        }
    }

    fun dismissDialog() {
        dialogVisible = false
    }

    fun startDownload() {
        val info = (state as? UpdateUiState.Available)?.info ?: return
        cancelRequested = false
        downloadJob = scope.launch {
            try {
                val file = withContext(Dispatchers.IO) {
                    // Progress is reported per 64 KB chunk from the IO
                    // thread; only publish a new state when the whole
                    // percent actually changes, so the dialog and the
                    // Settings row are not recomposed ~200 times for a
                    // 13 MB download.
                    var lastPublishedPercent = -1
                    downloadApk(info) { downloaded, total ->
                        val percent = if (total > 0) {
                            ((downloaded * 100) / total).toInt()
                        } else {
                            0
                        }
                        if (percent != lastPublishedPercent) {
                            lastPublishedPercent = percent
                            state = UpdateUiState.Downloading(info, downloaded, total)
                        }
                    }
                }
                state = UpdateUiState.ReadyToInstall(info, file)
            } catch (cancelled: CancellationException) {
                state = UpdateUiState.Available(info)
            } catch (error: Exception) {
                state = if (cancelRequested) {
                    UpdateUiState.Available(info)
                } else {
                    UpdateUiState.Failed(error.message ?: "Download failed")
                }
            }
        }
    }

    fun cancelDownload() {
        cancelRequested = true
        downloadJob?.cancel()
    }

    fun install(context: Context) {
        val ready = state as? UpdateUiState.ReadyToInstall ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !context.packageManager.canRequestPackageInstalls()
        ) {
            // Ask for the "install unknown apps" consent first; the user
            // returns and taps Install again.
            val consent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}"),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(consent)
            return
        }
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            ready.file,
        )
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(intent)
        dialogVisible = false
    }

    private fun downloadApk(info: UpdateInfo, onProgress: (Long, Long) -> Unit): File {
        val dir = File(appContext.cacheDir, "updates").apply { mkdirs() }
        val part = File(dir, info.assetName + ".part")
        val request = Request.Builder()
            .url(info.downloadUrl)
            .header("User-Agent", "iFoxy-Android-Updater")
            .build()
        try {
            AppUpdateChecker.downloadClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) error("HTTP ${response.code}")
                val body = response.body ?: error("Empty response")
                val total = body.contentLength().takeIf { it > 0 } ?: info.sizeBytes
                body.byteStream().use { input ->
                    part.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var downloaded = 0L
                        while (true) {
                            if (cancelRequested) throw CancellationException("Download cancelled")
                            val read = input.read(buffer)
                            if (read == -1) break
                            output.write(buffer, 0, read)
                            downloaded += read
                            onProgress(downloaded, total)
                        }
                    }
                }
            }
        } catch (error: Exception) {
            part.delete()
            throw error
        }
        // Verify the download against the SHA-256 the GitHub API
        // reported for this asset before it is offered to the installer
        // (external review, A6). The digest is REQUIRED (wave-3 review,
        // A-1): when the API omits it, verification used to be skipped
        // entirely and the APK went to the installer unchecked. Now a
        // missing digest fails the update closed.
        val expected = info.sha256 ?: run {
            part.delete()
            error("Update metadata carries no SHA-256 digest for this asset; refusing to install an unverified APK")
        }
        val actual = java.security.MessageDigest.getInstance("SHA-256").let { digest ->
            part.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read == -1) break
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        }
        if (actual != expected) {
            part.delete()
            error("Downloaded APK failed checksum verification (expected $expected, got $actual)")
        }
        // Defense in depth (A-1): the downloaded APK's signing
        // certificate must be the project's release certificate. The
        // package manager would reject a foreign signer at install time
        // anyway (an update must match the installed app's signer), but
        // checking here fails before the user is ever prompted.
        val signer = apkSignerSha256(appContext, part)
        if (signer != RELEASE_CERT_SHA256) {
            part.delete()
            error("Downloaded APK is not signed with the iFoxy release certificate; refusing to install")
        }
        val target = File(dir, info.assetName)
        if (target.exists()) target.delete()
        check(part.renameTo(target)) { "Could not finalize the downloaded APK" }
        return target
    }
}

/**
 * SHA-256 fingerprint of the iFoxy release signing certificate (the
 * public fingerprint of the key every official release is signed with;
 * it appears in every shipped APK and is not a secret).
 */
private const val RELEASE_CERT_SHA256 =
    "f5381666261427b5f3c5345c79110c1aaede57b593b540d7aaa5ac481a340bee"

/** SHA-256 fingerprint of an APK file's signing certificate, or null. */
private fun apkSignerSha256(context: android.content.Context, file: File): String? {
    val pm = context.packageManager
    val certBytes: ByteArray? = if (android.os.Build.VERSION.SDK_INT >= 28) {
        @Suppress("DEPRECATION")
        val info = if (android.os.Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(
                file.absolutePath,
                android.content.pm.PackageManager.PackageInfoFlags.of(
                    android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                ),
            )
        } else {
            pm.getPackageArchiveInfo(
                file.absolutePath,
                android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES,
            )
        }
        val signingInfo = info?.signingInfo
        val signers = signingInfo?.apkContentsSigners
        val cert = if (signers != null && signers.isNotEmpty()) signers[0]
            else signingInfo?.signingCertificateHistory?.firstOrNull()
        cert?.toByteArray()
    } else {
        // API 26/27: the deprecated signatures array is the only route.
        @Suppress("DEPRECATION")
        val info = pm.getPackageArchiveInfo(
            file.absolutePath,
            android.content.pm.PackageManager.GET_SIGNATURES,
        )
        @Suppress("DEPRECATION")
        info?.signatures?.firstOrNull()?.toByteArray()
    }
    certBytes ?: return null
    return java.security.MessageDigest.getInstance("SHA-256")
        .digest(certBytes)
        .joinToString("") { "%02x".format(it) }
}


// ---------------------------------------------------------------------------
// Update dialog — the themed design built for Anvex's update popup (dark
// glassy card, glowing download glyph, current → new version card, asset
// chip, gradient progress bar with byte counter, and living color: the
// glow and border breathe and a shimmer sweeps the bar while
// downloading), restyled to the iFoxy palette and type. The controller
// and its state machine above are unchanged — only the presentation
// moved off the plain AlertDialog. Colors are explicit (always dark)
// so the popup looks the same on light and dark system themes.
// ---------------------------------------------------------------------------

private val UpdateCardBg = Color(0xFF22232B)
private val UpdateGlass = Color.White.copy(alpha = 0.08f)
private val UpdateSubtitle = Color.White.copy(alpha = 0.65f)
private val UpdateLabel = Color.White.copy(alpha = 0.55f)
private val UpdateFileText = Color.White.copy(alpha = 0.85f)
private val UpdateTrack = Color.White.copy(alpha = 0.12f)

@Composable
fun AppUpdateDialog(controller: AppUpdateController) {
    if (!controller.dialogVisible) return
    val context = LocalContext.current
    val state = controller.state
    val info = when (state) {
        is UpdateUiState.Available -> state.info
        is UpdateUiState.Downloading -> state.info
        is UpdateUiState.ReadyToInstall -> state.info
        else -> null
    }
    if (info == null && state !is UpdateUiState.Failed) return

    // Living color: a breathing glow, a breathing border, and a shimmer
    // that sweeps the progress bar while downloading. One infinite
    // transition drives all of them; it only runs while the dialog is
    // composed, so nothing animates after dismissal.
    val motion = rememberInfiniteTransition(label = "update-motion")
    val glowPulse by motion.animateFloat(
        initialValue = 0.30f,
        targetValue = 0.60f,
        animationSpec = infiniteRepeatable(tween(1800), RepeatMode.Reverse),
        label = "glow-pulse",
    )
    val borderPulse by motion.animateFloat(
        initialValue = 0.45f,
        targetValue = 0.80f,
        animationSpec = infiniteRepeatable(tween(2400), RepeatMode.Reverse),
        label = "border-pulse",
    )
    val shimmerPhase by motion.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Restart),
        label = "shimmer-phase",
    )

    Dialog(
        onDismissRequest = { controller.dismissDialog() },
        properties = DialogProperties(
            dismissOnBackPress = true,
            dismissOnClickOutside = true,
        ),
    ) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = UpdateCardBg,
            border = BorderStroke(1.dp, IFoxyNeonOrange.copy(alpha = borderPulse)),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                // Cap the height and scroll the content: on short
                // viewports (landscape, split-screen) an unbounded
                // column pushed the action buttons off-screen.
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 560.dp)
                    .verticalScroll(rememberScrollState())
                    .padding(28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                // Glowing download glyph over a soft orange radial glow.
                Box(contentAlignment = Alignment.Center) {
                    Box(
                        Modifier.size(84.dp).clip(CircleShape).background(
                            Brush.radialGradient(
                                listOf(
                                    IFoxyNeonOrange.copy(alpha = glowPulse),
                                    Color.Transparent,
                                ),
                            ),
                        ),
                    )
                    Box(
                        Modifier
                            .size(64.dp)
                            .clip(RoundedCornerShape(18.dp))
                            .background(UpdateCardBg)
                            .border(1.5.dp, IFoxyNeonOrange, RoundedCornerShape(18.dp)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            Icons.Filled.ArrowDownward,
                            contentDescription = null,
                            tint = if (state is UpdateUiState.Failed) IFoxyErrorOnDark else IFoxyYellow,
                            modifier = Modifier.size(30.dp),
                        )
                    }
                }
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        when (state) {
                            is UpdateUiState.Downloading -> "Downloading update"
                            is UpdateUiState.ReadyToInstall -> "Ready to install"
                            is UpdateUiState.Failed -> "Update failed"
                            else -> "Update available"
                        },
                        color = Color.White,
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = PoppinsFamily,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        when (state) {
                            is UpdateUiState.ReadyToInstall -> "The new version has been downloaded"
                            is UpdateUiState.Failed -> "Something went wrong while updating"
                            else -> "A new version is ready"
                        },
                        color = UpdateSubtitle,
                        fontSize = 14.sp,
                        fontFamily = PoppinsFamily,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (info != null) {
                    // Current → new version card.
                    Surface(
                        shape = RoundedCornerShape(20.dp),
                        color = UpdateGlass,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            UpdateVersionCell("Current", "v${BuildConfig.VERSION_NAME}", Color.White)
                            Icon(
                                Icons.Filled.ArrowForward,
                                contentDescription = null,
                                tint = IFoxyNeonOrange,
                                modifier = Modifier.size(28.dp),
                            )
                            UpdateVersionCell("New", "v${info.version}", IFoxyYellow)
                        }
                    }
                    // Asset chip: package glyph + file name + size.
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = UpdateGlass,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(
                            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Icon(
                                Icons.Filled.Archive,
                                contentDescription = null,
                                tint = UpdateLabel,
                                modifier = Modifier.size(20.dp),
                            )
                            Text(
                                "${info.assetName} · ${formatBytes(info.sizeBytes)}",
                                color = UpdateFileText,
                                fontSize = 13.5.sp,
                                fontFamily = PoppinsFamily,
                            )
                        }
                    }
                    // The expected hash, so it can be compared against
                    // the release page out-of-band. Rendered in fixed
                    // 16-character chunks, one per line: the full 64-char
                    // digest is wider than the dialog and would otherwise
                    // wrap mid-hash, which makes visual comparison hard.
                    info.sha256?.let { sha ->
                        Column(Modifier.fillMaxWidth()) {
                            Text(
                                "SHA-256:",
                                color = UpdateLabel,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                            )
                            sha.chunked(16).forEach { chunk ->
                                Text(
                                    chunk,
                                    color = UpdateLabel,
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                )
                            }
                        }
                    }
                }
                if (state is UpdateUiState.Downloading) {
                    val total = if (state.total > 0) state.total else info!!.sizeBytes
                    val fraction = if (total > 0) {
                        (state.downloaded.toFloat() / total).coerceIn(0f, 1f)
                    } else {
                        0f
                    }
                    val percent = (fraction * 100).toInt()
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Text(
                            "Downloading… $percent%",
                            color = Color.White,
                            fontSize = 15.sp,
                            fontFamily = PoppinsFamily,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        BoxWithConstraints(
                            modifier = Modifier
                                .fillMaxWidth()
                                .semantics {
                                    progressBarRangeInfo =
                                        ProgressBarRangeInfo(fraction, 0f..1f)
                                },
                        ) {
                            val barWidth = maxWidth
                            Box(
                                modifier = Modifier.fillMaxWidth(),
                                contentAlignment = Alignment.CenterStart,
                            ) {
                                Box(
                                    Modifier.fillMaxWidth().height(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(UpdateTrack),
                                )
                                Box(
                                    Modifier.fillMaxWidth(fraction).height(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(
                                            Brush.horizontalGradient(
                                                listOf(IFoxyNeonOrange, IFoxyYellow),
                                            ),
                                        ),
                                )
                                // Shimmer band sweeping across the bar,
                                // clipped to the bar's own rounded shape.
                                Box(
                                    Modifier.fillMaxWidth().height(8.dp)
                                        .clip(RoundedCornerShape(4.dp)),
                                ) {
                                    val bandWidth = barWidth * 0.35f
                                    val bandX = barWidth * (shimmerPhase * 1.4f - 0.2f)
                                    Box(
                                        Modifier.offset(x = bandX).size(bandWidth, 8.dp)
                                            .background(
                                                Brush.horizontalGradient(
                                                    listOf(
                                                        Color.Transparent,
                                                        Color.White.copy(alpha = 0.35f),
                                                        Color.Transparent,
                                                    ),
                                                ),
                                            ),
                                    )
                                }
                            }
                            // Pulsing head dot riding the fill's end. It
                            // lives outside the clipped bar so it stays
                            // round instead of being cut to bar height.
                            Box(
                                Modifier.fillMaxWidth(fraction).height(8.dp),
                                contentAlignment = Alignment.CenterEnd,
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Box(
                                        Modifier.size(16.dp).clip(CircleShape)
                                            .background(
                                                IFoxyNeonOrange.copy(alpha = glowPulse),
                                            ),
                                    )
                                    Box(
                                        Modifier.size(10.dp).clip(CircleShape)
                                            .background(Color.White),
                                    )
                                }
                            }
                        }
                        Text(
                            "${formatBytes(state.downloaded)} / ${formatBytes(total)}",
                            color = UpdateLabel,
                            fontSize = 13.5.sp,
                            fontFamily = PoppinsFamily,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
                if (state is UpdateUiState.Failed) {
                    Text(
                        state.message,
                        color = IFoxyErrorOnDark,
                        fontSize = 13.5.sp,
                        fontFamily = PoppinsFamily,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    when (state) {
                        is UpdateUiState.Available -> {
                            TextButton(
                                onClick = { controller.dismissDialog() },
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("Later", color = UpdateLabel, fontFamily = PoppinsFamily)
                            }
                            UpdateGradientButton("Download update") {
                                controller.startDownload()
                            }
                        }
                        is UpdateUiState.Downloading -> {
                            TextButton(
                                onClick = { controller.dismissDialog() },
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("Background", color = UpdateLabel, fontFamily = PoppinsFamily)
                            }
                            Button(
                                onClick = { controller.cancelDownload() },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = IFoxyYellow,
                                    contentColor = IFoxyInk,
                                ),
                                shape = RoundedCornerShape(50),
                                contentPadding = PaddingValues(horizontal = 24.dp, vertical = 12.dp),
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text(
                                    "Cancel",
                                    fontWeight = FontWeight.SemiBold,
                                    fontFamily = PoppinsFamily,
                                )
                            }
                        }
                        is UpdateUiState.ReadyToInstall -> {
                            TextButton(
                                onClick = { controller.dismissDialog() },
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("Later", color = UpdateLabel, fontFamily = PoppinsFamily)
                            }
                            UpdateGradientButton("Install") {
                                controller.install(context)
                            }
                        }
                        is UpdateUiState.Failed -> {
                            TextButton(
                                onClick = { controller.dismissDialog() },
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("OK", color = UpdateLabel, fontFamily = PoppinsFamily)
                            }
                        }
                        else -> {}
                    }
                }
            }
        }
    }
}

@Composable
private fun UpdateVersionCell(label: String, version: String, versionColor: Color) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            label.uppercase(),
            color = UpdateLabel,
            fontSize = 11.5.sp,
            fontFamily = PoppinsFamily,
        )
        Text(
            version,
            color = versionColor,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = PoppinsFamily,
        )
    }
}

@Composable
private fun UpdateGradientButton(text: String, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.Transparent,
            contentColor = IFoxyInk,
        ),
        shape = RoundedCornerShape(50),
        contentPadding = PaddingValues(horizontal = 24.dp, vertical = 12.dp),
        modifier = Modifier
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(50))
            .background(
                Brush.horizontalGradient(listOf(IFoxyNeonOrange, IFoxyYellow)),
            ),
    ) {
        Text(text, fontWeight = FontWeight.SemiBold, fontFamily = PoppinsFamily)
    }
}
