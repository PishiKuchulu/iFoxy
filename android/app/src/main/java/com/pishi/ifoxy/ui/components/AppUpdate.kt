package com.pishi.ifoxy.ui.components

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.pishi.ifoxy.BuildConfig
import com.pishi.ifoxy.data.formatBytes
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
            val found = runCatching { AppUpdateChecker.findUpdate(BuildConfig.VERSION_NAME) }
                .getOrNull()
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
                    downloadApk(info) { downloaded, total ->
                        state = UpdateUiState.Downloading(info, downloaded, total)
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
        // (external review, A6). Android's package manager would still
        // enforce the signing certificate afterwards; the checksum is
        // what catches a corrupted or substituted download first.
        val expected = info.sha256
        if (expected != null) {
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
        }
        val target = File(dir, info.assetName)
        if (target.exists()) target.delete()
        check(part.renameTo(target)) { "Could not finalize the downloaded APK" }
        return target
    }
}

@Composable
fun AppUpdateDialog(controller: AppUpdateController) {
    if (!controller.dialogVisible) return
    val context = LocalContext.current
    when (val state = controller.state) {
        is UpdateUiState.Available -> AlertDialog(
            onDismissRequest = { controller.dismissDialog() },
            title = { Text("Update available") },
            text = {
                Text(
                    "iFoxy v${state.info.version} is available — you have " +
                        "v${BuildConfig.VERSION_NAME}.\n\n" +
                        "Download size: ${formatBytes(state.info.sizeBytes)}",
                )
            },
            confirmButton = {
                TextButton(onClick = { controller.startDownload() }) { Text("Download") }
            },
            dismissButton = {
                TextButton(onClick = { controller.dismissDialog() }) { Text("Later") }
            },
        )

        is UpdateUiState.Downloading -> {
            val fraction = if (state.total > 0) {
                (state.downloaded.toFloat() / state.total.toFloat()).coerceIn(0f, 1f)
            } else {
                0f
            }
            AlertDialog(
                onDismissRequest = { controller.dismissDialog() },
                title = { Text("Downloading update") },
                text = {
                    Column {
                        LinearProgressIndicator(progress = { fraction })
                        Spacer(Modifier.height(8.dp))
                        Text("${formatBytes(state.downloaded)} / ${formatBytes(state.total)}")
                    }
                },
                confirmButton = {
                    TextButton(onClick = { controller.cancelDownload() }) { Text("Cancel") }
                },
                dismissButton = {
                    TextButton(onClick = { controller.dismissDialog() }) { Text("Background") }
                },
            )
        }

        is UpdateUiState.ReadyToInstall -> AlertDialog(
            onDismissRequest = { controller.dismissDialog() },
            title = { Text("Ready to install") },
            text = { Text("iFoxy v${state.info.version} has been downloaded.") },
            confirmButton = {
                TextButton(onClick = { controller.install(context) }) { Text("Install") }
            },
            dismissButton = {
                TextButton(onClick = { controller.dismissDialog() }) { Text("Later") }
            },
        )

        is UpdateUiState.Failed -> AlertDialog(
            onDismissRequest = { controller.dismissDialog() },
            title = { Text("Update failed") },
            text = { Text(state.message) },
            confirmButton = {
                TextButton(onClick = { controller.dismissDialog() }) { Text("OK") }
            },
        )

        else -> Unit
    }
}
