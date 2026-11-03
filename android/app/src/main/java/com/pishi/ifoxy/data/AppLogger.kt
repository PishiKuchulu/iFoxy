package com.pishi.ifoxy.data

import android.util.Log
import com.pishi.ifoxy.BuildConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

enum class LogLevel { INFO, WARN, ERROR }

data class LogEntry(
    val id: Long,
    val timestampMillis: Long,
    val level: LogLevel,
    val tag: String,
    val message: String,
)

object AppLogger {

    private const val MAX_ENTRIES = 2_000
    private const val MIN_PUBLISH_INTERVAL_MS = 200L

    private val buffer = ConcurrentLinkedDeque<LogEntry>()
    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries

    private val lastPublishAt = AtomicLong(0L)
    private val flushScheduled = AtomicBoolean(false)

    private val scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "AppLogger-flush").apply { isDaemon = true }
    }

    private val timeFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    fun d(tag: String, message: String) {
        // Debug lines carry connection targets (host:port); they must
        // not reach logcat in release builds. The ProGuard
        // -assumenosideeffects rule strips the remaining direct Log.d
        // calls as a second layer.
        if (BuildConfig.DEBUG) Log.d(tag, message)
    }

    // Log lines end up on the clipboard / in shared files via the Logs
    // screen, so email addresses (account identities) are masked at
    // this single choke point before a message is stored or forwarded
    // to logcat: first character of the local part and of the domain
    // survive, e.g. "a***@e***.com". Runs only on messages containing
    // '@', and allocates nothing for the common no-email case.
    private val EMAIL_PATTERN = Regex("""([A-Za-z0-9])[\w.%+-]*@([A-Za-z0-9])[\w.-]*\.([A-Za-z]{2,})""")

    private fun maskEmails(message: String): String {
        if ('@' !in message) return message
        return EMAIL_PATTERN.replace(message) { match ->
            "${match.groupValues[1]}***@${match.groupValues[2]}***.${match.groupValues[3]}"
        }
    }

    fun i(tag: String, message: String) {
        val masked = maskEmails(message)
        Log.i(tag, masked)
        log(LogLevel.INFO, tag, masked)
    }

    fun w(tag: String, message: String, error: Throwable? = null) {
        if (error != null) Log.w(tag, maskEmails(message), error) else Log.w(tag, maskEmails(message))
        log(LogLevel.WARN, tag, maskEmails(if (error != null) "$message: ${error.message}" else message))
    }

    fun e(tag: String, message: String, error: Throwable? = null) {
        if (error != null) Log.e(tag, maskEmails(message), error) else Log.e(tag, maskEmails(message))
        log(LogLevel.ERROR, tag, maskEmails(if (error != null) "$message: ${error.message}" else message))
    }

    private val currentSize = java.util.concurrent.atomic.AtomicInteger(0)

    private val entryCounter = java.util.concurrent.atomic.AtomicLong(0)

    private fun log(level: LogLevel, tag: String, message: String) {
        buffer.addLast(LogEntry(entryCounter.incrementAndGet(), System.currentTimeMillis(), level, tag, message))
        var current = currentSize.incrementAndGet()

        while (current > MAX_ENTRIES) {
            if (buffer.pollFirst() != null) {
                current = currentSize.decrementAndGet()
            } else {
                currentSize.set(0)
                break
            }
        }
        schedulePublish()
    }

    private fun schedulePublish() {
        val now = System.currentTimeMillis()
        val last = lastPublishAt.get()
        if (now - last >= MIN_PUBLISH_INTERVAL_MS) {
            if (lastPublishAt.compareAndSet(last, now)) {
                _entries.value = buffer.toList()
            }
            return
        }
        if (flushScheduled.compareAndSet(false, true)) {
            val delayMs = (MIN_PUBLISH_INTERVAL_MS - (now - last)).coerceAtLeast(0)
            val scheduledOk = runCatching {
                scheduler.schedule({
                    flushScheduled.set(false)
                    lastPublishAt.set(System.currentTimeMillis())
                    _entries.value = buffer.toList()
                }, delayMs, TimeUnit.MILLISECONDS)
            }.isSuccess
            if (!scheduledOk) flushScheduled.set(false)
        }
    }

    fun clear() {
        buffer.clear()
        currentSize.set(0)
        _entries.value = emptyList()
    }

    fun exportAsText(): String = buffer.toList().joinToString("\n") { entry ->
        val ts = timeFormat.format(Date(entry.timestampMillis))
        "$ts ${entry.level.name.padEnd(5)} [${entry.tag}] ${entry.message}"
    }
}
