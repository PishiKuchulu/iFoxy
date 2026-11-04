package com.pishi.ifoxy.data

import android.content.Context
import android.os.Build
import com.pishi.ifoxy.BuildConfig
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

object CrashReporter {
    private const val TAG = "CrashReporter"
    private const val CRASH_FILE_NAME = "last_crash.txt"

    fun install(context: Context) {
        val appContext = context.applicationContext
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching { writeCrashFile(appContext, thread, throwable) }

            if (previousHandler != null) {
                previousHandler.uncaughtException(thread, throwable)
            } else {
                Runtime.getRuntime().exit(1)
            }
        }
    }

    fun replayLastCrashIfAny(context: Context) {
        val file = crashFile(context)
        if (!file.exists()) return
        val text = runCatching { file.readText() }.getOrNull()
        runCatching { file.delete() }
        if (text.isNullOrBlank()) return
        AppLogger.e(TAG, "app crashed last run; captured stack trace follows")
        text.lineSequence().forEach { line ->
            if (line.isNotBlank()) AppLogger.e(TAG, line)
        }
    }

    private fun writeCrashFile(context: Context, thread: Thread, throwable: Throwable) {
        val writer = StringWriter()
        PrintWriter(writer).use { pw ->
            // Version + device context first: a trace without the app
            // version forces a guessing round before diagnosis can
            // even start (learned from the 1.0.29 crash report).
            pw.println("App: iFoxy ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            pw.println("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ${Build.MANUFACTURER} ${Build.MODEL}")
            pw.println("Thread: ${thread.name}")
            throwable.printStackTrace(pw)
        }
        crashFile(context).writeText(writer.toString())
    }

    private fun crashFile(context: Context): File = File(context.filesDir, CRASH_FILE_NAME)
}
