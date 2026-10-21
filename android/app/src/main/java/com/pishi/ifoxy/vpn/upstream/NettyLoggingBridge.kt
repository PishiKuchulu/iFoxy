package com.pishi.ifoxy.vpn.upstream

import com.pishi.ifoxy.data.AppLogger
import io.netty.util.internal.logging.AbstractInternalLogger
import io.netty.util.internal.logging.InternalLogger
import io.netty.util.internal.logging.InternalLoggerFactory

object NettyLoggingBridge {
    private const val TAG = "Netty"

    // SEC-FX-12: the old pattern only caught "Bearer <token>" with a narrow
    // charset. Netty frame/header logs can also carry proxy-authorization
    // headers in other shapes, cookies, and JSON token fields — redact all of
    // them before anything reaches the (user-shareable) in-app log.
    private val BEARER_TOKEN_PATTERN = Regex("Bearer\\s+\\S+", RegexOption.IGNORE_CASE)
    private val AUTH_HEADER_PATTERN =
        Regex("((?:proxy-)?authorization\\s*[:=]\\s*)\\S+(?:\\s+\\S+)?", RegexOption.IGNORE_CASE)
    private val COOKIE_HEADER_PATTERN =
        Regex("((?:set-)?cookie\\s*[:=]\\s*)[^\\s;]+", RegexOption.IGNORE_CASE)
    private val JSON_TOKEN_FIELD_PATTERN =
        Regex("(\"(?:access_token|refresh_token|sessionToken|session_token|token)\"\\s*:\\s*\")[^\"]*\"", RegexOption.IGNORE_CASE)

    internal fun redactSecrets(message: String): String {
        var out = message
        out = BEARER_TOKEN_PATTERN.replace(out, "Bearer <redacted>")
        out = AUTH_HEADER_PATTERN.replace(out, "$1<redacted>")
        out = COOKIE_HEADER_PATTERN.replace(out, "$1<redacted>")
        out = JSON_TOKEN_FIELD_PATTERN.replace(out, "$1<redacted>\"")
        return out
    }

    fun install() {
        InternalLoggerFactory.setDefaultFactory(Factory)
    }

    private object Factory : InternalLoggerFactory() {
        override fun newInstance(name: String): InternalLogger = BridgedLogger(name)
    }

    private class BridgedLogger(loggerName: String) : AbstractInternalLogger(loggerName) {
        private val shortTag = "$TAG/${loggerName.substringAfterLast('.')}"

        override fun isTraceEnabled() = false
        override fun isDebugEnabled() = false
        override fun isInfoEnabled() = false
        override fun isWarnEnabled() = true
        override fun isErrorEnabled() = true

        override fun trace(msg: String) = AppLogger.d(shortTag, redactSecrets(msg))
        override fun trace(format: String, arg: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, arg)))
        override fun trace(format: String, argA: Any?, argB: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, argA, argB)))
        override fun trace(format: String, vararg arguments: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, *arguments)))
        override fun trace(msg: String, t: Throwable?) = AppLogger.d(shortTag, redactSecrets(withCause(msg, t)))

        override fun debug(msg: String) = AppLogger.d(shortTag, redactSecrets(msg))
        override fun debug(format: String, arg: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, arg)))
        override fun debug(format: String, argA: Any?, argB: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, argA, argB)))
        override fun debug(format: String, vararg arguments: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, *arguments)))
        override fun debug(msg: String, t: Throwable?) = AppLogger.d(shortTag, redactSecrets(withCause(msg, t)))

        override fun info(msg: String) = AppLogger.d(shortTag, redactSecrets(msg))
        override fun info(format: String, arg: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, arg)))
        override fun info(format: String, argA: Any?, argB: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, argA, argB)))
        override fun info(format: String, vararg arguments: Any?) = AppLogger.d(shortTag, redactSecrets(format(format, *arguments)))
        override fun info(msg: String, t: Throwable?) = AppLogger.d(shortTag, redactSecrets(withCause(msg, t)))

        override fun warn(msg: String) = AppLogger.w(shortTag, redactSecrets(msg))
        override fun warn(format: String, arg: Any?) = AppLogger.w(shortTag, redactSecrets(format(format, arg)))
        override fun warn(format: String, argA: Any?, argB: Any?) = AppLogger.w(shortTag, redactSecrets(format(format, argA, argB)))
        override fun warn(format: String, vararg arguments: Any?) = AppLogger.w(shortTag, redactSecrets(format(format, *arguments)))
        override fun warn(msg: String, t: Throwable?) = AppLogger.w(shortTag, redactSecrets(msg), t)

        override fun error(msg: String) = AppLogger.e(shortTag, redactSecrets(msg))
        override fun error(format: String, arg: Any?) = AppLogger.e(shortTag, redactSecrets(format(format, arg)))
        override fun error(format: String, argA: Any?, argB: Any?) = AppLogger.e(shortTag, redactSecrets(format(format, argA, argB)))
        override fun error(format: String, vararg arguments: Any?) = AppLogger.e(shortTag, redactSecrets(format(format, *arguments)))
        override fun error(msg: String, t: Throwable?) = AppLogger.e(shortTag, redactSecrets(msg), t)

        private fun withCause(msg: String, t: Throwable?): String =
            if (t != null) "$msg: ${t.message}" else msg

        private fun format(fmt: String, vararg args: Any?): String {
            if (args.isEmpty()) return fmt
            val builder = StringBuilder(fmt.length + 16)
            var argIndex = 0
            var i = 0
            while (i < fmt.length) {
                if (i < fmt.length - 1 && fmt[i] == '{' && fmt[i + 1] == '}' && argIndex < args.size) {
                    builder.append(args[argIndex])
                    argIndex++
                    i += 2
                } else {
                    builder.append(fmt[i])
                    i++
                }
            }
            return builder.toString()
        }
    }
}
