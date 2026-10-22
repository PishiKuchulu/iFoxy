package com.pishi.ifoxy.util

/**
 * Pure semantic-version helpers for the in-app updater. Versions are
 * compared numerically per segment (so 1.0.9 < 1.0.10), an optional
 * leading "v" is ignored, and missing segments count as 0.
 */
object VersionNumbers {

    fun parse(version: String): List<Int> =
        version.trim()
            .removePrefix("v")
            .removePrefix("V")
            .split('.')
            .map { segment -> segment.takeWhile { it.isDigit() }.toIntOrNull() ?: 0 }

    fun compare(a: String, b: String): Int {
        val pa = parse(a)
        val pb = parse(b)
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val diff = pa.getOrElse(i) { 0 }.compareTo(pb.getOrElse(i) { 0 })
            if (diff != 0) return diff
        }
        return 0
    }

    fun isNewer(candidate: String, current: String): Boolean = compare(candidate, current) > 0
}
