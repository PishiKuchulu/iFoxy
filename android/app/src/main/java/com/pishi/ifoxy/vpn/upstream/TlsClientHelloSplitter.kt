package com.pishi.ifoxy.vpn.upstream

import com.pishi.ifoxy.data.SettingsStore
import io.netty.buffer.ByteBuf

object TlsClientHelloSplitter {

    fun looksLikeClientHello(buf: ByteBuf): Boolean {
        if (buf.readableBytes() < 6) return false
        val rIdx = buf.readerIndex()
        return buf.getByte(rIdx) == 0x16.toByte() &&
            buf.getByte(rIdx + 1) == 0x03.toByte() &&
            buf.getByte(rIdx + 5) == 0x01.toByte()
    }

    fun looksLikeClientHello(b: ByteArray, off: Int = 0, len: Int = b.size): Boolean {
        if (len < 6 || off + len > b.size) return false
        return b[off] == 0x16.toByte() &&
            b[off + 1] == 0x03.toByte() &&
            b[off + 5] == 0x01.toByte()
    }

    fun findSniOffset(b: ByteArray): Pair<Int, Int>? {
        if (b.size < 44 || b[0] != 0x16.toByte()) {
            return null
        }
        var curr = 5
        if (b[curr] != 0x01.toByte()) {
            return null
        }
        curr += 4
        curr += 2 + 32
        if (curr >= b.size) return null

        val sessionIdLen = u8(b[curr])
        curr += 1 + sessionIdLen
        if (curr + 2 > b.size) return null

        val cipherSuitesLen = u16(b[curr], b[curr + 1])
        curr += 2 + cipherSuitesLen
        if (curr >= b.size) return null

        val compressionMethodsLen = u8(b[curr])
        curr += 1 + compressionMethodsLen
        if (curr + 2 > b.size) return null

        val extensionsLen = u16(b[curr], b[curr + 1])
        var extEnd = curr + 2 + extensionsLen
        curr += 2
        if (extEnd > b.size) {
            extEnd = b.size
        }

        while (curr + 4 <= extEnd) {
            val extType = u16(b[curr], b[curr + 1])
            val extLen = u16(b[curr + 2], b[curr + 3])
            val body = curr + 4
            if (body + extLen > extEnd) {
                return null
            }
            if (extType == 0) {
                if (extLen < 2) return null
                val listLen = u16(b[body], b[body + 1])
                val list = body + 2
                if (list + listLen > body + extLen) return null
                if (listLen < 3 || b[list] != 0.toByte()) return null
                val nameLen = u16(b[list + 1], b[list + 2])
                val start = list + 3
                val end = start + nameLen
                if (end > list + listLen || end > b.size) return null
                return Pair(start, end)
            }
            curr = body + extLen
        }
        return null
    }

    fun split(buf: ByteBuf, mode: SettingsStore.TlsSplitMode): List<ByteBuf>? {
        val totalLen = buf.readableBytes()
        val rIdx = buf.readerIndex()

        return when (mode) {
            SettingsStore.TlsSplitMode.OFF -> null
            SettingsStore.TlsSplitMode.FIRST_BYTE -> {
                if (totalLen < 2) return null
                listOf(
                    buf.retainedSlice(rIdx, 1),
                    buf.retainedSlice(rIdx + 1, totalLen - 1),
                )
            }
            SettingsStore.TlsSplitMode.SNI -> {
                val bytes = ByteArray(totalLen)
                buf.getBytes(rIdx, bytes)
                val offset = findSniOffset(bytes) ?: return null
                val start = offset.first
                if (start <= 0 || start >= totalLen) return null
                listOf(
                    buf.retainedSlice(rIdx, start),
                    buf.retainedSlice(rIdx + start, 1),
                    buf.retainedSlice(rIdx + start + 1, totalLen - start - 1),
                )
            }
        }
    }

    fun splitBytes(b: ByteArray, off: Int = 0, len: Int = b.size, mode: SettingsStore.TlsSplitMode): List<ByteArray>? {
        if (len < 2 || off + len > b.size) return null
        return when (mode) {
            SettingsStore.TlsSplitMode.OFF -> null
            SettingsStore.TlsSplitMode.FIRST_BYTE -> {
                listOf(
                    b.copyOfRange(off, off + 1),
                    b.copyOfRange(off + 1, off + len),
                )
            }
            SettingsStore.TlsSplitMode.SNI -> {
                val slice = if (off == 0 && len == b.size) b else b.copyOfRange(off, off + len)
                val offset = findSniOffset(slice) ?: return null
                val start = offset.first
                if (start <= 0 || start >= len) return null
                listOf(
                    b.copyOfRange(off, off + start),
                    b.copyOfRange(off + start, off + start + 1),
                    b.copyOfRange(off + start + 1, off + len),
                )
            }
        }
    }

    private fun u8(b: Byte): Int = b.toInt() and 0xFF

    private fun u16(b1: Byte, b2: Byte): Int =
        ((b1.toInt() and 0xFF) shl 8) or (b2.toInt() and 0xFF)
}
