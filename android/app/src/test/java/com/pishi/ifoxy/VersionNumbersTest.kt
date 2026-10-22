package com.pishi.ifoxy

import com.pishi.ifoxy.util.VersionNumbers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Updater version comparison: numeric per segment, "v" prefix ignored. */
class VersionNumbersTest {

    @Test
    fun `segments compare numerically not lexically`() {
        assertTrue(VersionNumbers.isNewer("1.0.10", "1.0.9"))
        assertTrue(VersionNumbers.isNewer("v1.0.10", "1.0.9"))
        assertFalse(VersionNumbers.isNewer("1.0.9", "1.0.10"))
    }

    @Test
    fun `equal versions are not newer`() {
        assertFalse(VersionNumbers.isNewer("1.0.10", "1.0.10"))
        assertEquals(0, VersionNumbers.compare("v1.0.10", "1.0.10"))
    }

    @Test
    fun `missing segments count as zero`() {
        assertEquals(0, VersionNumbers.compare("1.1", "1.1.0"))
        assertTrue(VersionNumbers.isNewer("1.1.1", "1.1"))
        assertTrue(VersionNumbers.isNewer("2.0", "1.9.9"))
    }

    @Test
    fun `major and minor dominate patch`() {
        assertTrue(VersionNumbers.isNewer("1.1.0", "1.0.99"))
        assertFalse(VersionNumbers.isNewer("0.9.9", "1.0.0"))
    }
}
