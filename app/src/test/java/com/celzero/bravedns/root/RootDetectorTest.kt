/*
 * Copyright 2026 RethinkDNS and its authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celzero.bravedns.root

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootDetectorTest {

    private class FakeRunner(
        var suAvailable: Boolean = true,
        var grantsRoot: Boolean = true,
    ) : CommandRunner {
        var probes = 0
            private set

        override fun run(command: String, asRoot: Boolean, timeoutMs: Long): ShellResult {
            return when {
                !asRoot && command.contains("command -v su") -> {
                    probes++
                    if (suAvailable) ShellResult(0, "/system/xbin/su", "") else ShellResult(1, "", "")
                }
                asRoot && command.trim() == "id" -> {
                    probes++
                    if (grantsRoot) ShellResult(0, "uid=0(root) gid=0(root) groups=0(root)", "")
                    else ShellResult(1, "", "permission denied")
                }
                else -> ShellResult(1, "", "unexpected: $command")
            }
        }
    }

    private var now = 1_000L
    private val clock: () -> Long = { now }

    @Test
    fun `reports unknown before the first probe`() {
        val d = RootDetector(FakeRunner(), clock)
        assertEquals(RootState.UNKNOWN, d.state())
    }

    @Test
    fun `reports granted for a uid 0 id`() {
        val d = RootDetector(FakeRunner(), clock)
        assertTrue(d.isGranted())
        assertEquals(RootState.GRANTED, d.state())
    }

    @Test
    fun `reports denied when su refuses to elevate`() {
        val d = RootDetector(FakeRunner(grantsRoot = false), clock)
        assertFalse(d.isGranted())
        assertEquals(RootState.DENIED, d.state())
    }

    @Test
    fun `reports unavailable when su is not on path`() {
        val d = RootDetector(FakeRunner(suAvailable = false), clock)
        assertFalse(d.isGranted())
        assertEquals(RootState.UNAVAILABLE, d.state())
    }

    @Test
    fun `does not treat a non-root id output as granted`() {
        val runner =
            object : CommandRunner {
                var calls = 0
                override fun run(command: String, asRoot: Boolean, timeoutMs: Long): ShellResult {
                    calls++
                    return if (command.contains("command -v su")) ShellResult(0, "/system/xbin/su", "")
                    else ShellResult(0, "uid=2000(shell) gid=2000(shell)", "")
                }
            }
        val d = RootDetector(runner, clock)
        assertFalse(d.isGranted())
        assertEquals(RootState.DENIED, d.state())
    }

    @Test
    fun `a successful probe is cached until the grant ttl expires`() {
        val runner = FakeRunner()
        val d = RootDetector(runner, clock)

        assertTrue(d.isGranted())
        assertEquals(2, runner.probes)

        now += RootDetector.GRANT_TTL_MS - 1
        assertTrue(d.isGranted())
        assertEquals("still inside the TTL", 2, runner.probes)

        now += 1
        assertTrue(d.isGranted())
        assertEquals("TTL expired => re-probe", 4, runner.probes)
    }

    @Test
    fun `a denial is cached for longer than a grant`() {
        val runner = FakeRunner(grantsRoot = false)
        val d = RootDetector(runner, clock)

        assertFalse(d.isGranted())
        val first = runner.probes

        now += RootDetector.GRANT_TTL_MS
        assertFalse("deny TTL outlasts the grant TTL", d.isGranted())
        assertEquals("still inside the deny TTL", first, runner.probes)

        now += RootDetector.DENY_TTL_MS - RootDetector.GRANT_TTL_MS + 1
        assertFalse(d.isGranted())
        assertTrue("TTL expired => re-probe", runner.probes > first)
    }

    @Test
    fun `force bypasses the cache`() {
        val runner = FakeRunner()
        val d = RootDetector(runner, clock)
        assertTrue(d.isGranted())
        val before = runner.probes
        assertTrue(d.isGranted(force = true))
        assertTrue(runner.probes > before)
    }

    @Test
    fun `a probe can recover from denied to granted`() {
        val runner = FakeRunner(grantsRoot = false)
        val d = RootDetector(runner, clock)
        assertFalse(d.isGranted())

        runner.grantsRoot = true
        now += RootDetector.DENY_TTL_MS + 1
        assertTrue(d.isGranted())
        assertEquals(RootState.GRANTED, d.state())
    }

    @Test
    fun `denial ttl is longer than grant ttl`() {
        assertTrue(RootDetector.DENY_TTL_MS > RootDetector.GRANT_TTL_MS)
    }
}
