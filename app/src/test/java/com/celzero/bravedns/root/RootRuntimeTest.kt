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

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Exercises [RootRuntime] end to end against a recording [CommandRunner], including the
 * failure paths — a root shell that starts failing half-way through must never leave the
 * runtime believing the kernel matches reality.
 */
class RootRuntimeTest {

    private class FakeRunner(
        /** uid -> response for `id` run as root; null means "no root granted". */
        var grantsRoot: Boolean = true,
        var suAvailable: Boolean = true,
        /** Scripted failures, keyed by the substring that triggers them. */
        var failOn: String? = null,
        /** Extra output returned by counter reads. */
        var counterOutput: String = "",
    ) : CommandRunner {
        val commands = mutableListOf<Pair<String, Boolean>>()

        override fun run(command: String, asRoot: Boolean, timeoutMs: Long): ShellResult {
            commands += command to asRoot
            if (failOn != null && command.contains(failOn!!)) {
                return ShellResult(1, "", "injected failure")
            }
            return when {
                !asRoot && command.contains("command -v su") ->
                    if (suAvailable) ShellResult(0, "/system/xbin/su", "") else ShellResult(1, "", "")
                asRoot && command.trim() == "id" ->
                    if (grantsRoot) ShellResult(0, "uid=0(root) gid=0(root)", "")
                    else ShellResult(1, "", "not allowed")
                asRoot && command.contains("-L") -> ShellResult(0, counterOutput, "")
                else -> ShellResult(0, "", "")
            }
        }
    }

    private lateinit var runner: FakeRunner
    private val logs = mutableListOf<String>()
    private lateinit var runtime: RootRuntime

    @Before
    fun setUp() {
        runner = FakeRunner()
        logs.clear()
        PowerGovernor.reset()
        runtime = RootRuntime(runner, log = { logs += it })
    }

    @After
    fun tearDown() {
        PowerGovernor.reset()
    }

    // ── activation ──────────────────────────────────────────────────────────────

    @Test
    fun `activate succeeds when root is granted and selects the root profile`() {
        assertTrue(runtime.activate())
        assertTrue(runtime.isEngaged)
        assertEquals("root", PowerGovernor.current.name)
        assertEquals(RootState.GRANTED, runtime.detector.state())
    }

    @Test
    fun `activate falls back to the vpn profile when su is missing`() {
        runner.suAvailable = false
        assertFalse(runtime.activate())
        assertFalse(runtime.isEngaged)
        assertEquals("vpn", PowerGovernor.current.name)
        assertEquals(RootState.UNAVAILABLE, runtime.detector.state())
    }

    @Test
    fun `activate falls back when su exists but refuses to elevate`() {
        runner.grantsRoot = false
        assertFalse(runtime.activate())
        assertFalse(runtime.isEngaged)
        assertEquals(RootState.DENIED, runtime.detector.state())
        assertEquals("vpn", PowerGovernor.current.name)
    }

    @Test
    fun `activate installs the hook on both address families`() {
        assertTrue(runtime.activate())
        val rootCommands = runner.commands.filter { it.second }.map { it.first }
        assertTrue(rootCommands.any { it.contains("iptables -w -N RETHINK_OUT") })
        assertTrue(rootCommands.any { it.contains("ip6tables -w -N RETHINK_OUT") })
        assertTrue(rootCommands.any { it.contains("-I OUTPUT 1 -j RETHINK_OUT") })
    }

    @Test
    fun `activate fails without side effects when the hook cannot be installed`() {
        runner.failOn = "-I OUTPUT 1"
        assertFalse(runtime.activate())
        assertFalse(runtime.isEngaged)
        assertEquals("vpn", PowerGovernor.current.name)
    }

    @Test
    fun `activate is idempotent`() {
        assertTrue(runtime.activate())
        val before = runner.commands.size
        assertTrue(runtime.activate())
        assertEquals("second activate must not shell out", before, runner.commands.size)
    }

    @Test
    fun `activate flushes rules left behind by a process that died without teardown`() {
        assertTrue(runtime.activate())
        val hookCommand = runner.commands.first { it.second && it.first.contains("RETHINK_OUT") }.first
        assertTrue(hookCommand.contains("iptables -w -F RETHINK_OUT"))
        assertTrue(hookCommand.contains("ip6tables -w -F RETHINK_OUT"))
        // and it must happen before any per-uid rule is (re)added
        assertEquals(setOf<Int>(), runtime.installedUids())
    }

    // ── sync ────────────────────────────────────────────────────────────────────

    @Test
    fun `sync programs only the diff`() {
        assertTrue(runtime.activate())
        val afterActivate = runner.commands.size

        assertTrue(runtime.sync(setOf(10001, 10002)))
        assertEquals(setOf(10001, 10002), runtime.installedUids())

        val syncCommands = runner.commands.drop(afterActivate).map { it.first }
        assertTrue(syncCommands.any { it.contains("--uid-owner 10001") })
        assertTrue(syncCommands.any { it.contains("--uid-owner 10002") })
        assertFalse("the hook must not be re-installed", syncCommands.any { it.contains("-I OUTPUT 1") })

        val afterFirstSync = runner.commands.size
        assertTrue(runtime.sync(setOf(10001, 10002)))
        assertEquals("no-op sync must not shell out", afterFirstSync, runner.commands.size)
    }

    @Test
    fun `sync removes rules for uids that are no longer denied`() {
        assertTrue(runtime.activate())
        assertTrue(runtime.sync(setOf(10001, 10002)))

        val before = runner.commands.size
        assertTrue(runtime.sync(setOf(10002)))
        val removal = runner.commands.drop(before).map { it.first }
        assertTrue(removal.any { it.contains("-D RETHINK_OUT -m owner --uid-owner 10001") })
        assertFalse(removal.any { it.contains("--uid-owner 10002 -j DROP") && it.contains("-A ") })
        assertEquals(setOf(10002), runtime.installedUids())
    }

    @Test
    fun `sync to an empty set clears the whole chain`() {
        assertTrue(runtime.activate())
        assertTrue(runtime.sync(setOf(10001, 10002, 10003)))
        assertTrue(runtime.sync(emptySet()))
        assertTrue(runtime.installedUids().isEmpty())
    }

    @Test
    fun `sync reports failure and keeps the previous state when the shell fails`() {
        assertTrue(runtime.activate())
        assertTrue(runtime.sync(setOf(10001)))

        runner.failOn = "-A RETHINK_OUT"
        assertFalse(runtime.sync(setOf(10001, 10002)))
        assertEquals(
            "must not claim the new uid was programmed",
            setOf(10001),
            runtime.installedUids(),
        )
        assertTrue(logs.any { it.contains("sync failed") })
    }

    @Test
    fun `sync before activation refuses instead of shelling out`() {
        assertFalse(runtime.sync(setOf(10001)))
        assertTrue(runner.commands.none { it.first.contains("RETHINK_OUT") && it.second })
    }

    @Test
    fun `sync recovers after a transient failure`() {
        assertTrue(runtime.activate())
        runner.failOn = "-A RETHINK_OUT"
        assertFalse(runtime.sync(setOf(10001)))

        runner.failOn = null
        assertTrue(runtime.sync(setOf(10001)))
        assertEquals(setOf(10001), runtime.installedUids())
    }

    // ── counters ────────────────────────────────────────────────────────────────

    @Test
    fun `counters merges both families`() {
        runner.counterOutput = " 5 10 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 10001"
        assertTrue(runtime.activate())

        val counters = runtime.counters()
        // two binaries each returning the same line => doubled
        assertEquals(10L, counters[10001])
    }

    @Test
    fun `counters is empty when not engaged`() {
        assertTrue(runtime.counters().isEmpty())
        assertTrue(runner.commands.isEmpty())
    }

    @Test
    fun `counters tolerates a failing shell`() {
        assertTrue(runtime.activate())
        runner.failOn = "-L"
        assertTrue(runtime.counters().isEmpty())
    }

    // ── teardown ────────────────────────────────────────────────────────────────

    @Test
    fun `deactivate removes the chain and restores the vpn profile`() {
        assertTrue(runtime.activate())
        assertTrue(runtime.sync(setOf(10001)))

        assertTrue(runtime.deactivate())
        assertFalse(runtime.isEngaged)
        assertTrue(runtime.installedUids().isEmpty())
        assertEquals("vpn", PowerGovernor.current.name)

        val teardown = runner.commands.last().first
        assertTrue(teardown.contains("-D OUTPUT -j RETHINK_OUT"))
        assertTrue(teardown.contains("-F RETHINK_OUT"))
        assertTrue(teardown.contains("-X RETHINK_OUT"))
        assertTrue(teardown.contains("ip6tables"))
    }

    @Test
    fun `deactivate is idempotent and safe when nothing was engaged`() {
        assertTrue(runtime.deactivate())
        assertFalse(runtime.isEngaged)
        // after a real activation
        assertTrue(runtime.activate())
        assertTrue(runtime.deactivate())
        assertTrue(runtime.deactivate())
    }

    @Test
    fun `deactivate reports failure when the shell refuses`() {
        assertTrue(runtime.activate())
        runner.failOn = "-X RETHINK_OUT"
        assertFalse(runtime.deactivate())
        assertTrue("must stay engaged so a retry can happen", runtime.isEngaged)
    }

    @Test
    fun `reactivation after deactivate reinstalls everything`() {
        assertTrue(runtime.activate())
        assertTrue(runtime.sync(setOf(10001)))
        assertTrue(runtime.deactivate())

        val before = runner.commands.size
        assertTrue(runtime.activate())
        assertEquals(setOf<Int>(), runtime.installedUids())
        assertTrue(runtime.sync(setOf(10002)))
        assertEquals(setOf(10002), runtime.installedUids())
        assertTrue(runner.commands.size > before)
    }
}
