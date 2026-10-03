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

class RootFirewallPlannerTest {

    private val bin = RootFirewallPlanner.IPTABLES

    // ── chain / hook ────────────────────────────────────────────────────────────

    @Test
    fun `ensureHook creates the chain only when missing and inserts the jump once`() {
        val cmd = RootFirewallPlanner.ensureHook(bin)

        assertTrue("must create chain tolerating an existing one", cmd.contains("$bin -w -N ${RootFirewallPlanner.CHAIN}"))
        assertTrue("must guard the jump with -C", cmd.contains("$bin -w -C OUTPUT -j ${RootFirewallPlanner.CHAIN}"))
        assertTrue("must insert at the head when absent", cmd.contains("$bin -w -I OUTPUT 1 -j ${RootFirewallPlanner.CHAIN}"))
        assertFalse("must never use -A for the jump (rules must run before app rules)", cmd.contains("-A OUTPUT"))
    }

    @Test
    fun `removeHook tears down jump, rules and chain and tolerates absence`() {
        val cmd = RootFirewallPlanner.removeHook(bin)

        assertTrue(cmd.contains("$bin -w -D OUTPUT -j ${RootFirewallPlanner.CHAIN}"))
        assertTrue(cmd.contains("$bin -w -F ${RootFirewallPlanner.CHAIN}"))
        assertTrue(cmd.contains("$bin -w -X ${RootFirewallPlanner.CHAIN}"))
        assertTrue("every step must ignore a missing object", cmd.contains("|| true"))
    }

    @Test
    fun `dropUid pins the owner and drops everything`() {
        val cmd = RootFirewallPlanner.dropUid(bin, 10042)
        assertEquals(
            "iptables -w -A RETHINK_OUT -m owner --uid-owner 10042 -j DROP",
            cmd,
        )
    }

    @Test
    fun `undropUid removes the exact rule that dropUid added`() {
        assertEquals(
            RootFirewallPlanner.dropUid(bin, 7).replace(" -A ", " -D "),
            RootFirewallPlanner.undropUid(bin, 7),
        )
    }

    // ── diff ────────────────────────────────────────────────────────────────────

    @Test
    fun `diff of identical sets emits nothing`() {
        val uids = setOf(10001, 10002, 10003)
        assertTrue(RootFirewallPlanner.diff(bin, uids, uids).isEmpty())
    }

    @Test
    fun `diff adds only the new uids and deletes only the removed ones`() {
        val cmds = RootFirewallPlanner.diff(bin, current = setOf(1, 2), desired = setOf(2, 3))

        assertEquals(2, cmds.size)
        assertTrue(cmds.contains(RootFirewallPlanner.dropUid(bin, 3)))
        assertTrue(cmds.contains(RootFirewallPlanner.undropUid(bin, 1)))
        assertFalse("unchanged uid must not be re-programmed", cmds.any { it.contains("--uid-owner 2 ") })
    }

    @Test
    fun `diff never re-emits the hook`() {
        val cmds = RootFirewallPlanner.diff(bin, emptySet(), setOf(5))
        assertTrue(cmds.none { it.contains("-j ${RootFirewallPlanner.CHAIN}") })
    }

    @Test
    fun `diff output is ordered adds before deletes for a stable apply order`() {
        val cmds = RootFirewallPlanner.diff(bin, current = setOf(1), desired = setOf(2))
        assertEquals(listOf(RootFirewallPlanner.dropUid(bin, 2), RootFirewallPlanner.undropUid(bin, 1)), cmds)
    }

    @Test
    fun `install emits hook plus every desired uid`() {
        val cmds = RootFirewallPlanner.install(bin, setOf(10, 20))
        assertEquals(3, cmds.size)
        assertEquals(RootFirewallPlanner.ensureHook(bin), cmds[0])
        assertEquals(RootFirewallPlanner.dropUid(bin, 10), cmds[1])
        assertEquals(RootFirewallPlanner.dropUid(bin, 20), cmds[2])
    }

    @Test
    fun `diff is deterministic regardless of set iteration order`() {
        val a = RootFirewallPlanner.diff(bin, setOf(4, 1, 3, 2), setOf(9, 8, 7))
        val b = RootFirewallPlanner.diff(bin, setOf(1, 2, 3, 4), setOf(7, 8, 9))
        assertEquals(a, b)
        val added =
            a.filter { it.contains(" -A ") }
                .map { it.substringAfterLast("--uid-owner ").substringBefore(" ").toInt() }
                .sorted()
        assertEquals(listOf(7, 8, 9), added)
    }

    // ── counters ────────────────────────────────────────────────────────────────

    @Test
    fun `parseCounters reads packets per owner uid`() {
        val out = """
            Chain RETHINK_OUT (1 references)
             pkts bytes target     prot opt in out source destination
              123 56789 DROP       all  --  *  *   0.0.0.0/0            0.0.0.0/0            owner UID match 10042
                0     0 DROP       all  --  *  *   0.0.0.0/0            0.0.0.0/0            owner UID match 10000
            65536 1048576 DROP     all  --  *  *   0.0.0.0/0            0.0.0.0/0            owner UID match 10100
        """.trimIndent()

        val parsed = RootFirewallPlanner.parseCounters(out)

        assertEquals(3, parsed.size)
        assertEquals(123L, parsed[10042])
        assertEquals(0L, parsed[10000])
        assertEquals(65536L, parsed[10100])
        assertTrue("header must not be parsed as a uid", parsed.keys.none { it == 1 })
    }

    @Test
    fun `parseCounters ignores lines without an owner match`() {
        val out = """
            Chain RETHINK_OUT (1 references)
             pkts bytes target prot opt in out source destination
               42  999 ACCEPT all  --  *  *   0.0.0.0/0            0.0.0.0/0
        """.trimIndent()

        assertTrue(RootFirewallPlanner.parseCounters(out).isEmpty())
        assertTrue(RootFirewallPlanner.parseCounters("").isEmpty())
        assertTrue(RootFirewallPlanner.parseCounters("garbage").isEmpty())
    }

    @Test
    fun `parseCounters tolerates trailing text after the uid`() {
        val out = " 7 88 DROP all -- * * ::/0 ::/0 owner UID match 1007"
        val parsed = RootFirewallPlanner.parseCounters(out)
        assertEquals(setOf(1007), parsed.keys)
        assertEquals(7L, parsed[1007])
    }

    @Test
    fun `parseCounters sums repeated rows for the same uid`() {
        val out = """
            5 10 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 1001
            6 11 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 1001
        """.trimIndent()
        assertEquals(11L, RootFirewallPlanner.parseCounters(out)[1001])
    }

    @Test
    fun `readCounters resets in place so every read is a delta`() {
        val cmd = RootFirewallPlanner.readCounters(bin)
        assertTrue(cmd.contains("-Z"))
        assertTrue(cmd.contains("-vnx"))
        assertTrue(cmd.contains(RootFirewallPlanner.CHAIN))
    }

    @Test
    fun `removal script covers both address families`() {
        val cmds = RootFirewallPlanner.removalScript()
        assertEquals(2, cmds.size)
        assertTrue(cmds[0].contains("iptables -w -D OUTPUT"))
        assertTrue(cmds[1].contains("ip6tables -w -D OUTPUT"))
    }

    @Test
    fun `teardown of an absent chain still succeeds`() {
        // the command must be safe to run unconditionally
        val cmd = RootFirewallPlanner.removeHook(bin)
        assertTrue(cmd.lines().all { it.contains("|| true") })
    }

    @Test
    fun `flush empties the chain but keeps the jump`() {
        val cmd = RootFirewallPlanner.flush(bin)
        assertEquals("$bin -w -F ${RootFirewallPlanner.CHAIN} 2>/dev/null || true", cmd)
        assertFalse("flush must not remove the jump", cmd.contains("-D OUTPUT"))
    }

    @Test
    fun `reset hooks the chain and then empties it`() {
        val cmds = RootFirewallPlanner.reset(bin)
        assertEquals(2, cmds.size)
        assertEquals(RootFirewallPlanner.ensureHook(bin), cmds[0])
        assertEquals(RootFirewallPlanner.flush(bin), cmds[1])
    }
}
