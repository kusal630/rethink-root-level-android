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

class RootTunPlannerTest {

    private val addrs = listOf("10.111.222.1/24", "fd66:f83a:c650::1/120")
    private val routes = listOf("0.0.0.0/0", "10.111.222.3/32")

    // ── link ───────────────────────────────────────────────────────────────────

    @Test
    fun `linkSetup brings the interface up and replaces every address`() {
        val cmds = RootTunPlanner.linkSetup(addrs, 1500)

        assertEquals("ip link set dev rtn0 up", cmds[0])
        assertEquals("ip link set dev rtn0 mtu 1500", cmds[1])
        assertTrue("must clear stale addresses first", cmds.contains("ip address flush dev rtn0"))
        assertTrue(cmds.contains("ip address replace 10.111.222.1/24 dev rtn0"))
        assertTrue(cmds.contains("ip -6 address replace fd66:f83a:c650::1/120 dev rtn0"))
    }

    @Test
    fun `interface name fits inside IFNAMSIZ`() {
        assertTrue(RootTunPlanner.IFACE.length < 16)
    }

    // ── routing ────────────────────────────────────────────────────────────────

    @Test
    fun `routeSetup installs builder routes into the private table only`() {
        val cmds = RootTunPlanner.routeSetup(routes, emptyList())

        assertTrue(cmds.any { it.contains("route replace 0.0.0.0/0 dev rtn0 table 50") })
        assertTrue(cmds.any { it.contains("route replace 10.111.222.3/32 dev rtn0 table 50") })
        assertFalse(
            "the main table must stay untouched",
            cmds.any { it.startsWith("ip route replace") && !it.contains("table 50") },
        )
    }

    @Test
    fun `routeSetup flushes both families before installing`() {
        val cmds = RootTunPlanner.routeSetup(routes, emptyList())

        assertTrue(cmds.contains("ip route flush table 50 2>/dev/null || true"))
        assertTrue(cmds.contains("ip -6 route flush table 50 2>/dev/null || true"))
        // flush must precede the first install
        assertTrue(cmds.indexOf(cmds.first { it.contains("flush table 50") }) < cmds.indexOfFirst { it.contains("route replace") })
    }

    @Test
    fun `routeSetup pulls every system resolver into the tunnel`() {
        // this is the addDnsServer() replacement: without a registered VPN the OS keeps
        // pointing at the LAN resolver, so it has to be routed in explicitly
        val cmds = RootTunPlanner.routeSetup(routes, listOf("192.168.1.1", "fe80::1"))

        assertTrue(cmds.any { it.contains("route replace 192.168.1.1/32 dev rtn0 table 50") })
        assertTrue(cmds.any { it.contains("route replace fe80::1/128 dev rtn0 table 50") })
    }

    @Test
    fun `the plan never touches the nat table`() {
        val cmds =
            (RootTunPlanner.linkSetup(addrs, 1500) +
                RootTunPlanner.routeSetup(routes, emptyList()) +
                RootTunPlanner.mangleSetup(10213, emptySet()) +
                RootTunPlanner.teardown())
                .joinToString("\n")

        assertFalse("DNS is routed, never rewritten: $cmds", cmds.contains("-t nat"))
        assertFalse("no DNAT target either", cmds.contains("DNAT"))
    }

    @Test
    fun `policy rule sits above netd but below the local table`() {
        val cmds = RootTunPlanner.routeSetup(routes, emptyList())

        assertTrue(cmds.contains("ip rule add fwmark 0xf0000000/0xf0000000 lookup 50 priority 9000"))
        assertTrue(cmds.contains("ip -6 rule add fwmark 0xf0000000/0xf0000000 lookup 50 priority 9000"))
        // deletes guard against duplicates across restarts
        assertTrue(cmds.any { it.startsWith("ip rule del ") && it.contains("|| true") })
        // 9000 > 0 (local wins for interface addresses) and 9000 < 10000 (we win over netd)
        assertTrue(RootTunPlanner.RULE_PRIO in 1..9999)
    }

    @Test
    fun `mark lives in bits netd never uses`() {
        val mark = RootTunPlanner.MARK
        val masks =
            listOf(
                0xFFFFL, // netid low bits
                0x1FFFFL, // netid + 1
                0xC0000L, // vpn
                0xD0000L, // legacy
                0x1FFFFFL,
            )

        masks.forEach { mask ->
            assertEquals("0x${mask.toString(16)} must not see our mark", 0L, mark and mask)
        }
        assertEquals("top nibble only", mark, 0xF0000000L)
        assertEquals("mask must cover exactly the bits we set", RootTunPlanner.MARK_MASK, mark)
    }

    @Test
    fun `ruleSpec mirrors what ip rule show prints`() {
        assertEquals(
            "9000: from all fwmark 0xf0000000/0xf0000000 lookup 50",
            RootTunPlanner.ruleSpec(),
        )
    }

    // ── mangle (the protect() replacement) ─────────────────────────────────────

    @Test
    fun `mangle returns our own uid before anything is marked`() {
        val cmds = RootTunPlanner.mangleSetup(10213, emptySet())
        val self = cmds.indexOfFirst { it.contains("--uid-owner 10213 -j RETURN") }
        val mark = cmds.indexOfFirst { it.contains("--set-xmark") }

        assertTrue("uid rule missing", self >= 0)
        assertTrue("mark rule missing", mark >= 0)
        assertTrue("own uid must be exempted before the mark is applied", self < mark)
    }

    @Test
    fun `mangle exempts bypassed apps, loopback and the tunnel itself`() {
        val cmds = RootTunPlanner.mangleSetup(10213, setOf(10456, 10457)).joinToString("\n")

        assertTrue(cmds.contains("--uid-owner 10456 -j RETURN"))
        assertTrue(cmds.contains("--uid-owner 10457 -j RETURN"))
        assertTrue(cmds.contains("-o lo -j RETURN"))
        assertTrue(cmds.contains("-o rtn0 -j RETURN"))
        assertTrue(cmds.contains("-m mark --mark 0xf0000000/0xf0000000 -j RETURN"))
    }

    @Test
    fun `mangle exempts our uid only once when it is also a bypass uid`() {
        val selfRule = "--uid-owner 10213 -j RETURN"
        val cmds = RootTunPlanner.mangleSetup(10213, setOf(10213, 10456))

        assertEquals(
            "the builder disallows our own package, which must not repeat the self rule",
            1,
            cmds.count { it.contains(selfRule) }
        )
        assertTrue(cmds.any { it.contains("--uid-owner 10456 -j RETURN") })
    }

    @Test
    fun `mangle chain is created, flushed and jumped from once`() {
        val cmds = RootTunPlanner.mangleSetup(10213, emptySet())

        assertTrue(cmds.contains("iptables -w -t mangle -N RETHINK_MARK 2>/dev/null || true"))
        assertTrue(cmds.contains("iptables -w -t mangle -F RETHINK_MARK"))
        assertTrue(cmds.any { it.contains("-C OUTPUT -j RETHINK_MARK 2>/dev/null || ") && it.contains("-I OUTPUT 1") })
    }

    @Test
    fun `mangleTeardown removes the jump before the chain`() {
        val cmds = RootTunPlanner.mangleTeardown()

        assertTrue(cmds[0].contains("-D OUTPUT -j RETHINK_MARK"))
        assertTrue(cmds[1].contains("-F RETHINK_MARK"))
        assertTrue(cmds[2].contains("-X RETHINK_MARK"))
    }

    // ── teardown ───────────────────────────────────────────────────────────────

    @Test
    fun `teardown removes rules, table, both chains and the address`() {
        val cmds = RootTunPlanner.teardown()

        assertTrue(cmds.any { it.startsWith("ip rule del ") && it.contains("lookup 50") })
        assertTrue(cmds.contains("ip route flush table 50 2>/dev/null || true"))
        assertTrue(cmds.any { it.contains("-D OUTPUT -j RETHINK_MARK") })
        assertTrue(cmds.contains("ip address flush dev rtn0 2>/dev/null || true"))
        // deleted, not just taken down: a registered-but-idle rtn0 makes the next
        // TUNSETIFF fail with EBUSY and silently fall back to VpnService
        assertTrue(cmds.contains("ip link delete dev rtn0 2>/dev/null || true"))
    }

    @Test
    fun `staleIface sweep is idempotent and scoped to our interface`() {
        val cmd = RootTunPlanner.staleIface()

        assertTrue(cmd.contains("ip link delete dev rtn0"))
        assertTrue(cmd.contains("2>/dev/null || true"))
    }

    @Test
    fun `every teardown step tolerates an absent object`() {
        RootTunPlanner.teardown().forEach { cmd ->
            if (cmd.contains("del ") || cmd.contains("-X ") || cmd.contains("-F ") || cmd.contains("flush")) {
                assertTrue("must not fail when already gone: $cmd", cmd.contains("|| true"))
            }
        }
    }

    // ── round trip ─────────────────────────────────────────────────────────────

    @Test
    fun `setup then teardown leaves no chain, rule or table reference`() {
        val up =
            RootTunPlanner.mangleSetup(10213, emptySet()) +
                RootTunPlanner.routeSetup(routes, emptyList())
        val down = RootTunPlanner.teardown().joinToString("\n")

        listOf("RETHINK_MARK", "lookup 50", "table 50").forEach { token ->
            val created = up.any { it.contains(token) }
            val removed = down.contains(token)
            if (created) assertTrue("teardown must mention $token", removed)
        }
    }
}
