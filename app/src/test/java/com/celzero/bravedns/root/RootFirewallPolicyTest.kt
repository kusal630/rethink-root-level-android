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

import com.celzero.bravedns.root.RootFirewallPolicy.AppRule
import com.celzero.bravedns.root.RootFirewallPolicy.Scope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RootFirewallPolicyTest {

    private val selfUid = 10123

    private fun scope(modify: Scope.() -> Scope = { this }): Scope {
        val base =
            Scope(
                firewallActive = true,
                lockdown = false,
                tunnelMayBeBypassed = false,
                selfUid = selfUid,
            )
        return base.modify()
    }

    private fun denied(uid: Int, tempAllowed: Boolean = false, excluded: Boolean = false, tracked: Boolean = true) =
        AppRule(uid = uid, denyAll = true, tempAllowed = tempAllowed, excluded = excluded, tracked = tracked)

    private fun allowed(uid: Int) =
        AppRule(uid = uid, denyAll = false, tempAllowed = false, excluded = false, tracked = true)

    // ── selection ───────────────────────────────────────────────────────────────

    @Test
    fun `unconditionally denied apps are offloaded`() {
        val result = RootFirewallPolicy.select(listOf(denied(10001), allowed(10002), denied(10003)), scope())
        assertEquals(setOf(10001, 10003), result)
    }

    @Test
    fun `network-conditional statuses are never offloaded`() {
        // connectionStatus of METERED / UNMETERED resolves to denyAll = false here
        val result = RootFirewallPolicy.select(listOf(allowed(10001)), scope())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `the app's own uid is always protected`() {
        val result = RootFirewallPolicy.select(listOf(denied(selfUid)), scope())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `temporarily allowed apps keep using the tun path`() {
        val result = RootFirewallPolicy.select(listOf(denied(10001, tempAllowed = true)), scope())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `excluded apps are never programmed`() {
        val result = RootFirewallPolicy.select(listOf(denied(10001, excluded = true)), scope())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `untracked apps are left alone`() {
        val result = RootFirewallPolicy.select(listOf(denied(10001, tracked = false)), scope())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `apps outside the tunnel are never programmed`() {
        val s = scope { copy(notInTunnel = setOf(10001)) }
        val result = RootFirewallPolicy.select(listOf(denied(10001), denied(10002)), s)
        assertEquals(setOf(10002), result)
    }

    @Test
    fun `proxy setup uids are protected`() {
        val s = scope { copy(proxySetupUids = setOf(10001)) }
        val result = RootFirewallPolicy.select(listOf(denied(10001), denied(10002)), s)
        assertEquals(setOf(10002), result)
    }

    // ── scope gates ─────────────────────────────────────────────────────────────

    @Test
    fun `nothing is offloaded when the firewall mode is inactive`() {
        val s = scope { copy(firewallActive = false) }
        assertTrue(RootFirewallPolicy.select(listOf(denied(10001)), s).isEmpty())
    }

    @Test
    fun `nothing is offloaded when apps may bypass the tunnel`() {
        val s = scope { copy(tunnelMayBeBypassed = true) }
        assertTrue(RootFirewallPolicy.select(listOf(denied(10001)), s).isEmpty())
    }

    @Test
    fun `lockdown still offloads denied apps`() {
        val s = scope { copy(lockdown = true) }
        assertEquals(setOf(10001), RootFirewallPolicy.select(listOf(denied(10001)), s))
    }

    @Test
    fun `empty rule set offloads nothing`() {
        assertTrue(RootFirewallPolicy.select(emptyList(), scope()).isEmpty())
    }

    // ── combinations ────────────────────────────────────────────────────────────

    @Test
    fun `every protection applies at once`() {
        val s =
            scope {
                copy(notInTunnel = setOf(10), proxySetupUids = setOf(11))
            }
        val rules =
            listOf(
                denied(selfUid), // self
                denied(10), // not in tunnel
                denied(11), // proxy setup
                denied(12, tempAllowed = true), // temp allow
                denied(13, excluded = true), // excluded
                denied(14, tracked = false), // unknown
                allowed(15), // network conditional
                denied(16), // the only one that may be dropped
            )
        assertEquals(setOf(16), RootFirewallPolicy.select(rules, s))
    }

    @Test
    fun `result never contains anything but plain positive uids`() {
        val rules = listOf(denied(10001), denied(10002), denied(-1))
        val result = RootFirewallPolicy.select(rules, scope())
        // uid -1 (UID_EVERYBODY style sentinel) is not a real app uid and must not be dropped
        assertEquals(setOf(10001, 10002), result)
    }
}
