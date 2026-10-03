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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RootPowerProfileTest {

    @After
    fun tearDown() {
        PowerGovernor.reset()
    }

    @Test
    fun `default profile is the vpn profile`() {
        assertEquals(PowerProfile.vpn(), PowerGovernor.current)
        assertEquals("vpn", PowerGovernor.current.name)
    }

    @Test
    fun `select root switches to the root profile and back`() {
        val root = PowerGovernor.select(root = true)
        assertEquals("root", root.name)
        assertEquals(root, PowerGovernor.current)

        val vpn = PowerGovernor.select(root = false)
        assertEquals("vpn", vpn.name)
        assertEquals(vpn, PowerGovernor.current)
    }

    @Test
    fun `vpn profile keeps the historical intervals`() {
        val vpn = PowerProfile.vpn()
        assertEquals(15_000L, vpn.connectivityCheckMs)
        assertEquals(1_000L, vpn.networkSettleMs)
        assertEquals(120_000L, vpn.globalProxyCheckMs)
        assertEquals(60_000L, vpn.proxyPingMs)
        assertEquals(2_500L, vpn.netLogFlushMs)
        assertEquals(3, vpn.refreshAppsHours)
        assertEquals(20L, vpn.dataUsageMins)
        assertEquals(45L, vpn.rpnProxyRefreshMins)
        assertEquals(1_000L, vpn.pauseTickMs)
        assertFalse(vpn.throttleNetworkEvents)
    }

    @Test
    fun `root profile is strictly quieter than the vpn profile on every churn knob`() {
        val vpn = PowerProfile.vpn()
        val root = PowerProfile.root()

        assertTrue(root.connectivityCheckMs > vpn.connectivityCheckMs)
        assertTrue(root.networkSettleMs > vpn.networkSettleMs)
        assertTrue(root.globalProxyCheckMs > vpn.globalProxyCheckMs)
        assertTrue(root.proxyPingMs > vpn.proxyPingMs)
        assertTrue(root.netLogFlushMs > vpn.netLogFlushMs)
        assertTrue(root.refreshAppsHours > vpn.refreshAppsHours)
        assertTrue(root.dataUsageMins > vpn.dataUsageMins)
        assertTrue(root.rpnProxyRefreshMins > vpn.rpnProxyRefreshMins)
        assertTrue(root.pauseTickMs > vpn.pauseTickMs)
        assertTrue(root.kernelRulePollMs > 0)
        assertTrue(root.throttleNetworkEvents)
    }

    @Test
    fun `root profile reduces the connectivity poll by at least four times`() {
        assertTrue(
            PowerProfile.root().connectivityCheckMs >= PowerProfile.vpn().connectivityCheckMs * 4,
        )
    }

    @Test
    fun `root intervals are not multiples of each other so their wakeups do not line up`() {
        val root = PowerProfile.root()
        val intervals =
            listOf(
                root.connectivityCheckMs,
                root.netLogFlushMs,
                root.proxyPingMs,
                root.pauseTickMs,
                root.kernelRulePollMs,
            )
        val distinct = intervals.toSet()
        assertEquals("intervals must be staggered", intervals.size, distinct.size)
        // no wake-up should be a whole multiple of another (would coalesce into one spike)
        for (a in intervals) {
            for (b in intervals) {
                if (a == b) continue
                if (b % a == 0L) {
                    // pauseTick and kernel poll are allowed to relate, but not the hot ones
                    if (a == root.netLogFlushMs || a == root.connectivityCheckMs) {
                        throw AssertionError("$b is a multiple of $a")
                    }
                }
            }
        }
    }

    @Test
    fun `profiles differ so a mode change is observable`() {
        assertNotEquals(PowerProfile.vpn(), PowerProfile.root())
    }

    @Test
    fun `override and reset are honoured`() {
        val custom = PowerProfile.vpn().copy(name = "custom", connectivityCheckMs = 99L)
        PowerGovernor.override(custom)
        assertEquals(99L, PowerGovernor.current.connectivityCheckMs)
        PowerGovernor.reset()
        assertEquals(15_000L, PowerGovernor.current.connectivityCheckMs)
    }

    @Test
    fun `all intervals are positive`() {
        for (p in listOf(PowerProfile.vpn(), PowerProfile.root())) {
            assertTrue("${p.name} connectivity", p.connectivityCheckMs > 0)
            assertTrue("${p.name} settle", p.networkSettleMs > 0)
            assertTrue("${p.name} proxy", p.globalProxyCheckMs > 0)
            assertTrue("${p.name} ping", p.proxyPingMs > 0)
            assertTrue("${p.name} log", p.netLogFlushMs > 0)
            assertTrue("${p.name} apps", p.refreshAppsHours > 0)
            assertTrue("${p.name} data", p.dataUsageMins > 0)
            assertTrue("${p.name} rpn", p.rpnProxyRefreshMins > 0)
            assertTrue("${p.name} pause", p.pauseTickMs > 0)
            assertTrue("${p.name} poll", p.kernelRulePollMs > 0)
        }
    }
}
