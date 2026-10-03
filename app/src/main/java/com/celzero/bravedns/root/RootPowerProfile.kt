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

/**
 * The tunneled, non-root runtime has to poll constantly: it owns the tun device, so it
 * must notice a new network on its own, flush its own logs, re-ping its own proxies and
 * re-derive its own block counts.
 *
 * At root those costs are avoidable. Connectivity is delivered by the platform to a
 * registered receiver, dropped packets are counted by the kernel, and proxies can be left
 * alone until a user-visible event actually changes. Each field below is a knob that a
 * subsystem reads instead of a hard-coded literal, so the runtime can trade latency for
 * battery without touching the subsystem.
 *
 * The default profile must stay identical to today's constants - existing tests assert
 * them (see ConnectionMonitorTest) and non-root users must see no behaviour change.
 */
data class PowerProfile(
    /** Identity, used in logs so a battery report can be attributed. */
    val name: String,
    /** How often the link is re-verified while the tunnel is up. */
    val connectivityCheckMs: Long,
    /** Settle delay applied to a connectivity change before the tunnel is rebuilt. */
    val networkSettleMs: Long,
    /** How often the global (HTTP) proxy endpoint is re-validated. */
    val globalProxyCheckMs: Long,
    /** Heartbeat interval for wireguard/proxy ping bookkeeping. */
    val proxyPingMs: Long,
    /** Batch window for the network event log writer. */
    val netLogFlushMs: Long,
    /** Hours between app list refreshes (installed-package scans). */
    val refreshAppsHours: Int,
    /** Minutes between data usage rollups. */
    val dataUsageMins: Long,
    /** Minutes between RPN proxy definition refreshes. */
    val rpnProxyRefreshMins: Long,
    /** Timer tick while a pause is counting down. */
    val pauseTickMs: Long,
    /** How often the kernel rule set is re-read for dropped-packet accounting. */
    val kernelRulePollMs: Long,
    /** Whether network-change events are debounced instead of handled inline. */
    val throttleNetworkEvents: Boolean,
) {
    companion object {
        /** Today's behaviour: chatty, because the app is the only source of truth. */
        fun vpn() =
            PowerProfile(
                name = "vpn",
                connectivityCheckMs = 15_000L,
                networkSettleMs = 1_000L,
                globalProxyCheckMs = 2 * 60_000L,
                proxyPingMs = 60_000L,
                netLogFlushMs = 2_500L,
                refreshAppsHours = 3,
                dataUsageMins = 20L,
                rpnProxyRefreshMins = 45L,
                pauseTickMs = 1_000L,
                kernelRulePollMs = 30_000L,
                throttleNetworkEvents = false,
            )

        /**
         * Root: the kernel and the platform already answer most of these questions, so
         * the app can go quiet. Every interval is deliberately *not* a multiple of the
         * others to avoid the polling phases lining up and waking the CPU together.
         */
        fun root() =
            PowerProfile(
                name = "root",
                connectivityCheckMs = 61_000L,
                networkSettleMs = 3_000L,
                globalProxyCheckMs = 10 * 60_000L,
                proxyPingMs = 307_000L,
                netLogFlushMs = 13_000L,
                refreshAppsHours = 12,
                dataUsageMins = 61L,
                rpnProxyRefreshMins = 181L,
                pauseTickMs = 5_000L,
                kernelRulePollMs = 90_000L,
                throttleNetworkEvents = true,
            )

        val DEFAULT: PowerProfile = vpn()
    }
}

/**
 * Process-wide holder for the active [PowerProfile].
 *
 * A singleton rather than a constructor parameter because the consumers (connectivity
 * monitor, proxy handlers, schedulers) are themselves singletons created long before the
 * VPN service decides which mode it is in.
 */
object PowerGovernor {

    @Volatile private var profile: PowerProfile = PowerProfile.DEFAULT

    val current: PowerProfile
        get() = profile

    /** Selects the profile. Returns the newly active one. */
    fun select(root: Boolean): PowerProfile {
        profile = if (root) PowerProfile.root() else PowerProfile.vpn()
        return profile
    }

    /** Forces a profile; used by tests and by the settings screen preview. */
    fun override(value: PowerProfile) {
        profile = value
    }

    fun reset() {
        profile = PowerProfile.DEFAULT
    }
}
