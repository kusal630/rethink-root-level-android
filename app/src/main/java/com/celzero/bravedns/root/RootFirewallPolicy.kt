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
 * Which uids may be dropped by the kernel instead of by the tun path.
 *
 * This is deliberately *conservative*: it is a pure function of already-resolved per-app
 * verdicts and it only ever selects uids whose verdict is an unconditional "deny" that
 * does not depend on the current network, the screen, the domain or the destination IP.
 * Anything conditional stays on the tun path where it can be evaluated per-flow.
 *
 * Being wrong in the other direction (leaving a uid on the tun path) costs nothing but
 * the battery saving; being wrong here would block a flow that should have been allowed.
 */
object RootFirewallPolicy {

    /** Inputs that decide whether *any* offload is meaningful or safe. */
    data class Scope(
        /** True when the brave mode actually evaluates connection rules (firewall/dns+firewall). */
        val firewallActive: Boolean,
        /** Lockdown forces every tracked app through the tunnel; rules stay authoritative. */
        val lockdown: Boolean,
        /**
         * True when an app may leave the tunnel entirely (`allowBypass` without lockdown).
         * Such an app is invisible to the tun path today, so dropping it in the kernel
         * would block traffic that the app currently lets through.
         */
        val tunnelMayBeBypassed: Boolean,
        /** The app's own uid — dropping it would kill firestack and the DNS resolver. */
        val selfUid: Int,
        /**
         * Uids that are not carried by the tunnel (disallowed in the VPN builder, excluded
         * by the user, or chosen as a proxy host app). The kernel rule has no tun
         * counterpart for them, so it must not be installed either.
         */
        val notInTunnel: Set<Int> = emptySet(),
        /** Orbot/socks setup traffic that must never be pre-empted. */
        val proxySetupUids: Set<Int> = emptySet(),
    )

    /** One app's resolved verdict, already reduced to plain data. */
    data class AppRule(
        val uid: Int,
        /** `FirewallManager.connectionStatus(...).blocked()` — i.e. "deny regardless of network". */
        val denyAll: Boolean,
        /** `FirewallManager.isTempAllowed(uid)` — evaluated before the app rule, so it wins. */
        val tempAllowed: Boolean,
        /** `FirewallManager.appStatus(...) == EXCLUDE`. */
        val excluded: Boolean,
        /** Rule exists for the uid at all; unknown apps are handled by other rules. */
        val tracked: Boolean,
    )

    /**
     * Returns the uids whose packets the kernel may drop directly.
     *
     * Order mirrors [com.celzero.bravedns.service.TunFirewallManager.firewall]: the early
     * allowances (self, temp-allow, proxy setup) are honoured before the app rule, and the
     * network-conditional statuses (METERED / UNMETERED) are never selected because they
     * cannot be expressed as a static owner match.
     */
    fun select(rules: Collection<AppRule>, scope: Scope): Set<Int> {
        if (!scope.firewallActive) return emptySet()
        if (scope.tunnelMayBeBypassed) return emptySet()
        if (rules.isEmpty()) return emptySet()

        val protectedUids = HashSet<Int>(scope.notInTunnel.size + scope.proxySetupUids.size + 1)
        protectedUids += scope.selfUid
        protectedUids += scope.notInTunnel
        protectedUids += scope.proxySetupUids

        val denied = HashSet<Int>()
        for (rule in rules) {
            if (!rule.denyAll || !rule.tracked) continue
            // a sentinel uid (UID_EVERYBODY style, <= 0) is not an app the kernel can match
            if (rule.uid <= 0) continue
            if (rule.excluded || rule.tempAllowed) continue
            if (rule.uid in protectedUids) continue
            denied += rule.uid
        }
        return denied
    }

    /**
     * Uids the kernel must not count either: traffic that never reaches the tun cannot be
     * attributed to a drop, so including it would inflate the blocked-connection stat.
     */
    fun counterEligible(selected: Set<Int>, scope: Scope): Set<Int> = selected
}
