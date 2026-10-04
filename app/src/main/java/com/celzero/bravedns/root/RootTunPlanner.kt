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
 * How the app takes over routing when it owns the tun device itself instead of letting
 * `VpnService.establish()` do it.
 *
 * `VpnService` gives us three things for free. This object reproduces each of them with
 * plain `ip`/`iptables` calls so that the data path downstream of the tun file descriptor
 * is byte-for-byte identical:
 *
 *  1. **A tun interface with the builder's addresses.**  `ip link` + `ip addr`.
 *  2. **The builder's routes.**  They are installed into a dedicated routing table rather
 *     than the main one, so the rest of the system keeps using its own default route.
 *  3. **`VpnService.protect()` for our own sockets.**  An `owner` match in the mangle
 *     `OUTPUT` chain returns before the packet is marked, so our sockets never enter the
 *     tunnel. This is exactly what `protect()` did, and it works even though we never
 *     registered a VPN with the system.
 *  4. **`VpnService.Builder.addDnsServer()`.**  A registered VPN tells the whole OS "your
 *     resolver is 10.111.222.3", so every DNS query lands in the tunnel with that
 *     destination. Without a VPN the OS keeps using the LAN resolver, so [routeSetup]
 *     routes the device's resolvers into the tunnel instead. Queries arrive with the
 *     destination the app asked for and the reply keeps the same source address, which is
 *     what a connected DNS socket expects.
 *
 * Marking uses the top nibble (`0xF0000000`). Android's netd keeps the network id in the
 * low 20 bits and its rule masks are `0xffff`, `0x1ffff`, `0xcffff`, `0xd0000` — none of
 * which cover bits 28..31, so our mark cannot collide with a network id while the bits
 * netd *does* care about are preserved (`--set-xmark` only touches the masked bits).
 *
 * Rule priority 9000 puts us above every netd rule (the first of which sits at 10000)
 * while leaving the `local` table at 0 in charge of loopback and interface addresses.
 *
 * Everything here returns command *strings*; nothing executes, so the whole routing
 * decision is unit-testable on a plain JVM.
 */
object RootTunPlanner {

    /** Interface name; short enough to stay under IFNAMSIZ on every kernel. */
    const val IFACE = "rtn0"

    /** Private routing table. Never the main table, so teardown is trivial. */
    const val TABLE = 50

    /** Above netd's first rule (10000), below `local` (0). */
    const val RULE_PRIO = 9000

    /** Top nibble: outside every mask netd uses for network ids. */
    const val MARK = 0xF0000000L

    const val MARK_MASK = 0xF0000000L

    /** Mangle chain holding the "everything but us" marking rules. */
    const val MANGLE_CHAIN = "RETHINK_MARK"

    /** Where the compiled `rtn` helper lives inside the APK. */
    const val HELPER_ASSET = "rtn"

    const val IPTABLES = "iptables"

    private const val MARK_HEX = "0xf0000000"
    private const val MARK_SPEC = "0xf0000000/0xf0000000"

    private fun v6(ip: String) = ip.contains(':')

    private fun ipBin(ip: String) = if (v6(ip)) "ip -6" else "ip"

    /**
     * Brings the interface up with [mtu] and one address per [addresses] entry
     * (`"10.111.222.1/24"`, `"fd66::1/120"`, ...). Idempotent: `addr replace` and
     * `link set` may be repeated on every restart.
     */
    fun linkSetup(addresses: List<String>, mtu: Int): List<String> {
        val cmds = mutableListOf<String>()
        cmds += "ip link set dev $IFACE up"
        cmds += "ip link set dev $IFACE mtu $mtu"
        // flush first so addresses removed from the builder do not linger across restarts
        cmds += "ip address flush dev $IFACE"
        addresses.forEach { addr -> cmds += "${ipBin(addr)} address replace $addr dev $IFACE" }
        return cmds
    }

    /**
     * Installs [routes] into [TABLE] — the exact set the `VpnService.Builder` would have
     * installed — plus the `fwmark` rule that selects the table.
     *
     * [systemDns] are the device's current resolvers — the [routeSetup] half of the
     * `VpnService.Builder.addDnsServer()` replacement. A registered VPN points the whole
     * OS at the tunnel's resolver; without one the OS keeps the LAN resolver, so these
     * are pulled into the tunnel explicitly. Without them a DNS query to the LAN resolver
     * would find nothing in [TABLE], fall through to netd and leave the device unfiltered.
     *
     * The table is flushed first because a stale route left by a crashed process would
     * otherwise keep sending traffic at a tun nobody owns.
     *
     * A destination that is *not* listed here makes the lookup fail with `-EAGAIN`, and
     * the kernel then falls through to netd's rules. That is what gives us the same
     * "only these destinations enter the tunnel" behaviour as `VpnService.addRoute`.
     */
    fun routeSetup(routes: List<String>, systemDns: List<String>): List<String> {
        val cmds = mutableListOf<String>()
        cmds += "ip route flush table $TABLE 2>/dev/null || true"
        cmds += "ip -6 route flush table $TABLE 2>/dev/null || true"
        routes.forEach { r -> cmds += "${ipBin(r)} route replace $r dev $IFACE table $TABLE" }
        systemDns.forEach { d ->
            val prefix = if (v6(d)) 128 else 32
            cmds += "${ipBin(d)} route replace $d/$prefix dev $IFACE table $TABLE"
        }
        cmds += "ip rule del fwmark $MARK_SPEC lookup $TABLE priority $RULE_PRIO 2>/dev/null || true"
        cmds +=
            "ip rule add fwmark $MARK_SPEC lookup $TABLE priority $RULE_PRIO"
        cmds += "ip -6 rule del fwmark $MARK_SPEC lookup $TABLE priority $RULE_PRIO 2>/dev/null || true"
        cmds += "ip -6 rule add fwmark $MARK_SPEC lookup $TABLE priority $RULE_PRIO"
        return cmds
    }

    /**
     * The mangle chain: mark every locally generated packet *except* ours.
     *
     * [selfUid] must be first — it is the `VpnService.protect()` replacement and the only
     * thing stopping our own sockets from being routed back into the tun they feed.
     * [bypassUids] are the apps the user excluded from the tunnel.
     *
     * Returns commands suitable for `CommandRunner.script` (joined with `;`), each guarded
     * with `|| true` where an absent object is an expected outcome.
     */
    fun mangleSetup(selfUid: Int, bypassUids: Set<Int>): List<String> {
        val cmds = mutableListOf<String>()
        cmds += "$IPTABLES -w -t mangle -N $MANGLE_CHAIN 2>/dev/null || true"
        cmds += "$IPTABLES -w -t mangle -F $MANGLE_CHAIN"
        cmds += "$IPTABLES -w -t mangle -C OUTPUT -j $MANGLE_CHAIN 2>/dev/null || " +
            "$IPTABLES -w -t mangle -I OUTPUT 1 -j $MANGLE_CHAIN"
        // our own sockets: the protect() equivalent
        cmds += "$IPTABLES -w -t mangle -A $MANGLE_CHAIN -m owner --uid-owner $selfUid -j RETURN"
        // apps the user excluded from the tunnel (the builder disallows our own package
        // too, which would otherwise repeat the selfUid rule above)
        (bypassUids - selfUid).sorted().forEach { uid ->
            cmds += "$IPTABLES -w -t mangle -A $MANGLE_CHAIN -m owner --uid-owner $uid -j RETURN"
        }
        // loopback and the tunnel itself never need marking
        cmds += "$IPTABLES -w -t mangle -A $MANGLE_CHAIN -o lo -j RETURN"
        cmds += "$IPTABLES -w -t mangle -A $MANGLE_CHAIN -o $IFACE -j RETURN"
        // already routed into the tunnel (e.g. re-marked packets)
        cmds += "$IPTABLES -w -t mangle -A $MANGLE_CHAIN -m mark --mark $MARK_SPEC -j RETURN"
        // everything else goes to the tunnel; set only our nibble, keep netd's bits
        cmds += "$IPTABLES -w -t mangle -A $MANGLE_CHAIN -j MARK --set-xmark $MARK_SPEC"
        return cmds
    }

    /** Reverse of [mangleSetup]; safe when nothing was installed. */
    fun mangleTeardown(): List<String> {
        val notChain = "$IPTABLES -w -t mangle -C OUTPUT -j $MANGLE_CHAIN 2>/dev/null && " +
            "$IPTABLES -w -t mangle -D OUTPUT -j $MANGLE_CHAIN || true"
        return listOf(
            notChain,
            "$IPTABLES -w -t mangle -F $MANGLE_CHAIN 2>/dev/null || true",
            "$IPTABLES -w -t mangle -X $MANGLE_CHAIN 2>/dev/null || true",
        )
    }

    /**
     * Full teardown: drop the policy rules and the table, unhook the mangle chain and
     * unregister the interface.
     *
     * The device is deleted rather than merely taken down. netstack keeps its own
     * descriptor for the tun after `disconnect()`, so "last fd closes" is not something
     * we can wait for — and a still-registered interface makes the next `TUNSETIFF`
     * fail with `EBUSY` (single-queue device, already attached), which silently drops
     * us back onto `VpnService.establish()`. Root can unregister it while that
     * descriptor remains open.
     */
    fun teardown(): List<String> {
        val cmds = mutableListOf<String>()
        cmds += "ip rule del fwmark $MARK_SPEC lookup $TABLE priority $RULE_PRIO 2>/dev/null || true"
        cmds += "ip -6 rule del fwmark $MARK_SPEC lookup $TABLE priority $RULE_PRIO 2>/dev/null || true"
        cmds += "ip route flush table $TABLE 2>/dev/null || true"
        cmds += "ip -6 route flush table $TABLE 2>/dev/null || true"
        mangleTeardown().forEach { cmds += it }
        cmds += "ip address flush dev $IFACE 2>/dev/null || true"
        cmds += "ip link delete dev $IFACE 2>/dev/null || true"
        return cmds
    }

    /**
     * Same removal, run immediately before opening the tun: covers an instance that died
     * without reaching [teardown]. Idempotent — nothing to do when [IFACE] is absent.
     */
    fun staleIface(): String = "ip link delete dev $IFACE 2>/dev/null || true"

    /**
     * Rule ids in `ip rule show` are `${priority}: from all fwmark ... lookup ...`;
     * exposed so tests can assert the installed rule is the one we asked for.
     */
    fun ruleSpec(): String =
        "$RULE_PRIO: from all fwmark $MARK_SPEC lookup $TABLE"

    fun markHex(): String = MARK_HEX
}
