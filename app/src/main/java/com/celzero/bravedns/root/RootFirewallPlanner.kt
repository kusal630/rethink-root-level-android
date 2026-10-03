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
 * Pure, side-effect free description of the kernel-level firewall used when the app runs
 * as root.
 *
 * The whole point of root mode is to keep denied packets off the tun device. Without it
 * every blocked flow still travels tun -> firestack -> kotlin -> database, keeping the
 * CPU awake. With a `--uid-owner` rule in `OUTPUT`, the packet is dropped by the kernel
 * before any of that happens, and the app only ever does one batched `iptables -L` to
 * learn how much was dropped.
 *
 * Everything here returns command *strings*; nothing executes. That keeps the whole
 * decision layer unit-testable on a plain JVM with no Robolectric, no native code and no
 * device.
 */
object RootFirewallPlanner {

    /** Dedicated chain so rules can be replaced wholesale without touching the app's own. */
    const val CHAIN = "RETHINK_OUT"

    const val IPTABLES = "iptables"
    const val IP6TABLES = "ip6tables"

    /** Marker used to locate the owning uid inside a `iptables -L -vnx` line. */
    const val OWNER_MARKER = "owner UID match"

    /**
     * Creates the chain (idempotent) and hooks it at the front of `OUTPUT` (idempotent).
     *
     * `-C` is used rather than `-I` unconditionally so repeated syncs never stack duplicate
     * jumps; `-N` on an existing chain is an expected failure, hence `|| true`.
     */
    fun ensureHook(bin: String): String {
        return "$bin -w -N $CHAIN 2>/dev/null || true ; " +
            "$bin -w -C OUTPUT -j $CHAIN 2>/dev/null || $bin -w -I OUTPUT 1 -j $CHAIN"
    }

    /** Drops every packet emitted by [uid] in the ip (and ip6) output path. */
    fun dropUid(bin: String, uid: Int): String =
        "$bin -w -A $CHAIN -m owner --uid-owner $uid -j DROP"

    /** Removes a rule previously added by [dropUid]; must match the rule exactly. */
    fun undropUid(bin: String, uid: Int): String =
        "$bin -w -D $CHAIN -m owner --uid-owner $uid -j DROP"

    /** Removes the jump from `OUTPUT`, then the chain itself. */
    fun removeHook(bin: String): String {
        return "$bin -w -D OUTPUT -j $CHAIN 2>/dev/null || true ; " +
            "$bin -w -F $CHAIN 2>/dev/null || true ; " +
            "$bin -w -X $CHAIN 2>/dev/null || true"
    }

    /**
     * Empties the chain without touching the hook.
     *
     * Called on activation so that rules left behind by a previous process that died
     * without reaching `deactivate()` cannot outlive it.
     */
    fun flush(bin: String): String = "$bin -w -F $CHAIN 2>/dev/null || true"

    /** Hook the chain and start from a known-empty state. */
    fun reset(bin: String): List<String> = listOf(ensureHook(bin), flush(bin))

    /**
     * Minimal install: hook + every uid in [desired]. Used on first activation.
     */
    fun install(bin: String, desired: Set<Int>): List<String> {
        val cmds = mutableListOf(ensureHook(bin))
        desired.sorted().forEach { cmds += dropUid(bin, it) }
        return cmds
    }

    /**
     * Commands that take the rule set from [current] to [desired].
     *
     * Only the symmetric difference is emitted, so an unchanged firewall costs zero `su`
     * forks on a sync. The jump hook is deliberately *not* part of the diff: the caller
     * owns it and adds [ensureHook] exactly once per activation, which keeps a no-op sync
     * free of any shell invocation at all.
     */
    fun diff(bin: String, current: Set<Int>, desired: Set<Int>): List<String> {
        if (current == desired) return emptyList()
        val cmds = mutableListOf<String>()
        (desired - current).sorted().forEach { cmds += dropUid(bin, it) }
        (current - desired).sorted().forEach { cmds += undropUid(bin, it) }
        return cmds
    }

    /** Full teardown; safe to run when nothing was installed. */
    fun remove(bin: String): List<String> = listOf(removeHook(bin))

    /**
     * Parses `iptables -L <CHAIN> -vnx` (numeric, no resolution) into `uid -> packets`.
     *
     * Example body line:
     * ```
     * 1234 56789 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 owner UID match 10042
     * ```
     *
     * Lines without an owner match (the chain's header and the references line) are
     * ignored, so the header can never be mistaken for traffic.
     */
    fun parseCounters(out: String): Map<Int, Long> {
        if (out.isEmpty()) return emptyMap()
        val result = LinkedHashMap<Int, Long>()
        out.lineSequence().forEach { line ->
            val idx = line.indexOf(OWNER_MARKER)
            if (idx < 0) return@forEach
            val uidText = line.substring(idx + OWNER_MARKER.length).trim()
            val uid = uidText.takeWhile { it.isDigit() || it == '-' }.toIntOrNull() ?: return@forEach
            val head = line.substring(0, idx).trim()
            // pkts bytes target ... — packets are the first field
            val pkts = head.split(Regex("\\s+")).firstOrNull()?.toLongOrNull() ?: return@forEach
            result[uid] = (result[uid] ?: 0L) + pkts
        }
        return result
    }

    /** `-L -vnx -Z` so counters restart at zero after every read. */
    fun readCounters(bin: String): String = "$bin -w -L $CHAIN -vnx -Z"

    /** Teardown must cover both families. */
    fun removalScript(binaries: List<String> = listOf(IPTABLES, IP6TABLES)): List<String> =
        binaries.flatMap { remove(it) }
}
