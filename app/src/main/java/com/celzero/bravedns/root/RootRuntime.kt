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
 * Owns everything root-related at runtime: whether root is usable, which power profile is
 * active, and what the kernel firewall currently looks like.
 *
 * The class never touches Android APIs — it is handed a [CommandRunner] and a log sink —
 * so the whole state machine is exercised by plain unit tests with a recording fake.
 *
 * Contract with the caller (the VPN service):
 *  - [activate] once, when the tunnel comes up;
 *  - [sync] after any change to app firewall verdicts (it is a no-op when nothing moved);
 *  - [counters] on the power profile's `kernelRulePollMs` cadence;
 *  - [deactivate] on teardown, which must leave the kernel exactly as it was found.
 */
class RootRuntime(
    private val runner: CommandRunner,
    private val log: (String) -> Unit = {},
    private val binaries: List<String> =
        listOf(RootFirewallPlanner.IPTABLES, RootFirewallPlanner.IP6TABLES),
) {
    val detector: RootDetector = RootDetector(runner)

    /** Whether the chain is installed and safe to diff against. */
    @Volatile var isEngaged: Boolean = false
        private set

    /** Last known kernel rule set. Empty when not engaged. */
    @Volatile private var installed: Set<Int> = emptySet()

    @Volatile private var hooked: Boolean = false

    fun installedUids(): Set<Int> = installed

    /**
     * Probes root, switches to the root power profile and installs the chain.
     *
     * Returns false without side effects when root is not usable, so the caller can fall
     * back to the tun path and the vpn power profile unchanged.
     */
    fun activate(force: Boolean = false): Boolean {
        if (isEngaged) return true
        if (!detector.isGranted(force)) {
            log("root unavailable (${detector.state()}); keeping tun-path firewall")
            PowerGovernor.select(root = false)
            return false
        }
        PowerGovernor.select(root = true)
        // reset (hook + flush) rather than just hook: a process that died before
        // deactivate() would otherwise leave its rules armed for the next boot session
        val cmds = binaries.flatMap { RootFirewallPlanner.reset(it) }
        val result = runner.run(CommandRunner.script(cmds), asRoot = true)
        if (!result.ok) {
            log("root firewall hook failed: ${result.err.ifBlank { result.out }.trim()}")
            PowerGovernor.select(root = false)
            return false
        }
        hooked = true
        installed = emptySet()
        isEngaged = true
        log("root firewall engaged (profile=${PowerGovernor.current.name})")
        return true
    }

    /**
     * Reconciles the kernel rules with [desired].
     *
     * @return true when the kernel matches [desired] on return — including the case where
     * nothing needed to change.
     */
    fun sync(desired: Set<Int>): Boolean {
        if (!isEngaged) return false
        val target = desired
        if (hooked && installed == target) return true

        val cmds = mutableListOf<String>()
        for (bin in binaries) {
            if (!hooked) cmds += RootFirewallPlanner.ensureHook(bin)
            cmds += RootFirewallPlanner.diff(bin, installed, target)
        }
        if (cmds.isEmpty()) {
            hooked = true
            installed = target
            return true
        }
        val result = runner.run(CommandRunner.script(cmds), asRoot = true)
        if (!result.ok) {
            // Do not pretend the diff applied: the next sync must re-derive from reality.
            log("root firewall sync failed: ${result.err.ifBlank { result.out }.trim()}")
            return false
        }
        hooked = true
        installed = target
        log("root firewall sync ok (${installed.size} uids dropped)")
        return true
    }

    /**
     * Reads (and resets) the kernel drop counters, merged across ip families.
     * Returns `uid -> packets dropped` for uids the chain has a rule for.
     */
    fun counters(): Map<Int, Long> {
        if (!isEngaged) return emptyMap()
        val out = LinkedHashMap<Int, Long>()
        for (bin in binaries) {
            val result = runner.run(RootFirewallPlanner.readCounters(bin), asRoot = true)
            if (!result.ok) continue
            for ((uid, packets) in RootFirewallPlanner.parseCounters(result.out)) {
                out[uid] = (out[uid] ?: 0L) + packets
            }
        }
        return out
    }

    /** Removes every rule and restores the pre-root power profile. Idempotent. */
    fun deactivate(): Boolean {
        if (!isEngaged && !hooked) {
            PowerGovernor.select(root = false)
            return true
        }
        val cmds = binaries.flatMap { RootFirewallPlanner.remove(it) }
        val result = runner.run(CommandRunner.script(cmds), asRoot = true)
        if (!result.ok) {
            log("root firewall teardown failed: ${result.err.ifBlank { result.out }.trim()}")
            return false
        }
        hooked = false
        installed = emptySet()
        isEngaged = false
        PowerGovernor.select(root = false)
        log("root firewall removed")
        return true
    }
}
