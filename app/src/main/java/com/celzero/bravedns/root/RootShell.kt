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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit

/**
 * Outcome of a single shell invocation. Never thrown, never null: a command that could
 * not be started at all is reported as [code] `-1` with the reason in [err], so callers
 * can treat "no root binary", "su denied" and "command failed" uniformly.
 */
data class ShellResult(val code: Int, val out: String, val err: String) {
    val ok: Boolean
        get() = code == 0

    companion object {
        fun notRun(reason: String) = ShellResult(-1, "", reason)
    }
}

/**
 * Abstraction over "run a shell command". The root stack only ever talks to this, so the
 * whole root path can be exercised in unit tests with a recording fake and without ever
 * touching a real `su`.
 */
interface CommandRunner {
    /**
     * Runs [command]. When [asRoot] is true the command must execute with uid 0.
     * Implementations must not throw.
     */
    fun run(command: String, asRoot: Boolean, timeoutMs: Long = DEFAULT_TIMEOUT_MS): ShellResult

    companion object {
        const val DEFAULT_TIMEOUT_MS = 15_000L

        /** Joins independent commands into one shell line; the last exit code wins. */
        fun script(commands: List<String>): String = commands.joinToString(" ; ")
    }
}

/**
 * Runs commands through `su -c` (root) or `sh -c` (app uid).
 *
 * Both stdout and stderr are drained on their own threads: a root shell that writes more
 * than a pipe buffer (e.g. `iptables -L -vnx` over a large rule set) would otherwise
 * deadlock the child and burn a full timeout waiting on itself.
 */
class ProcessCommandRunner : CommandRunner {

    override fun run(command: String, asRoot: Boolean, timeoutMs: Long): ShellResult {
        val argv = if (asRoot) arrayOf(SU_BINARY, "-c", command) else arrayOf(SHELL, "-c", command)
        return try {
            val process = ProcessBuilder(*argv).redirectErrorStream(false).start()
            val out = drain(process.inputStream)
            val err = drain(process.errorStream)
            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                ShellResult.notRun("timeout after ${timeoutMs}ms: $command")
            } else {
                ShellResult(process.exitValue(), out, err)
            }
        } catch (e: IOException) {
            ShellResult.notRun("${e.javaClass.simpleName}: ${e.message}")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            ShellResult.notRun("interrupted")
        }
    }

    private fun drain(stream: InputStream): String {
        val bytes = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        val t = Thread(
            {
                try {
                    while (true) {
                        val n = stream.read(buf)
                        if (n < 0) break
                        bytes.write(buf, 0, n)
                    }
                } catch (_: IOException) {
                    // process went away; whatever was read is still useful
                } finally {
                    try {
                        stream.close()
                    } catch (_: IOException) {
                    }
                }
            },
            "root-shell-drain",
        )
        t.isDaemon = true
        t.start()
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    companion object {
        private const val SU_BINARY = "su"
        private const val SHELL = "sh"
    }
}

/** State of root availability on this device. */
enum class RootState {
    /** Not probed yet. */
    UNKNOWN,

    /** `su` exists and granted uid 0. */
    GRANTED,

    /** `su` exists but the grant was refused / not elevated. */
    DENIED,

    /** No `su` binary on PATH at all. */
    UNAVAILABLE,
}

/**
 * Probes (and caches) root availability.
 *
 * Denials are cached for longer than grants: re-forking `su` on every sync is both a
 * battery cost and a UX annoyance when the user pressed "deny" in the superuser app.
 */
class RootDetector(
    private val runner: CommandRunner,
    private val clock: () -> Long = System::currentTimeMillis,
    private val grantTtlMs: Long = GRANT_TTL_MS,
    private val denyTtlMs: Long = DENY_TTL_MS,
) {
    @Volatile private var state: RootState = RootState.UNKNOWN
    @Volatile private var probedAt: Long = 0L

    fun state(): RootState = state

    /**
     * Returns true when a root shell is usable. Cached for [grantTtlMs] after a success
     * and [denyTtlMs] after a failure, unless [force] is set.
     */
    fun isGranted(force: Boolean = false): Boolean {
        val now = clock()
        val ttl = if (state == RootState.GRANTED) grantTtlMs else denyTtlMs
        if (!force && state != RootState.UNKNOWN && now - probedAt < ttl) {
            return state == RootState.GRANTED
        }
        val result = probe()
        state = result
        probedAt = now
        return result == RootState.GRANTED
    }

    private fun probe(): RootState {
        val hasSu =
            runner.run("command -v su >/dev/null 2>&1", asRoot = false, timeoutMs = PROBE_TIMEOUT_MS)
        if (!hasSu.ok) return RootState.UNAVAILABLE

        val who = runner.run("id", asRoot = true, timeoutMs = PROBE_TIMEOUT_MS)
        return if (who.ok && who.out.contains(ROOT_UID_MARKER)) {
            RootState.GRANTED
        } else {
            RootState.DENIED
        }
    }

    companion object {
        const val ROOT_UID_MARKER = "uid=0"
        const val PROBE_TIMEOUT_MS = 10_000L
        const val GRANT_TTL_MS = 5 * 60_000L
        const val DENY_TTL_MS = 30 * 60_000L
    }
}
