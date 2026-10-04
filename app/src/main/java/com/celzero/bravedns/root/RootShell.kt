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

import android.os.Build
import android.os.SystemClock
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
 * Runs commands through `su` (root) or `sh -c` (app uid).
 *
 * Two `su` dialects are supported, because they really do differ in the wild:
 *
 *  * **flag** — Magisk, KernelSU, SuperSU: `su -c '<command>'`
 *  * **who**  — AOSP/toybox `su` (userdebug builds, emulators, some ROMs):
 *    `su <who> <command...>`, whose `su -c` fails with `invalid uid/gid`
 *
 * The dialect is detected once per process by running a harmless `echo` and is only
 * cached when a working one was found, so a grant that arrives later still gets used.
 * An app that cannot find a usable `su` at all reports a failure rather than throwing,
 * and the caller falls back to the non-root path.
 *
 * Both stdout and stderr are drained on their own threads: a root shell that writes more
 * than a pipe buffer (e.g. `iptables -L -vnx` over a large rule set) would otherwise
 * deadlock the child and burn a full timeout waiting on itself.
 */
class ProcessCommandRunner : CommandRunner {

    override fun run(command: String, asRoot: Boolean, timeoutMs: Long): ShellResult {
        if (!asRoot) return exec(arrayOf(SHELL, "-c", command), command, timeoutMs)
        return when (val style = resolveSuStyle(timeoutMs)) {
            SuStyle.FLAG_C -> exec(arrayOf(SU_BINARY, "-c", command), command, timeoutMs)
            SuStyle.WHO_COMMAND ->
                exec(arrayOf(SU_BINARY, ROOT_WHO, SHELL, "-c", command), command, timeoutMs)
            SuStyle.UNSUPPORTED -> ShellResult.notRun("no usable su invocation ($probeDetail)")
            SuStyle.UNKNOWN -> ShellResult.notRun("su dialect undetectable")
        }
    }

    /**
     * Finds the `su` invocation this device accepts. Caches a hit for the life of the
     * process; deliberately does not cache a miss, because a superuser app may grant
     * permission later without the app restarting.
     */
    private fun resolveSuStyle(timeoutMs: Long): SuStyle {
        suStyle.takeIf { it != SuStyle.UNKNOWN }?.let { return it }
        val flagC = exec(arrayOf(SU_BINARY, "-c", "echo $STYLE_PROBE"), STYLE_PROBE, timeoutMs)
        if (flagC.out.contains(STYLE_PROBE)) {
            return SuStyle.FLAG_C.also { suStyle = it }
        }
        val who =
            exec(arrayOf(SU_BINARY, ROOT_WHO, SHELL, "-c", "echo $STYLE_PROBE"), STYLE_PROBE, timeoutMs)
        if (who.out.contains(STYLE_PROBE)) {
            return SuStyle.WHO_COMMAND.also { suStyle = it }
        }
        probeDetail = "[-c ${describe(flagC)}] [who ${describe(who)}]"
        return SuStyle.UNSUPPORTED
    }

    private fun describe(r: ShellResult): String =
        "rc=${r.code} out=${r.out.trim().take(80).replace('\n', ' ')} " +
            "err=${r.err.trim().take(80).replace('\n', ' ')}"

    private fun exec(argv: Array<String>, display: String, timeoutMs: Long): ShellResult {
        return try {
            val process = ProcessBuilder(*argv).redirectErrorStream(false).start()
            val out = Drain(process.inputStream)
            val err = Drain(process.errorStream)
            if (!waitFor(process, timeoutMs)) {
                destroyForcibly(process)
                ShellResult.notRun("timeout after ${timeoutMs}ms: $display")
            } else {
                ShellResult(process.exitValue(), out.await(), err.await())
            }
        } catch (e: IOException) {
            ShellResult.notRun("${e.javaClass.simpleName}: ${e.message}")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            ShellResult.notRun("interrupted")
        }
    }

    /**
     * Waits up to [timeoutMs] for [process] to exit.
     *
     * `Process.waitFor(long, TimeUnit)` is API 26 while minSdk here is 23, so older
     * devices poll `exitValue()` instead. The timeout is a bound on how long the caller
     * blocks either way — the shell outlives it and is killed by [destroyForcibly].
     */
    private fun waitFor(process: Process, timeoutMs: Long): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        }
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        while (SystemClock.uptimeMillis() < deadline) {
            try {
                process.exitValue()
                return true
            } catch (e: IllegalThreadStateException) {
                try {
                    Thread.sleep(POLL_INTERVAL_MS)
                } catch (ie: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        }
        return false
    }

    /** `Process.destroyForcibly()` is API 26 as well; `destroy()` exists everywhere. */
    private fun destroyForcibly(process: Process) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            process.destroyForcibly()
        } else {
            process.destroy()
        }
    }

    /**
     * Reads [stream] on a background thread while the child is still running: a shell that
     * writes more than a pipe buffer (`iptables -L -vnx` over a large rule set) would
     * otherwise fill the pipe, block, and never reach exit — leaving [waitFor] to time out
     * on a process waiting to be read from.
     *
     * [await] joins that reader first, so the returned text is the child's complete output.
     * Snapshotting the buffer straight after [Thread.start] would race the reader and hand
     * back an empty string for a child that exited promptly.
     */
    private class Drain(stream: InputStream) {
        private val bytes = ByteArrayOutputStream()
        private val thread: Thread

        init {
            thread =
                Thread(
                    {
                        val buf = ByteArray(4096)
                        try {
                            while (true) {
                                val n = stream.read(buf)
                                if (n < 0) break
                                synchronized(bytes) { bytes.write(buf, 0, n) }
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
            thread.isDaemon = true
            thread.start()
        }

        fun await(): String {
            try {
                thread.join(DRAIN_JOIN_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            synchronized(bytes) {
                return String(bytes.toByteArray(), Charsets.UTF_8)
            }
        }

        companion object {
            /** Generous: the child has already exited by the time we get here. */
            private const val DRAIN_JOIN_MS = 5_000L
        }
    }

    /** How this device's `su` wants to be told what to run. */
    private enum class SuStyle {
        UNKNOWN,

        /** `su -c '<command>'` — Magisk, KernelSU, SuperSU. */
        FLAG_C,

        /** `su <who> <command...>` — AOSP/toybox `su`. */
        WHO_COMMAND,

        /** Neither form worked; not cached (a grant may still arrive). */
        UNSUPPORTED,
    }

    @Volatile private var suStyle: SuStyle = SuStyle.UNKNOWN

    /** What the two dialect probes actually saw; only set when both missed. */
    @Volatile private var probeDetail: String = ""

    companion object {
        private const val SU_BINARY = "su"
        private const val SHELL = "sh"

        /** Who to become for the WHO_COMMAND dialect: `0`/`root` are both accepted. */
        private const val ROOT_WHO = "0"

        /** Echoed by both probe forms so a match cannot come from su's own chatter. */
        private const val STYLE_PROBE = "rethink-su-style-ok"

        private const val POLL_INTERVAL_MS = 25L
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
    private val log: (String) -> Unit = {},
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
        if (!hasSu.ok) {
            log("root probe: no su on PATH")
            return RootState.UNAVAILABLE
        }

        val who = runner.run("id", asRoot = true, timeoutMs = PROBE_TIMEOUT_MS)
        if (who.ok && who.out.contains(ROOT_UID_MARKER)) {
            log("root probe: granted")
            return RootState.GRANTED
        }
        // one line, because "denied" and "su dialect refused us" look identical otherwise
        log(
            "root probe: denied (code=${who.code}, out=${who.out.trim().take(120)}, " +
                "err=${who.err.trim().take(120)})",
        )
        return RootState.DENIED
    }

    companion object {
        const val ROOT_UID_MARKER = "uid=0"
        const val PROBE_TIMEOUT_MS = 10_000L
        const val GRANT_TTL_MS = 5 * 60_000L
        const val DENY_TTL_MS = 30 * 60_000L
    }
}
