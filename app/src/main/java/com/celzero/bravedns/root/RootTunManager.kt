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

import android.content.Context
import android.net.LocalServerSocket
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import com.celzero.bravedns.util.Logger
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Owns a tun device obtained from root instead of from `VpnService.establish()`.
 *
 * The class does three things and nothing else:
 *
 *  1. Runs the [RootTunPlanner] command scripts through a [CommandRunner] as root.
 *  2. Obtains the tun file descriptor from the compiled `rtn` helper over an
 *     `AF_UNIX`/`SCM_RIGHTS` handshake, keeping one descriptor of its own so the
 *     interface survives every restart of the upstream adapter.
 *  3. Gives callers a fresh `dup` of that descriptor each time, so ownership rules
 *     downstream (detach, hand to firestack, close) stay exactly as they were when the
 *     descriptor came from a real VPN.
 *
 * Every failure — no root, no `su`, a `su` build that will not run our binary, a SELinux
 * denial — returns null. The caller then falls back to `VpnService.establish()` and the
 * app keeps working as a normal VPN, which is the only correct outcome.
 */
class RootTunManager(
    private val context: Context,
    private val runner: CommandRunner,
    private val detector: RootDetector,
) {

    /** Everything the routing setup needs for one `establish()` pass. */
    data class TunSpec(
        /** Interface addresses, e.g. `10.111.222.1/24`, exactly as the builder set them. */
        val addresses: List<String>,
        /** Interface routes, exactly as `VpnService.Builder.addRoute()` produced them. */
        val routes: List<String>,
        /** The device's current resolvers; routed in so DNS keeps entering the tunnel. */
        val systemDns: List<String>,
        val mtu: Int,
        val selfUid: Int,
        /** Uids of apps the user excluded from the tunnel. */
        val bypassUids: Set<Int>,
    )

    private val mutex = Mutex()

    /**
     * Kept open for the lifetime of the root tun so the interface cannot disappear when
     * the upstream adapter detaches and hands its own copy to firestack.
     */
    @Volatile private var held: ParcelFileDescriptor? = null

    @Volatile private var lastError: String? = null

    private var helperPath: String? = null

    fun isUp(): Boolean = held != null

    fun lastError(): String? = lastError

    /**
     * Returns a descriptor for the root tun, creating and configuring it on first use,
     * or null when root is unavailable for any reason.
     */
    suspend fun establish(spec: TunSpec): ParcelFileDescriptor? = withContext(Dispatchers.IO) {
        if (!detector.isGranted()) {
            lastError = "root not granted"
            return@withContext null
        }
        val helper = ensureHelper() ?: return@withContext null

        mutex.withLock {
            try {
                if (held == null) {
                    // Clear a device left registered by an instance that never tore down
                    // (netstack can outlive our own descriptor); otherwise TUNSETIFF
                    // fails with EBUSY and the caller falls back to VpnService.
                    runner.run(RootTunPlanner.staleIface(), asRoot = true, timeoutMs = 5_000L)
                    val pfd = openTun(helper, spec.mtu)
                    if (pfd == null) {
                        lastError = lastError ?: "helper handshake failed"
                        return@withContext null
                    }
                    held = pfd
                    Logger.i(TAG, "root tun up, if=${RootTunPlanner.IFACE}")
                }
                if (!configure(spec)) {
                    lastError = lastError ?: "routing setup failed"
                    releaseHeld()
                    return@withContext null
                }
                // hand out our own copy so the caller may detach or close freely
                return@withContext held?.dup()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                lastError = "${e.javaClass.simpleName}: ${e.message}"
                Logger.e(TAG, "root tun establish failed: ${e.message}", e)
                releaseHeld()
                return@withContext null
            }
        }
        null
    }

    /** Drops the routing state and the held descriptor. Idempotent. */
    suspend fun teardown() = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (held == null) return@withLock
            try {
                runner.run(
                    CommandRunner.script(RootTunPlanner.teardown()),
                    asRoot = true,
                    timeoutMs = TEARDOWN_TIMEOUT_MS,
                )
            } catch (e: Exception) {
                Logger.w(TAG, "root tun teardown: ${e.message}")
            } finally {
                releaseHeld()
                Logger.i(TAG, "root tun down")
            }
        }
    }

    // ---------------------------------------------------------------- tun handshake

    private suspend fun openTun(helper: String, mtu: Int): ParcelFileDescriptor? =
        coroutineScope {
            val server =
                try {
                    // LocalServerSocket(String) binds in the abstract namespace: no node
                    // on disk means no permission bits for the helper to trip over.
                    LocalServerSocket(SOCKET_NAME)
                } catch (e: IOException) {
                    lastError = "listen failed: ${e.message}"
                    Logger.e(TAG, "cannot listen on $SOCKET_NAME: ${e.message}", e)
                    return@coroutineScope null
                }

            try {
                val accept = async(Dispatchers.IO) { server.accept() }
                val run =
                    async(Dispatchers.IO) {
                        runner.run(
                            "'$helper' $ABSTRACT_PREFIX$SOCKET_NAME ${RootTunPlanner.IFACE} $mtu",
                            asRoot = true,
                            timeoutMs = HELPER_TIMEOUT_MS,
                        )
                    }

                val sock =
                    try {
                        withTimeoutOrNull(HELPER_TIMEOUT_MS) { accept.await() }
                    } catch (e: CancellationException) {
                        run.cancel()
                        throw e
                    }

                if (sock == null) {
                    run.cancel()
                    lastError = "helper did not connect"
                    Logger.e(TAG, "helper did not connect within ${HELPER_TIMEOUT_MS}ms")
                    return@coroutineScope null
                }

                val pfd = receiveFd(sock, run)
                run.await()
                pfd
            } finally {
                // LocalServerSocket only became Closeable in API 28, so no `use {}`
                // here — that would cast and crash on everything below it.
                try {
                    server.close()
                } catch (e: Exception) {
                    Logger.v(TAG, "socket close: ${e.message}")
                }
            }
        }

    /**
     * Reads the single carrier byte the helper sends. `LocalSocket` attaches any
     * ancillary descriptor to that very read, so by the time it returns the descriptor
     * is in [LocalSocket.ancillaryFileDescriptors].
     */
    private suspend fun receiveFd(
        sock: android.net.LocalSocket,
        run: Deferred<ShellResult>,
    ): ParcelFileDescriptor? {
        try {
            val input = sock.inputStream
            val carrier = input.read()
            val fds = sock.ancillaryFileDescriptors
            if (carrier < 0 || fds == null || fds.isEmpty()) {
                val res = run.await()
                lastError = "no fd: ${res.out.trim()} ${res.err.trim()}".trim()
                Logger.e(TAG, "helper sent no descriptor: $lastError")
                return null
            }
            // dup() owns its own copy, so closing the socket cannot take it away
            return ParcelFileDescriptor.dup(fds[0])
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            lastError = "${e.javaClass.simpleName}: ${e.message}"
            Logger.e(TAG, "fd receive failed: ${e.message}", e)
            return null
        } finally {
            try {
                sock.close()
            } catch (e: IOException) {
                Logger.v(TAG, "socket close: ${e.message}")
            }
        }
    }

    // ------------------------------------------------------------------- routing

    private fun configure(spec: TunSpec): Boolean {
        val cmds =
            RootTunPlanner.linkSetup(spec.addresses, spec.mtu) +
                RootTunPlanner.routeSetup(spec.routes, spec.systemDns) +
                RootTunPlanner.mangleSetup(spec.selfUid, spec.bypassUids)

        val res = runner.run(CommandRunner.script(cmds), asRoot = true, timeoutMs = SETUP_TIMEOUT_MS)
        if (res.code == -1) {
            lastError = res.err
            Logger.e(TAG, "routing setup did not run: ${res.err}")
            return false
        }
        if (res.err.isNotBlank()) {
            Logger.d(TAG, "routing setup stderr: ${res.err.trim()}")
        }

        // one deterministic check beats trusting a wall of `|| true`
        val check =
            runner.run("ip link show ${RootTunPlanner.IFACE}", asRoot = true, timeoutMs = 5_000)
        if (!check.ok) {
            lastError = check.err.ifBlank { "interface missing" }
            Logger.e(TAG, "root tun interface missing: ${lastError}")
            return false
        }
        return true
    }

    private fun releaseHeld() {
        val pfd = held
        held = null
        if (pfd != null) {
            try {
                pfd.close()
            } catch (e: IOException) {
                Logger.v(TAG, "close held fd: ${e.message}")
            }
        }
    }

    // -------------------------------------------------------------------- helper

    private fun ensureHelper(): String? {
        helperPath?.let { return it }

        val abi =
            Build.SUPPORTED_ABIS.firstOrNull { assetExists(it) }
                ?: run {
                    lastError = "no helper for ${Build.SUPPORTED_ABIS.joinToString()}"
                    Logger.e(TAG, lastError ?: "no helper")
                    return null
                }

        val dir = File(context.filesDir, "rtn")
        if (!dir.exists() && !dir.mkdirs()) {
            lastError = "cannot create ${dir.path}"
            Logger.e(TAG, lastError ?: "mkdirs failed")
            return null
        }
        val out = File(dir, "rtn")
        val tmp = File(dir, "rtn.new")
        try {
            context.assets.open("${RootTunPlanner.HELPER_ASSET}/$abi/rtn").use { ins ->
                tmp.outputStream().use { ins.copyTo(it) }
            }
            if (!tmp.renameTo(out)) {
                tmp.copyTo(out, overwrite = true)
                tmp.delete()
            }
        } catch (e: IOException) {
            lastError = "extract failed: ${e.message}"
            Logger.e(TAG, lastError ?: "extract failed", e)
            return null
        }

        try {
            Os.chmod(out.absolutePath, 0b111_101_101 /* 0755 */)
        } catch (e: Exception) {
            Logger.w(TAG, "chmod helper: ${e.message}")
        }
        out.setReadable(true, false)
        out.setExecutable(true, false)

        // prove the binary is runnable *as root* before we depend on it
        var path = out.absolutePath
        var version = probeVersion(path)
        if (version == null) {
            // Some root domains are barred from executing a file the app owns (SELinux
            // labels everything under filesDir as app_data_file). Root then copies it into
            // a directory root owns — created 0700, so no other app can plant anything in
            // there — which every root domain can execute from.
            val sys = installSystemHelper(out)
            version = sys?.let { probeVersion(it) }
            if (version == null) {
                lastError = "helper not runnable as root"
                Logger.e(TAG, "$lastError (both $path and the $SYSTEM_DIR copy were refused)")
                return null
            }
            path = sys!!
        }

        Logger.i(TAG, "helper ready, abi=$abi version=$version")
        return path.also { helperPath = it }
    }

    /** The helper's `--version` output, or null when it could not be executed. */
    private fun probeVersion(path: String): String? {
        val probe = runner.run("'$path' --version", asRoot = true, timeoutMs = 10_000)
        if (!probe.ok || probe.out.isBlank()) {
            Logger.w(
                TAG,
                "helper probe failed for $path: ${probe.err.ifBlank { probe.out }.trim()}",
            )
            return null
        }
        return probe.out.trim()
    }

    /**
     * Copies [src] into a root-owned directory under [SYSTEM_DIR] and returns the new
     * path, or null when root could not write there. The whole tree is removed and
     * recreated by root first: nothing the app or any other app may have planted can
     * survive as a symlink for `cat >` to follow.
     */
    private fun installSystemHelper(src: File): String? {
        val dir = "$SYSTEM_DIR/rtn-${Process.myUid()}"
        val dst = "$dir/rtn"
        val res =
            runner.run(
                "rm -rf '$dir' && mkdir -p '$dir' && chmod 0700 '$dir' && chown 0:0 '$dir'" +
                    " && cat '${src.absolutePath}' > '$dst' && chmod 0755 '$dst'",
                asRoot = true,
                timeoutMs = INSTALL_TIMEOUT_MS,
            )
        if (!res.ok) {
            Logger.w(TAG, "system helper install failed: ${res.err.trim()}")
            return null
        }
        return dst
    }

    private fun assetExists(abi: String): Boolean =
        try {
            context.assets.open("${RootTunPlanner.HELPER_ASSET}/$abi/rtn").close()
            true
        } catch (e: IOException) {
            false
        }

    companion object {
        private const val TAG = "RootTun"

        /** Abstract-namespace rendezvous point shared with the `rtn` helper. */
        private const val SOCKET_NAME = "com.celzero.bravedns.rtn"

        /** `@` tells the helper to bind/connect in the abstract namespace. */
        private const val ABSTRACT_PREFIX = "@"

        /** Fallback home for the helper when app data is not executable by root. */
        private const val SYSTEM_DIR = "/data/local/tmp"

        private const val HELPER_TIMEOUT_MS = 15_000L
        private const val INSTALL_TIMEOUT_MS = 15_000L
        private const val SETUP_TIMEOUT_MS = 20_000L
        private const val TEARDOWN_TIMEOUT_MS = 20_000L
    }
}
