# RethinkDNS — Root Level Edition

A fork of [RethinkDNS for Android](https://github.com/celzero/rethink-app) (firewall + DNS + proxy) that runs as much of its work as possible **as root**, instead of through the per-app VPN tun device — with the explicit goal of cutting battery drain while keeping every feature working.

> **Upstream:** all credit for the application itself goes to the RethinkDNS authors.
> This repository adds a root execution path on top of the upstream snapshot recorded in
> the first commit. See [Credits](#credits).

---

## Contents

- [Why](#why)
- [What root mode does](#what-root-mode-does)
  - [1. A tun device the app owns — no VPN](#1-a-tun-device-the-app-owns--no-vpn)
  - [2. Kernel-level firewall offload](#2-kernel-level-firewall-offload)
  - [3. Rule lifecycle that survives crashes](#3-rule-lifecycle-that-survives-crashes)
  - [4. Power profile](#4-power-profile)
  - [5. A switch in the UI](#5-a-switch-in-the-ui)
- [What still runs in the Go engine](#what-still-runs-in-the-go-engine)
- [Using it](#using-it)
- [Building](#building)
- [Testing](#testing)
- [Release APKs](#release-apks)
- [Verifying the root behaviour yourself](#verifying-the-root-behaviour-yourself)
- [Safety, limitations and rollback](#safety-limitations-and-rollback)
- [Repository layout](#repository-layout)
- [Credits](#credits)

---

## Why

RethinkDNS is a `VpnService`. Every packet the app wants to inspect is routed into a tun
device, handed to the Go firewall/DNS engine, and only then decided on. That design is what
makes the app work without root — but it has a cost:

* **The system owns the tunnel.** `VpnService.establish()` asks `system_server` to create
  the interface, publish a VPN network and repoint every resolver at it. The key icon goes
  up, `protect()` becomes mandatory for our own sockets, and connectivity callbacks arrive
  through the VPN subsystem's own timing.
* **Blocked traffic still travels the whole stack.** A denied connection is written into
  the tun, read by firestack, turned into a Kotlin decision, logged, persisted, and only
  then dropped. The CPU has to wake up for traffic that was never going to succeed.
* **The app must poll, because nobody tells it anything.** It re-verifies connectivity on a
  timer, re-flushes its own log batches, re-pings its own proxies and re-derives its own
  drop counts — all at fixed, fairly aggressive intervals, each one a wakeup.

Root changes the trade. The kernel can open `/dev/net/tun` for us, mark and drop packets
before they ever reach the app, and the platform can deliver connectivity changes to a
registered receiver instead of the app having to ask for them. This fork exploits all of
those facts.

---

## What root mode does

Most of it lives in one package: **`com.celzero.bravedns.root`** — seven source files,
~1,350 lines, plus ~1,100 lines of unit tests.

### 1. A tun device the app owns — no VPN

When root is available, the app **does not register a VPN with the system at all**. Instead:

1. A tiny compiled helper, **`rtn`** (C, `app/src/main/cpp/rtn.c`, 182 lines, shipped
   prebuilt for each ABI under `app/src/main/assets/rtn/<abi>/rtn`), is executed as root.
   It opens `/dev/net/tun`, creates `rtn0` and sends the file descriptor back over an
   abstract `AF_UNIX` socket with `SCM_RIGHTS`.
2. `RootTunManager` receives that descriptor and **keeps one copy open for the lifetime of
   the service**, so the interface cannot disappear when the upstream adapter detaches and
   hands its own copy to firestack. Every `establish()` returns a fresh `dup`, so the
   ownership rules downstream (detach, hand to firestack, close) are exactly what they were
   when the descriptor came from a real VPN.
3. `RootTunPlanner` reproduces the four things `VpnService.establish()` gives away for
   free, with plain `ip`/`iptables` calls:

   | What the VPN did | What root mode does |
   | --- | --- |
   | Create the tun and set its addresses | `ip link set` / `ip address replace` on `rtn0` |
   | `addRoute()` into the system's routing table | the same routes in **table 50**, selected by an `fwmark` rule at **priority 9000** (above netd's first rule at 10000) |
   | `protect()` our own sockets | a `--uid-owner <self> -j RETURN` at the front of the mangle `RETHINK_MARK` chain — our packets are never marked, so they never match the rule |
   | `addDnsServer()` — repoint the whole OS at the tunnel | the device's **current** resolvers are routed into table 50, so queries keep the destination the app asked for and replies keep the source address the app expects |

   Everything else is marked `0xF0000000` in mangle `OUTPUT` and therefore lands in the
   tunnel. The mark uses the top nibble, outside every mask netd uses for network ids, so
   it cannot collide with the bits the platform cares about.

**What the user sees:** no VPN key icon in the status bar (nothing was registered as a
VPN), no VPN network for the OS to route around, and no `VpnService.protect()` work on the
data path. The one-time Android “Connection request” dialog still appears, because the app
still starts a `VpnService` — it just never calls `establish()`.

**Helper execution fallback.** Some root builds refuse to execute a file the app owns
(SELinux labels everything under `filesDir` as `app_data_file`). `RootTunManager` proves
the helper runs as root before it depends on it; if it does not, root re-copies it into a
`/data/local/tmp/rtn-<uid>/` directory that root creates `0700` and owns — nothing any
other app may have planted there can survive — and probes again. If *both* fail, root tun
mode is abandoned and the normal VPN path takes over.

**DNS has no NAT stage.** An earlier draft DNAT-ed every DNS packet to the tunnel address.
That chain is dead code: the mangle exemptions (our uid, bypass uids, loopback, `rtn0`,
already-marked) are a strict superset of what the nat chain exempted, so the DNAT could
never fire. Routing the resolvers in (`routeSetup`) is the whole mechanism, and it is the
one that preserves reply source addresses.

### 2. Kernel-level firewall offload

When root is available, the app installs a dedicated iptables/ip6tables chain:

```text
RETHINK_OUT
```

…and hooks it at the **front** of `OUTPUT`:

```sh
iptables -w -N RETHINK_OUT 2>/dev/null || true
iptables -w -C OUTPUT -j RETHINK_OUT 2>/dev/null || iptables -w -I OUTPUT 1 -j RETHINK_OUT
iptables -w -A RETHINK_OUT -m owner --uid-owner <uid> -j DROP
```

Each uid the firewall has *unconditionally* denied gets one `owner`-match `DROP` rule. From
that moment on, packets from that app never reach the tun device, never reach the Go
engine, never reach Kotlin, and never touch the Room database — the kernel drops them in
`OUTPUT`.

**Only unconditional denials are offloaded.** A verdict that depends on network, screen
state, domain or a timer (for example “block only on metered networks”) must stay in the
tunnel, because the kernel cannot evaluate those conditions on its own. The selection logic
is a pure function in `RootFirewallPolicy.select()` and deliberately errs towards *not*
offloading.

Dropped-packet accounting stays cheap: one batched `iptables -L RETHINK_OUT -vnx -Z`
per polling cycle (`-Z` zeroes the counters as it reads them), parsed by
`RootFirewallPlanner.parseCounters()`.

### 3. Rule lifecycle that survives crashes

`RootRuntime` is a small state machine over a `CommandRunner` interface:

| Operation | Behaviour |
| --- | --- |
| `activate()` | probe for root → select the root power profile → **flush any stale `RETHINK_OUT` rules** left by a process that died without teardown → hook the chain |
| `sync(desired)` | emit only the symmetric difference (`RootFirewallPlanner.diff`) — an unchanged firewall costs **zero** root commands |
| `counters()` | one batched `iptables -L … -vnx -Z` across both families |
| `deactivate()` | flush + unhook + destroy the chain, then restore the non-root power profile; stays engaged if the shell fails, so a half-torn-down state is never pretended away |

Activation always flushes first, so rules written by a previous process can never outlive
it. Root detection (`RootDetector`) caches a **grant for 5 minutes** and a **denial for
30 minutes**, so a device without root is not re-probed on every tunnel restart.

#### One `su` per process, not one per command

`ProcessCommandRunner` opens a **single long-lived root shell** (`ShellSession`) and writes
every root command to its stdin, terminated by a marker line that carries the exit code.
Until now each command forked its own `su`, so a counters poll (every 90 s), a firewall
sync and a tun re-establish each re-issued a superuser request — on a rooted device that is
exactly what the superuser app repeats as *"Rethink is given root level permissions"*, over
and over.

* The shell is opened lazily and reused; `su` forks again only if it dies (idle timeout,
  revoked grant, killed by the superuser app), and the command is retried once on the
  replacement shell.
* A command that times out **kills the shell** rather than holding the root lock forever,
  and a daemon thread drains stdout continuously, so `iptables -L -vnx` over a large rule
  set can neither fill a pipe nor wedge the session.
* **This is an optimisation, not a requirement.** Not every `su` hands a shell its stdin —
  the AOSP-style `su` on some emulators and ROMs runs each command with stdin on
  `/dev/null`. The first session attempt proves the shell answers a no-op with exit 0; if
  it does not, the runner records the device as one-fork-per-command and uses the original
  path (`su -c '<command>'` / `su <who> sh -c '<command>'`, dialect probed once and cached
  on a hit) for the rest of the process. Nothing about the root path changed for those
  devices beyond one extra failed attempt at startup.

### 4. Power profile

Polling intervals were hard-coded constants scattered across subsystems. They are now read
from a single `PowerProfile`, selected by the `PowerGovernor` singleton:

| Subsystem | Non-root (`vpn`) | Root (`root`) |
| --- | ---: | ---: |
| Connectivity re-check | 15 s | 61 s |
| Network settle delay | 1 s | 3 s |
| Global HTTP proxy re-check | 2 min | 10 min |
| WireGuard/proxy ping | 60 s | 307 s |
| Network-log flush window | 2.5 s | 13 s |
| App list refresh | 3 h | 12 h |
| Data-usage rollup | 20 min | 61 min |
| RPN proxy refresh | 45 min | 181 min |
| Pause countdown tick | 1 s | 5 s |
| Kernel rule poll | 30 s | 90 s |
| Network events | handled inline | debounced |

Two deliberate choices:

* **The `vpn` profile is byte-for-byte today’s behaviour.** Existing tests
  (`ConnectionMonitorTest` and friends) assert those exact constants, and non-root users
  see no change whatsoever.
* **Root intervals are deliberately *not* multiples of each other** (61 s, 307 s, 90 s…),
  so the polling phases drift apart instead of lining up and waking the CPU in a single
  burst.

Consumers were changed to read the profile instead of a literal:
`ConnectionMonitor`, `GlobalProxyHandler`, `WgProxyPingController`, `NetLogBatcher`,
`PauseTimer`.

### 5. A switch in the UI

**Settings → Tunnel settings → “Root mode”** (default **on**).

* On: the service probes for root when the tunnel starts. If root is granted, the kernel
  firewall and the root power profile are activated, and the tun is taken from root rather
  than from the system. If it is **not** granted, the app logs
  `root mode requested but unavailable; using tun firewall` / `root tun unavailable (…);
  using VpnService.establish()`, restores the non-root profile and continues exactly as
  upstream does.
* Off: root is never probed, the chain and the root routing rules are torn down, and the
  non-root profile is used.

The preference is persisted as `root_mode_enabled` (`PersistentState.rootModeEnabled`).
Flipping it raises `vpnRestartTrigger`, so the tunnel is rebuilt with the other
implementation immediately rather than at the next incidental restart.

---

## What still runs in the Go engine

The tun device is now opened by root, but **it is still handed to firestack**. The Go
engine keeps doing DNS, proxying, per-domain rules and every network/screen/domain
conditional verdict — byte-for-byte the same code as upstream. What changed is only *who
created the interface and how packets get into it*.

Equally unchanged:

* **The non-root path is untouched.** With root mode off, or root unavailable, the code
  falls through to `VpnService.establish()` and behaves exactly like upstream.
* **Rule selection stays in Kotlin.** The kernel only ever sees unconditional denials.
* **The one descriptor is handed out as a `dup`**, so downstream detach/close semantics
  are identical in both modes.

---

## Using it

1. Install one of the APKs from [Releases](../../releases) (sideload; the release build is
   signed with the Android debug keystore).
2. First run: skip the welcome pages and the tour.
3. Tap **START** → accept the Android “Connection request” dialog → the app shows
   **PROTECTED**. With root granted there is **no key icon** — the tunnel is `rtn0`,
   owned by the app.
4. **Settings → Tunnel settings → Root mode** to enable/disable the root path. Toggling it
   rebuilds the tunnel straight away.
5. If the device has a working `su`, `adb logcat` will show `root tun established, …` and
   `rootFirewall` engaging. If it does not, you will see the fallback messages and the app
   behaves exactly like upstream.

---

## Building

Requirements:

| Tool | Version used |
| --- | --- |
| JDK | 17 |
| Android Gradle Plugin | 9.4.x |
| Gradle wrapper | 9.6.0 |
| compileSdk / targetSdk | 37 |
| minSdk | 23 |
| NDK | 28.2.13676358 |

`local.properties` must point at your SDK:

```properties
sdk.dir=/path/to/Android/Sdk
```

### Unit tests + debug APK (what was verified)

```sh
./gradlew :app:testFdroidFullDebugUnitTest
./gradlew :app:assembleFdroidFullDebug
```

### Lint (CI gate; `abortOnError = true`)

```sh
./gradlew :app:lintFdroidFullDebug
# 0 errors, 0 fatal
```

### Optimised (R8) APK, signed with the debug keystore

```sh
./gradlew :app:assembleFdroidFullReleaseDebug
```

> The `fdroid`/`play` *release* build types need a `keystore.properties` file; this fork
> does not ship one, so `releaseDebug` is the build type used for public APKs. It runs the
> same R8 minification as `release` but is signed with `~/.android/debug.keystore`, which
> makes it sideloadable.

Outputs land in `app/build/outputs/apk/fdroidFull/<buildType>/`.

### The `rtn` helper

The helper is plain C with no dependencies beyond bionic, so it needs no CMake — one clang
invocation per ABI:

```sh
app/src/main/cpp/build.sh        # NDK=... optional, falls back to local.properties
```

It writes `app/src/main/assets/rtn/<abi>/rtn` and is reproducible: rebuilding with the NDK
above produces byte-identical binaries to the ones checked in.

> **Tip:** long Gradle invocations are best launched detached so they are not killed by a
> shell timeout:
> `(setsid nohup ./gradlew :app:testFdroidFullDebugUnitTest > /tmp/test.log 2>&1 < /dev/null &)`

---

## Testing

### Unit tests — **1334 tests, 71 classes, 0 failures**

```text
./gradlew :app:testFdroidFullDebugUnitTest
BUILD SUCCESSFUL
1334 tests, 0 failed, 71 classes
```

Baseline upstream snapshot (first commit) was **1229 tests / 68 classes, 5 failures**:
three JVM out-of-memory failures and two pre-existing test bugs. All five are fixed below,
and this fork adds **105 new tests** across eight new classes:

| Test class | Tests | Covers |
| --- | ---: | --- |
| `RootTunPlannerTest` | 18 | link/route/mangle command generation, table-50 flush, fwmark rule id, resolver routing, teardown idempotence, **no nat rules at all** |
| `RootFirewallPlannerTest` | 19 | hook/flush/install/diff command generation, `-Z` counter parsing |
| `RootFirewallPolicyTest` | 14 | which uids are (and are not) eligible for offload |
| `RootPowerProfileTest` | 9 | `vpn()` equals the historical constants; `root()` values |
| `RootRuntimeTest` | 20 | activate / sync / counters / deactivate state machine, stale-rule flush |
| `RootDetectorTest` | 10 | `su` probe, 5 min grant cache, 30 min denial cache |
| `ShellSessionTest` | 9 | the shared root shell: marker/exit-code protocol, stderr, no-trailing-newline output, output past the pipe buffer, timeout kills the shell |
| `ProcessCommandRunnerTest` | 6 | the dispatcher: one `su` fork for every root command in a session, one fork per command when `su` refuses stdin, both `su` dialects, missing/failing `su` reported as denied |

Pre-existing test failures were fixed along the way:

* `RpnProxyManagerTest` — missing `AppConfig` registration (`appConfig$delegate` was never
  stubbed).
* An intermittent `UncaughtExceptionsBeforeTest` — `BraveVPNService.signalStopService()`
  spawned a coroutine that outlived the test’s Koin scope and threw
  `KoinApplication has not been started`. The spawn is now wrapped in try/catch, and
  `BraveVPNServiceLifecycleTest.tearDown()` destroys the service before stopping Koin.
* `app/build.gradle.kts` sets `maxHeapSize = "2g"` for unit tests (three tests OOMed on the
  default heap).

### Instrumented tests (emulator, `tablet_api35`, Android 35 google_apis x86_64)

```text
./gradlew :app:connectedFdroidFullDebugAndroidTest
71 tests, 13 failures
```

Those 13 failures are **pre-existing and environmental**. The same run on the untouched
baseline commit (working tree stashed) produced **the identical 71 tests / identical 13
failures**:

```text
AppInfoActivityTest (4), ConfigChangeTest, CoreNavigationTest,
DnsDetailNavigationTest, FirewallActivityTest, HomeScreenActivityTest (2),
NetworkLogsActivityTest, SummaryStatisticsFragmentTest, ThemeChangeTest
```

They are Espresso assertions about empty first-run data and onboarding state on a wiped
tablet emulator — none of them touch the code this fork changes.

### Runtime smoke test (on-device)

On the same emulator, with the built APK:

* App launched, onboarding skipped, VPN started → `VpnService` established **tun0/tun1**.
* Home screen reported **PROTECTED**, DNS connected to `RDNS Default`, live throughput and
  rule counters updating.
* **Zero** `FATAL EXCEPTION`s.
* Root probe correctly returned *unavailable* (an untrusted app cannot execute `su` on this
  image) and the app logged
  `root mode requested but unavailable; using tun firewall`, then continued on the tun
  firewall — i.e. the fallback path works end-to-end.

### Kernel rule validation (real `iptables`)

Every command the firewall planner generates was executed as root against Android’s own
`iptables v1.8.10 (legacy)` and `ip6tables` on the emulator:

| Command | Result |
| --- | --- |
| `ensureHook` (`-N`, `-C`, `-I OUTPUT 1`) | exit 0, idempotent |
| `flush` (`-F`) | exit 0 |
| `dropUid` (`-A … -m owner --uid-owner`) | exit 0 |
| `-C` idempotency check | `same` |
| `readCounters` (`-L RETHINK_OUT -vnx -Z`) | prints `owner UID match 10213`, parses correctly |
| `removeHook` (`-D OUTPUT`, `-F`, `-X`) | chain gone, hook absent |
| `ip6tables` same chain name | accepted |

The `ip`/mangle commands in `RootTunPlanner` are unit-tested for shape and idempotence
(`RootTunPlannerTest`) and, as of this revision, have also been executed for real on a
rooted image — see the next section.

### Root tun + per-app firewall — verified end-to-end (rooted emulator)

Everything above ran on an Android 35 `google_apis` x86_64 emulator where the app *is*
granted root (`/system/xbin/su`). Traffic was generated with a tiny on-device probe that
performs a DNS lookup and an HTTP fetch **as an arbitrary uid**, so the firewall could be
observed acting on a specific app rather than on `adb shell`.

| Check | Result |
| --- | --- |
| `rtn0` created by the `rtn` helper, `UP`, `10.111.222.1/24` | pass |
| `9000: from all fwmark 0xf0000000/0xf0000000 lookup 50` in `ip rule` | pass |
| `ip route show table 50` = `default dev rtn0` + the device's resolvers | pass |
| DNS **through** the tunnel, as root *and* as a non-privileged app uid | `NOERROR`, 2 answers |
| HTTP/TCP **through** the tunnel as an app uid | `HTTP/1.1 200 OK`, body delivered |
| No VPN key icon, no system-owned `tun0`/`tun1` | pass |

**Per-app firewall, A/B.** With `org.chromium.webview_shell` (uid 10111) in the
foreground, the probe is run twice:

| `AppInfo.connectionStatus` for uid 10111 | `RETHINK_OUT` | probe as 10111 | probe as `adb shell` |
| --- | --- | --- | --- |
| `ALLOW` (3) | *(empty)* | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |
| `BOTH` (0) | `-A RETHINK_OUT -m owner --uid-owner 10111 -j DROP` | `connect: Operation now in progress` (SYN dropped) | `HTTP/1.1 200 OK` |

The blocked app's packets are stopped by the **kernel**, never reaching the tun, the Go
engine or Kotlin — which is the whole point of the offload. Reverting the rule and
restarting the tunnel removes the stale `DROP`: `activate()` runs `reset()` (hook + flush)
before anything is installed, so even a process killed with the rule armed comes back
clean.

### Known limitations of root mode

* **The tun path cannot attribute a flow to an app.** firestack hands the flow to Kotlin
  with `uid = -1` and the `ConnectivityManager.getConnectionOwnerUid` fallback does not
  resolve it either, so you will see `preflow: returning uid: -1` in logcat. This does
  *not* affect blocking: unconditional per-app denials never reach the tun, they are
  dropped by uid in `RETHINK_OUT`. It does affect *conditional* verdicts (metered /
  unmetered, per-app IP and domain rules), which fall back to the tun path, and it means
  connection logs cannot name the app behind a flow.
* **ICMP is not answered.** `ping` resolves its name through the tunnel but receives no
  echo replies. TCP and UDP are unaffected (verified above).
* **Kernel drop counters are consumed by the app.** `counters()` reads with `-Z`, so a
  bare `iptables -L RETHINK_OUT` between two polls prints `0` even right after a drop.

---

## Release APKs

Published as GitHub Releases, tagged (e.g. `v1.0.0`, `v1.1.0`).

| APK | ABI |
| --- | --- |
| `app-fdroid-full-arm64-v8a-*.apk` | arm64-v8a (most devices) |
| `app-fdroid-full-armeabi-v7a-*.apk` | 32-bit ARM |
| `app-fdroid-full-x86_64-*.apk` | x86_64 (emulators, ChromeOS) |
| `app-fdroid-full-x86-*.apk` | x86 |
| `app-fdroid-full-universal-*.apk` | all of the above |

The `fdroid` flavor is **de-Googled**: no Firebase, no Google Play Services. `versionName`
comes from `git describe --tags`, so **tag before building** and it matches the release tag.

Install with `adb install <apk>` or from a file manager.

---

## Verifying the root behaviour yourself

With a rooted device (or an emulator where the app can obtain root), start the tunnel with
Root mode on, then:

```sh
# the tunnel interface exists and owns the builder's address
adb shell su -c 'ip -br addr show rtn0'

# the builder's routes and the system resolvers are in table 50,
# selected by our fwmark rule at priority 9000
adb shell su -c 'ip route show table 50'
adb shell su -c 'ip rule show'

# everything except our uid is marked; protect() is the first RETURN
adb shell su -c 'iptables -w -t mangle -L RETHINK_MARK -vnx'

# the kernel firewall chain (only unconditional denials appear here)
adb shell su -c 'iptables -w -L RETHINK_OUT -vnx'
adb shell su -c 'iptables -w -L RETHINK_OUT -vnx | grep "owner UID match"'

# per-app firewall: block an app in the app's firewall UI, then drive traffic as
# that uid and watch it fail while another uid still succeeds
adb shell 'su --as <uid> -c "probe http example.com /"'   # -> connect hangs
adb shell 'probe http example.com /'                      # -> HTTP/1.1 200 OK
# unblock, restart the tunnel: activate() flushes first, the DROP rule is gone

# the app's own log lines
adb logcat -d | grep -E 'root tun|root mode|rootFirewall'
```

What you should **not** see with root granted: a VPN key icon in the status bar, or a
`tun0`/`tun1` owned by the system.

Tearing the tunnel down should leave **no** `rtn0`, **no** `ip rule`, **no** `RETHINK_MARK`
chain and **no** `RETHINK_OUT` chain. Activation always flushes first, so even a crash
leaves nothing behind after the next start.

---

## Safety, limitations and rollback

* **Offload is conservative by design.** Anything conditional (network type, screen state,
  domain, temporary allowance, self/protected uids) is never offloaded — it stays in the
  tunnel where the full rule engine can evaluate it. If in doubt, the policy does *not*
  offload.
* **No root → no behaviour change.** The probe fails fast (cached for 30 minutes), the app
  logs the fallback, the power profile reverts to `vpn`, and the app is byte-for-byte the
  upstream experience.
* **Every root tun failure falls back to the real VPN.** No root, no `su`, a `su` build
  that will not run our binary, a SELinux denial, a helper timeout, a routing failure — all
  return null, tear the root routing rules down *before* `VpnService.establish()` runs (the
  two path selections must never overlap, or traffic would silently split), and the app
  keeps working as a normal VPN.
* **Rollback is one switch.** Turning Root mode off tears down `RETHINK_OUT`,
  `RETHINK_MARK`, table 50 and the fwmark rules and restores the non-root profile. Even if
  that fails, the next activation flushes.
* **Limitations of root mode** are listed under
  [Known limitations of root mode](#known-limitations-of-root-mode): the tun path cannot
  name the app behind a flow (`uid = -1`), ICMP is not answered, and the kernel drop
  counters are drained by the app's own poll.
* **Debug-key signature.** Release APKs are signed with the Android debug keystore, so they
  are not upgrade-compatible with a Play Store / F-Droid install of upstream.

---

## Repository layout

```text
app/src/main/java/com/celzero/bravedns/
├── root/
│   ├── RootShell.kt             ShellResult, CommandRunner, ProcessCommandRunner,
│   │                            RootState, RootDetector (su probe + TTL cache);
│   │                            API-23-safe process wait/destroy
│   ├── RootTunManager.kt        tun descriptor via rtn helper (SCM_RIGHTS), helper
│   │                            extraction/probe/fallback install, configure/teardown
│   ├── RootTunPlanner.kt        Pure command strings: linkSetup, routeSetup (table 50),
│   │                            mangleSetup (protect() replacement), teardown
│   ├── RootFirewallPlanner.kt   Pure command strings: ensureHook, flush, diff,
│   │                            parseCounters, removalScript
│   ├── RootFirewallPolicy.kt    Pure uid selection: only unconditional denials
│   ├── RootPowerProfile.kt      PowerProfile.vpn() / root() + PowerGovernor
│   └── RootRuntime.kt           activate / sync / counters / deactivate state machine
├── service/BraveVPNService.kt   Wiring: startRootRuntime, syncRootFirewall, rootTunEstablish,
│                                releaseRootTun, protectUnderlying, onDestroy, pref listener
├── service/PersistentState.kt   root_mode_enabled preference
└── ui/activity/TunnelSettingsActivity.kt  + activity_tunnel_settings.xml  Toggle UI

app/src/main/cpp/
├── rtn.c                        Helper: open /dev/net/tun, create rtn0, send the fd
├── build.sh                     One clang per ABI → ../assets/rtn/<abi>/rtn
app/src/main/assets/rtn/<abi>/rtn  Prebuilt helpers (byte-reproducible via build.sh)

app/src/test/java/com/celzero/bravedns/root/   6 unit-test classes (88 tests)
app/src/test/java/com/celzero/bravedns/…       2 upstream test fixes
```

---

## Credits

* **[RethinkDNS](https://github.com/celzero/rethink-app)** — the application itself.
  Apache-2.0, see [LICENSE](LICENSE).
* **[firestack](https://github.com/celzero/firestack)** — the Go tunnel/DNS/firewall core.
* **[WireGuard for Android](https://www.wireguard.com/)** — tunnel implementation.

This fork only adds the root execution path, the root tun, the power profile and the tests
described above; every other line is upstream work.
