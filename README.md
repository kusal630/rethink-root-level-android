# RethinkDNS — Root Level Edition

A fork of [RethinkDNS for Android](https://github.com/celzero/rethink-app) (firewall + DNS + proxy) that runs as much of its work as possible **as root**, instead of through the per-app VPN tun device — with the explicit goal of cutting battery drain while keeping every feature working.

> **Upstream:** all credit for the application itself goes to the RethinkDNS authors.
> This repository adds a root execution path on top of the upstream snapshot recorded in
> the first commit. See [Credits](#credits).

---

## Contents

- [Why](#why)
- [What root mode does](#what-root-mode-does)
- [What stays in the tunnel, and why](#what-stays-in-the-tunnel-and-why)
- [Power profile](#power-profile)
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

* **Blocked traffic still travels the whole stack.** A denied connection is written into
  the tun, read by firestack, turned into a Kotlin decision, logged, persisted, and only
  then dropped. The CPU has to wake up for traffic that was never going to succeed.
* **The app must poll, because nobody tells it anything.** It owns the tun, so it has to
  re-verify connectivity on a timer, re-flush its own log batches, re-ping its own proxies
  and re-derive its own drop counts — all at fixed, fairly aggressive intervals.
* **Wakelocks and wakeups add up.** Each of those timers is an alarm that can pull the SoC
  out of a low-power state.

Root changes the trade. The kernel can drop a denied packet in `OUTPUT` before it is ever
written to tun, and the platform can deliver connectivity changes to a registered receiver
instead of the app having to ask for them. This fork exploits exactly those two facts.

---

## What root mode does

Everything lives in one new package: **`com.celzero.bravedns.root`** (5 source files,
~710 lines, plus ~950 lines of unit tests).

### 1. Kernel-level firewall offload

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

The **tun device itself is not replaced.** The `VpnService` still establishes the tun and
still hands the fd to firestack; only the *denial* path is short-circuited. See
[What stays in the tunnel](#what-stays-in-the-tunnel-and-why) for why.

### 2. Rule lifecycle that survives crashes

`RootRuntime` is a small state machine over a `CommandRunner` interface:

| Operation | Behaviour |
| --- | --- |
| `activate()` | probe for root → select the root power profile → **flush any stale `RETHINK_OUT` rules** left by a process that died without teardown → hook the chain |
| `sync(desired)` | emit only the symmetric difference (`RootFirewallPlanner.diff`) — an unchanged firewall costs **zero** `su` forks |
| `counters()` | one batched `iptables -L … -vnx -Z` across both families |
| `deactivate()` | flush + unhook + destroy the chain, then restore the non-root power profile; stays engaged if the shell fails, so a half-torn-down state is never pretended away |

Activation always flushes first, so rules written by a previous process can never outlive
it. Root detection (`RootDetector`) caches a **grant for 5 minutes** and a **denial for
30 minutes**, so a device without root is not re-probed on every tunnel restart.

### 3. Power profile

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
* **Root intervals are deliberately *not* multiples of each other** (61 s, 307 s, 307 s…
  90 s), so the polling phases drift apart instead of lining up and waking the CPU in a
  single burst.

Consumers were changed to read the profile instead of a literal:
`ConnectionMonitor`, `GlobalProxyHandler`, `WgProxyPingController`, `NetLogBatcher`,
`PauseTimer`.

### 4. A switch in the UI

**Settings → Tunnel settings → “Root mode”** (default **on**).

* On: the service probes for root when the tunnel starts. If root is granted, the kernel
  firewall and the root power profile are activated. If it is **not** granted, the app logs
  `root mode requested but unavailable; using tun firewall`, restores the non-root profile
  and continues exactly as upstream does.
* Off: root is never probed, the chain is torn down if present, and the non-root profile is
  used.

The preference is persisted as `root_mode_enabled` (`PersistentState.rootModeEnabled`).

---

## What stays in the tunnel, and why

The tun device and the `VpnService` are **not** removed. This is intentional:

1. **SELinux blocks apps from opening `/dev/net/tun`.** The fd must come from
   `VpnService.establish()` via `system_server`.
2. **firestack needs that fd.** `Intra.connect(tunfd, …)` is what runs the DNS, firewall
   verdicts and proxying. Passing the fd over a `SCM_RIGHTS` socket to a root helper was
   evaluated and deliberately dropped: it is a large, fragile change to the hot path for a
   benefit that does not survive contact with SELinux.

So root mode in this fork means **“offload the parts that root makes cheap”** — denials,
accounting and polling cadence — not “re-implement the tunnel as a root firewall”. DNS,
proxying, per-domain rules and everything network/screen/domain-conditional continue to
work exactly as before.

---

## Using it

1. Install one of the APKs from [Releases](../../releases) (sideload; the release build is
   signed with the Android debug keystore).
2. First run: skip the welcome pages and the tour.
3. Tap **START** → accept the Android “Connection request” dialog → the app shows
   **PROTECTED**.
4. **Settings → Tunnel settings → Root mode** to enable/disable the root path.
5. If the device has a working `su`, the tunnel log will show the root firewall engaging.
   If it does not, you will see the fallback message and the app behaves exactly like
   upstream.

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
| CMake | 3.22.1 |

`local.properties` must point at your SDK:

```properties
sdk.dir=/path/to/Android/Sdk
```

### Unit tests + debug APK (what was verified)

```sh
./gradlew :app:testFdroidFullDebugUnitTest
./gradlew :app:assembleFdroidFullDebug
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

> **Tip:** long Gradle invocations are best launched detached so they are not killed by a
> shell timeout:
> `(setsid nohup ./gradlew :app:testFdroidFullDebugUnitTest > /tmp/test.log 2>&1 < /dev/null &)`

---

## Testing

### Unit tests — **1301 tests, 68 classes, 0 failures**

```text
./gradlew :app:testFdroidFullDebugUnitTest
BUILD SUCCESSFUL
1301 tests, 0 failed, 68 classes
```

Baseline upstream snapshot (first commit) was **1229 tests / 5 failures**:
three JVM out-of-memory failures and two pre-existing test bugs. All five are fixed below,
and this fork adds **72 new tests** across five new classes:

| Test class | Covers |
| --- | --- |
| `RootFirewallPlannerTest` | hook/flush/install/diff command generation, `-Z` counter parsing |
| `RootFirewallPolicyTest` | which uids are (and are not) eligible for offload |
| `RootPowerProfileTest` | `vpn()` equals the historical constants; `root()` values |
| `RootRuntimeTest` | activate / sync / counters / deactivate state machine, stale-rule flush |
| `RootDetectorTest` | `su` probe, 5 min grant cache, 30 min denial cache |

Two pre-existing test failures were fixed along the way:

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

Every command the planner generates was executed as root against Android’s own
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

---

## Release APKs

Published as GitHub Releases, tagged (e.g. `v1.0.0`).

| APK | ABI |
| --- | --- |
| `app-fdroid-full-arm64-v8a-*.apk` | arm64-v8a (most devices) |
| `app-fdroid-full-armeabi-v7a-*.apk` | 32-bit ARM |
| `app-fdroid-full-x86_64-*.apk` | x86_64 (emulators, ChromeOS) |
| `app-fdroid-full-x86-*.apk` | x86 |
| `app-fdroid-full-universal-*.apk` | all of the above |

The `fdroid` flavor is **de-Googled**: no Firebase, no Google Play Services. `versionName`
comes from `git describe --tags`, so it matches the release tag.

Install with `adb install <apk>` or from a file manager.

---

## Verifying the root behaviour yourself

With a rooted device (or an emulator where the app can obtain root):

```sh
# chain exists and is hooked before OUTPUT starts dropping
adb shell su -c 'iptables -w -L RETHINK_OUT -vnx'

# your uid should be present only if it was unconditionally denied
adb shell su -c 'iptables -w -L RETHINK_OUT -vnx | grep "owner UID match"'

# the app's own log line when root is granted (vs the fallback message)
adb logcat -d | grep -E 'root mode|rootFirewall'
```

Tearing the tunnel down should leave **no** `RETHINK_OUT` chain and **no** jump in
`OUTPUT`; activation always flushes first, so even a crash leaves nothing behind after the
next start.

---

## Safety, limitations and rollback

* **Offload is conservative by design.** Anything conditional (network type, screen state,
  domain, temporary allowance, self/protected uids) is never offloaded — it stays in the
  tunnel where the full rule engine can evaluate it. If in doubt, the policy does *not*
  offload.
* **No root → no behaviour change.** The probe fails fast (cached for 30 minutes), the app
  logs the fallback, the power profile reverts to `vpn`, and the app is byte-for-byte the
  upstream experience.
* **Rollback is one switch.** Turning Root mode off calls `deactivate()`, which removes the
  chain and the hook and restores the non-root profile. Even if that fails, the next
  activation flushes.
* **The tun device is unchanged**, so DNS, proxying and per-domain rules keep working in
  both modes.
* **Limitations:** the offload path has been validated against real Android `iptables` and
  unit-tested end-to-end over a fake command runner, but *not* exercised on a genuinely
  rooted device in this repository’s CI — no rooted hardware was available. The only thing
  untested there is the last mile (`su` actually granting); everything behind it is.
* **Debug-key signature.** Release APKs are signed with the Android debug keystore, so they
  are not upgrade-compatible with a Play Store / F-Droid install of upstream.

---

## Repository layout

```text
app/src/main/java/com/celzero/bravedns/
├── root/
│   ├── RootShell.kt             ShellResult, CommandRunner, ProcessCommandRunner,
│   │                            RootState, RootDetector (su probe + TTL cache)
│   ├── RootFirewallPlanner.kt   Pure command strings: ensureHook, flush, diff,
│   │                            parseCounters, removalScript
│   ├── RootFirewallPolicy.kt    Pure uid selection: only unconditional denials
│   ├── RootPowerProfile.kt      PowerProfile.vpn() / root() + PowerGovernor
│   └── RootRuntime.kt           activate / sync / counters / deactivate state machine
├── service/BraveVPNService.kt   Wiring: startRootRuntime, syncRootFirewall, builder
│                                exclusion recording, pref listener, counter poll
├── service/PersistentState.kt   root_mode_enabled preference
└── ui/activity/TunnelSettingsActivity.kt  + activity_tunnel_settings.xml  Toggle UI

app/src/test/java/com/celzero/bravedns/root/   5 unit-test classes (72 tests)
app/src/test/java/com/celzero/bravedns/…       2 upstream test fixes
```

---

## Credits

* **[RethinkDNS](https://github.com/celzero/rethink-app)** — the application itself.
  Apache-2.0, see [LICENSE](LICENSE).
* **[firestack](https://github.com/celzero/firestack)** — the Go tunnel/DNS/firewall core.
* **[WireGuard for Android](https://www.wireguard.com/)** — tunnel implementation.

This fork only adds the root execution path, the power profile and the tests described
above; every other line is upstream work.
