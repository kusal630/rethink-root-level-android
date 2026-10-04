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

/*
 * rtn -- create a TUN device and hand its file descriptor to the caller.
 *
 * Why this exists:
 *   An untrusted_app cannot open /dev/net/tun; SELinux denies it. Android's only
 *   sanctioned way to get one is VpnService.establish(), which is exactly what we are
 *   trying to avoid because it puts a permanent VPN indicator on the device and makes
 *   the system own our routing.
 *
 *   When we already hold root we can do what system_server does: open the device, run
 *   TUNSETIFF, and pass the resulting descriptor across a unix socket with SCM_RIGHTS.
 *   The receiving app then feeds the *real* tun fd to firestack's Intra.connect()
 *   exactly as it would have fed the one from VpnService, so nothing downstream
 *   changes: DNS, firewall verdicts, per-domain rules, proxies and connection logging
 *   all keep working byte-for-byte as before.
 *
 * Usage:  rtn (@name | <unix-socket-path>) <ifname> <mtu>
 *         rtn --version
 *
 * Protocol:
 *   1. The app creates a listening AF_UNIX/SOCK_STREAM socket at <unix-socket-path>
 *      (a leading "@" selects the abstract namespace).
 *   2. This program is launched as root; it opens the tun and connects to that path.
 *   3. It sends one SCM_RIGHTS message carrying the tun fd.
 *   4. It prints "OK <ifname>" (or "ERR <reason>") to stdout and exits.
 *
 *   The interface lives exactly as long as the descriptor is open, so this process
 *   may exit immediately after the send.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#define RTN_VERSION "1.1.0"

static void fail(const char *what) {
    /* stdout is read by the app; keep the machine-parseable prefix first. */
    fprintf(stdout, "ERR %s: %s\n", what, strerror(errno));
    fflush(stdout);
    exit(1);
}

static int send_fd(int sock, int fd) {
    struct msghdr msg;
    struct iovec iov;
    char cbuf[CMSG_SPACE(sizeof(int))];
    char dummy = 'x';

    memset(&msg, 0, sizeof(msg));
    memset(cbuf, 0, sizeof(cbuf));

    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    return (int)sendmsg(sock, &msg, 0);
}

/*
 * Connect to the app's listening socket.
 *
 * A leading "@" means the abstract namespace (no file is ever created, so there are no
 * directory permissions or SELinux file labels for the helper to trip over). The app's
 * LocalServerSocket(String) binds there too.
 */
static int connect_to_path(const char *sockpath) {
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) fail("socket");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    int abstract = (sockpath[0] == '@');
    const char *name = abstract ? sockpath + 1 : sockpath;
    size_t namelen = strlen(name);

    if (namelen == 0 || namelen >= sizeof(addr.sun_path)) {
        fprintf(stdout, "ERR socket name too long\n");
        exit(2);
    }

    if (abstract) {
        /* abstract: sun_path[0] is a NUL length byte and the name follows it */
        memcpy(addr.sun_path + 1, name, namelen);
    } else {
        memcpy(addr.sun_path, name, namelen); /* NUL terminator comes from the memset */
    }
    socklen_t addrlen =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + namelen);

    if (connect(sock, (struct sockaddr *)&addr, addrlen) < 0) fail("connect");
    return sock;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", RTN_VERSION);
        return 0;
    }

    if (argc != 4) {
        fprintf(stdout, "ERR usage: rtn <unix-socket-path> <ifname> <mtu>\n");
        return 2;
    }

    const char *sockarg = argv[1];
    const char *ifname = argv[2];
    long mtu = strtol(argv[3], NULL, 10);
    if (ifname[0] == '\0' || strlen(ifname) >= IFNAMSIZ) {
        fprintf(stdout, "ERR ifname too long\n");
        return 2;
    }
    if (mtu <= 0 || mtu > 65535) mtu = 1500;

    if (geteuid() != 0) {
        fprintf(stdout, "ERR not running as root (euid=%d)\n", (int)geteuid());
        return 3;
    }

    /* 1. talk to the app first so a failure never leaves a half-made interface */
    int sock = connect_to_path(sockarg);

    /* 2. open the tun device; this is the step an app is not allowed to do */
    int tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tun < 0) fail("open /dev/net/tun");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(tun, TUNSETIFF, &ifr) < 0) fail("TUNSETIFF");

    /* mtu is applied by the app with `ip link set dev <if> mtu` after the fd arrives */

    /* 3. hand it over */
    if (send_fd(sock, tun) < 0) fail("sendmsg");

    close(tun);
    close(sock);

    fprintf(stdout, "OK %s\n", ifr.ifr_name);
    fflush(stdout);
    return 0;
}
