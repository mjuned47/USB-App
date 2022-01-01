/* usbredirserver.c simple usb network redirection tcp/ip server (host).

   Copyright 2010-2011 Red Hat, Inc.

   Red Hat Authors:
   Hans de Goede <hdegoede@redhat.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "usbredirhost.h"


#define SERVER_VERSION "usbredirserver " PACKAGE_VERSION

#if !defined(SOL_TCP) && defined(IPPROTO_TCP)
#define SOL_TCP IPPROTO_TCP
#endif
#if !defined(TCP_KEEPIDLE) && defined(TCP_KEEPALIVE) && defined(__APPLE__)
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif

static int verbose = usbredirparser_info;
static int client_fd, running = 1;
static libusb_context *ctx;
static struct usbredirhost *host;

static const struct option longopts[] = {
    { "port", required_argument, NULL, 'p' },
    { "verbose", required_argument, NULL, 'v' },
    { "ipv4", required_argument, NULL, '4' },
    { "ipv6", required_argument, NULL, '6' },
    { "keepalive", required_argument, NULL, 'k' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static void usbredirserver_log(void *priv, int level, const char *msg)
{
    if (level <= verbose)
        fprintf(stderr, "%s\n", msg);
}

static int usbredirserver_read(void *priv, uint8_t *data, int count)
{
    int r = read(client_fd, data, count);
    if (r < 0) {
        if (errno == EAGAIN)
            return 0;
        return -1;
    }
    if (r == 0) { /* Client disconnected */
        close(client_fd);
        client_fd = -1;
    }
    return r;
}

static int usbredirserver_write(void *priv, uint8_t *data, int count)
{
    int r = write(client_fd, data, count);
    if (r < 0) {
        if (errno == EAGAIN)
            return 0;
        if (errno == EPIPE) { /* Client disconnected */
            close(client_fd);
            client_fd = -1;
            return 0;
        }
        return -1;
    }
    return r;
}

static void usage(int exit_code, char *argv0)
{
    fprintf(exit_code? stderr:stdout,
        "Usage: %s [-p|--port <port>] [-v|--verbose <0-5>] "
        "[[-4|--ipv4 ipaddr]|[-6|--ipv6 ipaddr]] "
        "[-k|--keepalive seconds] "
        "<busnum-devnum|vendorid:prodid>\n",
        argv0);
    exit(exit_code);
}

static void invalid_usb_device_id(char *usb_device_id, char *argv0)
{
    fprintf(stderr, "Invalid usb device identifier: %s\n", usb_device_id);
    usage(1, argv0);
}

static void run_main_loop(void)
{
    const struct libusb_pollfd **pollfds = NULL;
    fd_set readfds, writefds;
    int i, n, nfds;
    struct timeval timeout, *timeout_p;

    while (running && client_fd != -1) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        FD_SET(client_fd, &readfds);
        if (usbredirhost_has_data_to_write(host)) {
            FD_SET(client_fd, &writefds);
        }
        nfds = client_fd + 1;

        free(pollfds);
        pollfds = libusb_get_pollfds(ctx);
        for (i = 0; pollfds && pollfds[i]; i++) {
            if (pollfds[i]->events & POLLIN) {
                FD_SET(pollfds[i]->fd, &readfds);
            }
            if (pollfds[i]->events & POLLOUT) {
                FD_SET(pollfds[i]->fd, &writefds);
            }
            if (pollfds[i]->fd >= nfds)
                nfds = pollfds[i]->fd + 1;
        }

        if (libusb_get_next_timeout(ctx, &timeout) == 1) {
            timeout_p = &timeout;
        } else {
            timeout_p = NULL;
        }
        n = select(nfds, &readfds, &writefds, NULL, timeout_p);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }
        memset(&timeout, 0, sizeof(timeout));
        if (n == 0) {
            libusb_handle_events_timeout(ctx, &timeout);
            continue;
        }

        if (FD_ISSET(client_fd, &readfds)) {
            if (usbredirhost_read_guest_data(host)) {
                break;
            }
        }
        /* usbredirhost_read_guest_data may have detected client disconnect */
        if (client_fd == -1)
            break;

        if (FD_ISSET(client_fd, &writefds)) {
            if (usbredirhost_write_guest_data(host)) {
                break;
            }
        }

        for (i = 0; pollfds && pollfds[i]; i++) {
            if (FD_ISSET(pollfds[i]->fd, &readfds) ||
                FD_ISSET(pollfds[i]->fd, &writefds)) {
                libusb_handle_events_timeout(ctx, &timeout);
                break;
            }
        }
    }
    if (client_fd != -1) { /* Broken out of the loop because of an error ? */
        close(client_fd);
        client_fd = -1;
    }
    free(pollfds);
}

static void quit_handler(int sig)
{
    running = 0;
}

int main(int argc, char *argv[])
{
    int o, flags, server_fd = -1;
    char *endptr, *delim;
    int port       = 4000;
    int usbbus     = -1;
    int usbaddr    = -1;
    int usbvendor  = -1;
    int usbproduct = -1;
    int on = 1;
    int keepalive  = -1;
    char *ipv4_addr = NULL, *ipv6_addr = NULL;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } serveraddr;
    struct sigaction act;
    libusb_device_handle *handle = NULL;

    while ((o = getopt_long(argc, argv, "hp:v:4:6:k:", longopts, NULL)) != -1) {
        switch (o) {
        case 'p':
            port = strtol(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "Invalid value for --port: '%s'\n", optarg);
                usage(1, argv[0]);
            }
            break;
        case 'v':
            verbose = strtol(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "Invalid value for --verbose: '%s'\n", optarg);
                usage(1, argv[0]);
            }
            break;
        case '4':
            ipv4_addr = optarg;
            break;
        case '6':
            ipv6_addr = optarg;
            break;
        case 'k':
            keepalive = strtol(optarg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "Invalid value for -k: '%s'\n", optarg);
                usage(1, argv[0]);
            }
            break;
        case '?':
        case 'h':
            usage(o == '?', argv[0]);
            break;
        }
    }
    if (optind == argc) {
        fprintf(stderr, "Missing usb device identifier argument\n");
        usage(1, argv[0]);
    }
    delim = strchr(argv[optind], '-');
    if (delim && delim[1]) {
        usbbus = strtol(argv[optind], &endptr, 10);
        if (*endptr != '-') {
            invalid_usb_device_id(argv[optind], argv[0]);
        }
        usbaddr = strtol(delim + 1, &endptr, 10);
        if (*endptr != '\0') {
            invalid_usb_device_id(argv[optind], argv[0]);
        }
    } else {
        delim = strchr(argv[optind], ':');
        if (!delim || !delim[1]) {
            invalid_usb_device_id(argv[optind], argv[0]);
        }
        usbvendor = strtol(argv[optind], &endptr, 16);
        if (*endptr != ':' || usbvendor <= 0 || usbvendor > 0xffff) {
            invalid_usb_device_id(argv[optind], argv[0]);
        }
        usbproduct = strtol(delim + 1, &endptr, 16);
        /* Product ID 0000 is valid */
        if (*endptr != '\0' || usbproduct < 0 || usbproduct > 0xffff) {
            invalid_usb_device_id(argv[optind], argv[0]);
        }
    }
    optind++;
    if (optind != argc) {
        fprintf(stderr, "Excess non option arguments\n");
        usage(1, argv[0]);
    }

    memset(&act, 0, sizeof(act));
    act.sa_handler = quit_handler;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);

    if (libusb_init(&ctx)) {
        fprintf(stderr, "Could not init libusb\n");
        exit(1);
    }

#if LIBUSB_API_VERSION >= 0x01000106
    libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, verbose);
#else
    libusb_set_debug(ctx, verbose);
#endif

    if (ipv4_addr) {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
    } else {
        server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    }
    if (server_fd == -1) {
        perror("Error creating ip socket");
        exit(1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        perror("Error setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }

    memset(&serveraddr, 0, sizeof(serveraddr));

    if (ipv4_addr) {
        serveraddr.v4.sin_family = AF_INET;
        serveraddr.v4.sin_port   = htons(port);
        if ((inet_pton(AF_INET, ipv4_addr,
                       &serveraddr.v4.sin_addr)) != 1) {
            perror("Error convert ipv4 address");
            exit(1);
        }
    } else {
        serveraddr.v6.sin6_family = AF_INET6;
        serveraddr.v6.sin6_port   = htons(port);
        if (ipv6_addr) {
            if ((inet_pton(AF_INET6, ipv6_addr,
                           &serveraddr.v6.sin6_addr)) != 1) {
                perror("Error convert ipv6 address");
                exit(1);
            }
        } else {
            serveraddr.v6.sin6_addr   = in6addr_any;
        }
    }

    if (bind(server_fd, (struct sockaddr *)&serveraddr,
             sizeof(serveraddr))) {
        perror("Error bind");
        exit(1);
    }

    if (listen(server_fd, 1)) {
        perror("Error listening");
        exit(1);
    }

    while (running) {
        client_fd = accept(server_fd, NULL, 0);
        if (client_fd == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }

        if (keepalive > 0) {
            int optval = 1;
            socklen_t optlen = sizeof(optval);
            if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) == -1) {
                if (errno != ENOTSUP) {
                    perror("setsockopt SO_KEEPALIVE error.");
                    break;
                }
            }
            optval = keepalive;	/* set default TCP_KEEPIDLE time from cmdline */
            if (setsockopt(client_fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) == -1) {
                if (errno != ENOTSUP) {
                    perror("setsockopt TCP_KEEPIDLE error.");
                    break;
                }
            }
            optval = 10;	/* set default TCP_KEEPINTVL time as 10s */
            if (setsockopt(client_fd, SOL_TCP, TCP_KEEPINTVL, &optval, optlen) == -1) {
                if (errno != ENOTSUP) {
                    perror("setsockopt TCP_KEEPINTVL error.");
                    break;
                }
            }
            optval = 3;	/* set default TCP_KEEPCNT as 3 */
            if (setsockopt(client_fd, SOL_TCP, TCP_KEEPCNT, &optval, optlen) == -1) {
                if (errno != ENOTSUP) {
                    perror("setsockopt TCP_KEEPCNT error.");
                    break;
                }
            }
        }

        flags = fcntl(client_fd, F_GETFL);
        if (flags == -1) {
            perror("fcntl F_GETFL");
            break;
        }
        flags = fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
        if (flags == -1) {
            perror("fcntl F_SETFL O_NONBLOCK");
            break;
        }

        /* Try to find the specified usb device */
        if (usbvendor != -1) {
            handle = libusb_open_device_with_vid_pid(ctx, usbvendor,
                                                     usbproduct);
            if (!handle) {
                fprintf(stderr,
                    "Could not open an usb-device with vid:pid %04x:%04x\n",
                    usbvendor, usbproduct);
            } else if (verbose >= usbredirparser_info) {
                libusb_device *dev;
                dev = libusb_get_device(handle);
                fprintf(stderr, "Open a usb-device with vid:pid %04x:%04x on "
                        "bus %03x device %03x\n",
                        usbvendor, usbproduct,
                        libusb_get_bus_number(dev),
                        libusb_get_device_address(dev));
            }
        } else {
            libusb_device **list = NULL;
            ssize_t i, n;

            n = libusb_get_device_list(ctx, &list);
            for (i = 0; i < n; i++) {
                if (libusb_get_bus_number(list[i]) == usbbus &&
                        libusb_get_device_address(list[i]) == usbaddr)
                    break;
            }
            if (i < n) {
                if (libusb_open(list[i], &handle) != 0) {
                    fprintf(stderr,
                        "Could not open usb-device at busnum-devnum %d-%d\n",
                        usbbus, usbaddr);
                }
            } else {
                fprintf(stderr,
                    "Could not find an usb-device at busnum-devnum %d-%d\n",
                    usbbus, usbaddr);
            }
            libusb_free_device_list(list, 1);
        }
        if (!handle) {
            close(client_fd);
            continue;
        }

        host = usbredirhost_open(ctx, handle, usbredirserver_log,
                                 usbredirserver_read, usbredirserver_write,
                                 NULL, SERVER_VERSION, verbose, 0);
        if (!host)
            exit(1);
        run_main_loop();
        usbredirhost_close(host);
        handle = NULL;
    }

    close(server_fd);
    libusb_exit(ctx);
    exit(0);
}
