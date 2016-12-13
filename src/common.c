/* Copyright 2010 Ivo Smits <Ivo@UCIS.nl>. All rights reserved.
   Redistribution and use in source and binary forms, with or without modification, are
   permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   The views and conclusions contained in the software and documentation are those of the
   authors and should not be interpreted as representing official policies, either expressed
   or implied, of Ivo Smits.*/

#include "common.h"

#include <pwd.h>
#include <grp.h>
#ifndef HAVE_NETINET_IN_H
#endif
#include <sys/ioctl.h>
#include <poll.h>
#include <netdb.h>
#include <stdlib.h>

char* (*getconf)(const char*) = getenv;
int debug = 0;
static int gargc = 0;
static char** gargv = NULL;

int errorexit(const char* text) {
	fprintf(stderr, "%s\n", text);
	return -1;
}
int errorexit2(const char* text, const char* error) {
	fprintf(stderr, "%s: %s\n", text, error);
	return -1;
}
int errorexitp(const char* text) {
	perror(text);
	return -1;
}

void print_header() {
	fprintf(stderr, "UCIS QuickTun "QT_VERSION" (c) 2010-2013 Ivo Smits <Ivo@UCIS.nl>\n");
	fprintf(stderr, "More information: http://wiki.ucis.nl/QuickTun\n");
}

static int is_all_zero(void* buf, int size) {
	int i;
	char* bb = (char*)buf;
	for (i = 0; i < size; i++) if (bb[i] != 0) return 0;
	return 1;
}
static int sockaddr_is_zero_address(sockaddr_any* sa) {
	int af = sa->any.sa_family;
	if (af == AF_INET) return is_all_zero(&sa->ip4.sin_addr, sizeof(struct in_addr));
	if (af == AF_INET6) return is_all_zero(&sa->ip6.sin6_addr, sizeof(struct in6_addr));
	return is_all_zero(sa, sizeof(sockaddr_any));
}
static int sockaddr_set_port(sockaddr_any* sa, int port) {
	port = htons(port);
	int af = sa->any.sa_family;
	if (af == AF_INET) sa->ip4.sin_port = port;
	else if (af == AF_INET6) sa->ip6.sin6_port = port;
	else return errorexit("Unknown address family");
	return 0;
}
static int sockaddr_equal(sockaddr_any* a, sockaddr_any* b) {
	if (a->any.sa_family != b->any.sa_family) return 0;
	if (a->any.sa_family == AF_INET) return a->ip4.sin_port == b->ip4.sin_port && a->ip4.sin_addr.s_addr == b->ip4.sin_addr.s_addr;
	if (a->any.sa_family == AF_INET6) return a->ip6.sin6_port == b->ip6.sin6_port && memcmp(&a->ip6.sin6_addr, &b->ip6.sin6_addr, sizeof(struct in6_addr)) == 0 && a->ip6.sin6_scope_id == b->ip6.sin6_scope_id;
	return memcmp(a, b, sizeof(sockaddr_any)) == 0;
}
static void sockaddr_to_string(sockaddr_any* sa, char* str, int strbuflen) {
	if (sa->any.sa_family == AF_INET) {
		if (!inet_ntop(AF_INET, &sa->ip4.sin_addr, str, strbuflen)) str[0] = 0;
		int i = strlen(str);
		snprintf(str + i, strbuflen - i, ":%u", ntohs(sa->ip4.sin_port));
	} else if (sa->any.sa_family == AF_INET6) {
		if (!inet_ntop(AF_INET6, &sa->ip6.sin6_addr, str, strbuflen)) str[0] = 0;
		int i = strlen(str);
		snprintf(str + i, strbuflen - i, "%%%d:%u", sa->ip6.sin6_scope_id, ntohs(sa->ip6.sin6_port));
	} else {
		strncpy(str, "Unknown AF", strbuflen);
	}
	str[strbuflen - 1] = 0;
}

static int init_udp(struct qtsession* session) {
	char* envval;
	fprintf(stderr, "Initializing UDP socket...\n");
	struct addrinfo *ai_local = NULL, *ai_remote = NULL;
	unsigned short af = 0;
	int ret;
	if ((envval = getconf("LOCAL_ADDRESS"))) {
		if ((ret = getaddrinfo(envval, NULL, NULL, &ai_local))) return errorexit2("getaddrinfo(LOCAL_ADDRESS)", gai_strerror(ret));
		if (!ai_local) return errorexit("LOCAL_ADDRESS lookup failed");
		if (ai_local->ai_addrlen > sizeof(sockaddr_any)) return errorexit("Resolved LOCAL_ADDRESS is too big");
		af = ai_local->ai_family;
	}
	if ((envval = getconf("REMOTE_ADDRESS"))) {
		if ((ret = getaddrinfo(envval, NULL, NULL, &ai_remote))) return errorexit2("getaddrinfo(REMOTE_ADDRESS)", gai_strerror(ret));
		if (!ai_remote) return errorexit("REMOTE_ADDRESS lookup failed");
		if (ai_remote->ai_addrlen > sizeof(sockaddr_any)) return errorexit("Resolved REMOTE_ADDRESS is too big");
		if (af && af != ai_remote->ai_family) return errorexit("Address families do not match");
		af = ai_remote->ai_family;
	}
	if (!af) af = AF_INET;
	int sa_size = sizeof(sockaddr_any);
	if (af == AF_INET) sa_size = sizeof(struct sockaddr_in);
	else if (af == AF_INET6) sa_size = sizeof(struct sockaddr_in6);
	int sfd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
	if (sfd < 0) return errorexitp("Could not create UDP socket");
	sockaddr_any udpaddr;
	memset(&udpaddr, 0, sizeof(udpaddr));
	udpaddr.any.sa_family = af;
	if (ai_local) memcpy(&udpaddr, ai_local->ai_addr, ai_local->ai_addrlen);
	int port = 2998;
	if ((envval = getconf("LOCAL_PORT"))) port = atoi(envval);
	if (sockaddr_set_port(&udpaddr, port)) return -1;
	if (bind(sfd, &udpaddr.any, sa_size)) return errorexitp("Could not bind socket");
	memset(&udpaddr, 0, sizeof(udpaddr));
	udpaddr.any.sa_family = af;
	if (ai_remote) memcpy(&udpaddr, ai_remote->ai_addr, ai_remote->ai_addrlen);
	if (!ai_remote || sockaddr_is_zero_address(&udpaddr)) {
		session->remote_float = 1;
	} else {
		session->remote_float = getconf("REMOTE_FLOAT") ? 1 : 0;
		port = 2998;
		if ((envval = getconf("REMOTE_PORT"))) port = atoi(envval);
		if (sockaddr_set_port(&udpaddr, port)) return -1;
		session->remote_addr = udpaddr;
		if (session->remote_float) {
			session->remote_float = 2;
		} else {
			if (connect(sfd, &udpaddr.any, sa_size)) return errorexitp("Could not connect socket");
		}
	}
	if (ai_local) freeaddrinfo(ai_local);
	if (ai_remote) freeaddrinfo(ai_remote);
	session->fd_socket = sfd;
	return sfd;
}

static int init_tuntap(struct qtsession* session) {
	char* envval;
	fprintf(stderr, "Initializing tun/tap device...\n");
	int ttfd; //Tap device file descriptor
	int tunmode = 0;
	if ((envval = getconf("TUN_MODE"))) tunmode = atoi(envval);
	session->use_pi = 0;
	if (tunmode && (envval = getconf("USE_PI"))) session->use_pi = atoi(envval);
#if defined(__linux__)
	struct ifreq ifr; //required for tun/tap setup
	memset(&ifr, 0, sizeof(ifr));
	if ((ttfd = open("/dev/net/tun", O_RDWR)) < 0) return errorexitp("Could not open tun/tap device file");
	if ((envval = getconf("INTERFACE"))) strcpy(ifr.ifr_name, envval);
	ifr.ifr_flags = tunmode ? IFF_TUN : IFF_TAP;
	if (!session->use_pi) ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(ttfd, TUNSETIFF, (void *)&ifr) < 0) return errorexitp("TUNSETIFF ioctl failed");
#elif defined SOLARIS
	int ip_fd = -1, if_fd = -1, ppa = 0;
	if ((ttfd = open("/dev/tun", O_RDWR)) < 0) return errorexitp("Could not open tun device file");
	if ((ip_fd = open("/dev/ip", O_RDWR, 0)) < 0) return errorexitp("Could not open /dev/ip");
	if ((envval = getconf("INTERFACE"))) {
		while (*envval && !isdigit((int)*envval)) envval++;
		ppa = atoi(envval);
	}
	if ((ppa = ioctl(ttfd, TUNNEWPPA, ppa)) < 0) return errorexitp("Could not assign new PPA");
	if ((if_fd = open("/dev/tun", O_RDWR, 0)) < 0) return errorexitp("Could not open tun device file again");
	if (ioctl(if_fd, I_PUSH, "ip") < 0) return errorexitp("Could not push IP module");
	if (ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0) return errorexitp("Could not set PPA");
	if (ioctl(ip_fd, I_LINK, if_fd) < 0) return errorexitp("Could not link TUN device to IP");
#else
	if (!(envval = getconf("INTERFACE"))) envval = "/dev/tun0";
	if ((ttfd = open(envval, O_RDWR)) < 0) return errorexitp("Could not open tun device file");
	if (tunmode) {
		int i = IFF_POINTOPOINT | IFF_MULTICAST;
		ioctl(ttfd, TUNSIFMODE, &i);
#if defined(__OpenBSD__)
		if (!session->use_pi) session->use_pi = 2;
#else
		i = session->use_pi ? 1 : 0;
		ioctl(ttfd, TUNSIFHEAD, &i);
#endif
	}
#endif
	if ((envval = getconf("TUN_UP_SCRIPT"))) system(envval);
	session->fd_dev = ttfd;
	return ttfd;
}

void hex2bin(unsigned char* dest, const char* src, const int count) {
	int i;
	for (i = 0; i < count; i++) {
		if (*src >= '0' && *src <= '9') *dest = *src - '0';
		else if (*src >= 'a' && * src <='f') *dest = *src - 'a' + 10;
		else if (*src >= 'A' && * src <='F') *dest = *src - 'A' + 10;
		src++; *dest = *dest << 4;
		if (*src >= '0' && *src <= '9') *dest += *src - '0';
		else if (*src >= 'a' && *src <= 'f') *dest += *src - 'a' + 10;
		else if (*src >= 'A' && *src <= 'F') *dest += *src - 'A' + 10;
		src++; dest++;
	}
}

static int drop_privileges() {
	char* envval;
	struct passwd *pw = NULL;
	if ((envval = getconf("SETUID"))) {
		pw = getpwnam(envval);
		if (!pw) return errorexitp("getpwnam");
	}
	if ((envval = getconf("CHROOT"))) {
		if (chroot(envval)) return errorexitp("chroot");
		if (chdir("/")) return errorexitp("chdir /");
	}
	if (pw) {
		if (setgroups(0, NULL) == -1) return errorexitp("setgroups");
		if (setgid(pw->pw_gid) == -1) return errorexitp("setgid");
		if (setuid(pw->pw_uid) == -1) return errorexitp("setuid");
	}
	return 0;
}

static void qtsendnetworkpacket(struct qtsession* session, char* msg, int len) {
	if (session->remote_float == 0) {
		len = write(session->fd_socket, msg, len);
	} else if (session->remote_float == 2) {
		len = sendto(session->fd_socket, msg, len, 0, (struct sockaddr*)&session->remote_addr, sizeof(sockaddr_any));
	}
}

int qtrun(struct qtproto* p) {
	if (getconf("DEBUG")) debug = 1;
	struct qtsession session;
	session.poll_timeout = -1;
	session.protocol = *p;

	if (init_udp(&session) < 0) return -1;
	int sfd = session.fd_socket;

	session.sendnetworkpacket = qtsendnetworkpacket;

	if (init_tuntap(&session) < 0) return -1;
	int ttfd = session.fd_dev;

	char protocol_data[p->protocol_data_size];
	memset(protocol_data, 0, p->protocol_data_size);
	session.protocol_data = protocol_data;
	if (p->init && p->init(&session) < 0) return -1;

	if (drop_privileges() < 0) return -1;

	fprintf(stderr, "The tunnel is now operational!\n");

	struct pollfd fds[2];
	fds[0].fd = ttfd;
	fds[0].events = POLLIN;
	fds[1].fd = sfd;
	fds[1].events = POLLIN;

	int pi_length = 0;
	if (session.use_pi == 2) pi_length = 4;

	char buffer_raw_a[p->buffersize_raw + pi_length];
	char buffer_enc_a[p->buffersize_enc];
	char* buffer_raw = buffer_raw_a;
	char* buffer_enc = buffer_enc_a;

	while (1) {
		int len = poll(fds, 2, session.poll_timeout);
		if (len < 0) return errorexitp("poll error");
		else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) return errorexit("poll error on tap device");
		else if (fds[1].revents & (POLLHUP | POLLNVAL)) return errorexit("poll error on udp socket");
		if (len == 0 && p->idle) p->idle(&session);
		if (fds[0].revents & POLLIN) {
			len = read(ttfd, buffer_raw + p->offset_raw, p->buffersize_raw + pi_length);
			if (len < pi_length) errorexit("read packet smaller than header from tun device");
			if (session.remote_float == 0 || session.remote_float == 2) {
				len = p->encode(&session, buffer_raw + pi_length, buffer_enc, len - pi_length);
				if (len < 0) return len;
				if (len == 0) continue; //encoding is not yet possible
				qtsendnetworkpacket(&session, buffer_enc + p->offset_enc, len);
			}
		}
		if (fds[1].revents & POLLERR) {
			int out;
			socklen_t slen = sizeof(out);
			getsockopt(sfd, SOL_SOCKET, SO_ERROR, &out, &slen);
			fprintf(stderr, "Received error %d on udp socket\n", out);
		}
		if (fds[1].revents & POLLIN) {
			sockaddr_any recvaddr;
			socklen_t recvaddr_len = sizeof(recvaddr);
			if (session.remote_float == 0) {
			 	len = read(sfd, buffer_enc + p->offset_enc, p->buffersize_enc);
			} else {
				len = recvfrom(sfd, buffer_enc + p->offset_enc, p->buffersize_enc, 0, (struct sockaddr*)&recvaddr, &recvaddr_len);
			}
			if (len < 0) {
				int out;
				socklen_t slen = sizeof(out);
				getsockopt(sfd, SOL_SOCKET, SO_ERROR, &out, &slen);
				fprintf(stderr, "Received end of file on udp socket (error %d)\n", out);
			} else {
				len = p->decode(&session, buffer_enc, buffer_raw + pi_length, len);
				if (len < 0) continue;
				if (session.remote_float != 0 && !sockaddr_equal(&session.remote_addr, &recvaddr)) {
					char epname[INET6_ADDRSTRLEN + 1 + 2 + 1 + 5]; //addr%scope:port
					sockaddr_to_string(&recvaddr, epname, sizeof(epname));
					fprintf(stderr, "Remote endpoint has changed to %s\n", epname);
					session.remote_addr = recvaddr;
					session.remote_float = 2;
				}
				if (len > 0 && session.use_pi == 2) {
					int ipver = (buffer_raw[p->offset_raw + pi_length] >> 4) & 0xf;
					int pihdr = 0;
#if defined linux
					if (ipver == 4) pihdr = 0x0000 | (0x0008 << 16); //little endian: flags and protocol are swapped
					else if (ipver == 6) pihdr = 0x0000 | (0xdd86 << 16);
#else
					if (ipver == 4) pihdr = htonl(AF_INET);
					else if (ipver == 6) pihdr = htonl(AF_INET6);
#endif
					*(int*)(buffer_raw + p->offset_raw) = pihdr;
				}
				if (len > 0) write(ttfd, buffer_raw + p->offset_raw, len + pi_length);
			}
		}
	}
	return 0;
}

static char* getconfcmdargs(const char* name) {
	int i;
	for (i = 1; i < gargc - 2; i++) {
		if (strcmp(gargv[i], "-c")) continue;
		if (strcmp(gargv[i + 1], name)) continue;
		return gargv[i + 2];
	}
	return NULL;
}

static char* getenvdeb(const char* name) {
	char tmp[1024] = "IF_QT_";
	if (strcmp(name, "INTERFACE") == 0) return getenv("IFACE");
	if (strlen(tmp) + strlen(name) >= 1024) {
		fprintf(stderr, "Error: prefixed environment variable name is too long");
		return NULL;
	}
	strcat(tmp, name);
	return getenv(tmp);
}

int qtprocessargs(int argc, char** argv) {
	int i;
	for (i = 1; i < argc; i++) {
		char* a = argv[i];
		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			return errorexit("Please read the documentation at http://wiki.ucis.nl/QuickTun");
		} else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
			return errorexit("UCIS QuickTun "QT_VERSION);
                } else if (!strcmp(a, "--ifupdown")) {
			getconf = getenvdeb;
		} else if (!strcmp(a, "-c")) {
			gargc = argc;
			gargv = argv;
			getconf = getconfcmdargs;
			i += 2;
		} else {
			return errorexit("Unexpected command line argument");
		}
	}
	return 0;
}
