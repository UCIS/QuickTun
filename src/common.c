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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifndef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <netdb.h>
#include <stdlib.h>
#include <net/if.h>
#ifdef linux
	#include <linux/if_tun.h>
	#include <linux/if_ether.h>
#else
	#define ETH_FRAME_LEN 1514
	#include <net/if_tun.h>
	#ifdef SOLARIS
		#include <sys/stropts.h>
		#include <sys/sockio.h>
	#endif
#endif

#define MAX_PACKET_LEN (ETH_FRAME_LEN+4) //Some space for optional packet information

struct qtsession;
struct qtproto {
	int encrypted;
	int buffersize_raw;
	int buffersize_enc;
	int offset_raw;
	int offset_enc;
	int (*encode)(struct qtsession* sess, char* raw, char* enc, int len);
	int (*decode)(struct qtsession* sess, char* enc, char* raw, int len);
	int (*init)(struct qtsession* sess);
	int protocol_data_size;
};
struct qtsession {
	struct qtproto protocol;
	void* protocol_data;
	int fd_socket;
	int fd_dev;
	int remote_float;
	struct sockaddr_in remote_addr;
};

#ifdef COMBINED_BINARY
	extern char* (*getconf)(const char*);
	extern int errorexit(const char*);
	extern int errorexitp(const char*);
	extern void print_header();
	extern void hex2bin(unsigned char*, unsigned char*, int);
	extern int debug;
#else

char* (*getconf)(const char*) = getenv;
int debug = 0;

int errorexit(const char* text) {
	fprintf(stderr, "%s\n", text);
	return -1;
}
int errorexitp(const char* text) {
	perror(text);
	return -1;
}

void print_header() {
	fprintf(stderr, "UCIS QuickTun (c) 2010 Ivo Smits <Ivo@UCIS.nl>\n");
	fprintf(stderr, "More information: http://wiki.ucis.nl/QuickTun\n");
}

int init_udp(struct qtsession* session) {
	char* envval;
	fprintf(stderr, "Initializing UDP socket...\n");
	int sfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sfd < 0) return errorexitp("Could not create UDP socket");
	struct sockaddr_in udpaddr;
	struct hostent *he;
	udpaddr.sin_family = AF_INET;
	udpaddr.sin_addr.s_addr = INADDR_ANY;
	udpaddr.sin_port = htons(2998);
	if (envval = getconf("LOCAL_ADDRESS")) {
		he = gethostbyname(envval);
		if (!he) return errorexit("bind address lookup failed");
		else if (!he->h_addr_list[0]) return errorexit("no address to bind to");
		udpaddr.sin_addr.s_addr = *((unsigned long*)he->h_addr_list[0]);
		udpaddr.sin_family = he->h_addrtype;
	}
	if (envval = getconf("LOCAL_PORT")) {
		udpaddr.sin_port = htons(atoi(envval));
	}
	if (bind(sfd, (struct sockaddr*)&udpaddr, sizeof(struct sockaddr_in))) return errorexitp("Could not bind socket");
	if (!(envval = getconf("REMOTE_ADDRESS"))) {
		session->remote_float = 1;
		//return errorexit("Missing REMOTE_ADDRESS");
	} else {
		session->remote_float = getconf("REMOTE_FLOAT") ? 1 : 0;
		he = gethostbyname(envval);
		if (!he) return errorexit("remote address lookup failed");
		else if (!he->h_addr_list[0]) return errorexit("no address to connect to");
		udpaddr.sin_family = he->h_addrtype;
		udpaddr.sin_addr.s_addr = *((unsigned long*)he->h_addr_list[0]);
		if (udpaddr.sin_addr.s_addr == 0) {
			session->remote_float = 1;
		} else {
			if (envval = getconf("REMOTE_PORT")) {
				udpaddr.sin_port = htons(atoi(envval));
			}
			if (connect(sfd, (struct sockaddr*)&udpaddr, sizeof(struct sockaddr_in))) return errorexitp("Could not connect socket");
			session->remote_addr = udpaddr;
		}
	}
	session->fd_socket = sfd;
	return sfd;
}

int init_tuntap() {
	char* envval;
	fprintf(stderr, "Initializing tun/tap device...\n");
	int ttfd; //Tap device file descriptor
#if defined linux
	struct ifreq ifr; //required for tun/tap setup
	memset(&ifr, 0, sizeof(ifr));
	if ((ttfd = open("/dev/net/tun", O_RDWR)) < 0) return errorexitp("Could not open tun/tap device file");
	if (envval = getconf("INTERFACE")) strcpy(ifr.ifr_name, envval);
	if ((envval = getconf("TUN_MODE")) && atoi(envval)) {
		ifr.ifr_flags = IFF_TUN;
	} else {
		ifr.ifr_flags = IFF_TAP;
	}
	if (!(envval = getconf("USE_PI")) || !atoi(envval)) {
		ifr.ifr_flags |= IFF_NO_PI;
	}
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
#endif
	return ttfd;
}

void hex2bin(unsigned char* dest, unsigned char* src, int count) {
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

int qtrun(struct qtproto* p) {
	if (getconf("DEBUG")) debug = 1;
	struct qtsession session;
	session.protocol = *p;

	if (init_udp(&session) < 0) return -1;
	int sfd = session.fd_socket;
	if (sfd == -1) return -1;

	int ttfd = init_tuntap();
	if (ttfd == -1) return -1;
	session.fd_dev = ttfd;

	char protocol_data[p->protocol_data_size];
	memset(protocol_data, 0, p->protocol_data_size);
	session.protocol_data = &protocol_data;
	if (p->init && p->init(&session) < 0) return -1;

	fprintf(stderr, "The tunnel is now operational!\n");

	struct pollfd fds[2];
	fds[0].fd = ttfd;
	fds[0].events = POLLIN;
	fds[1].fd = sfd;
	fds[1].events = POLLIN;

	struct sockaddr_in recvaddr;

	char buffer_raw_a[p->buffersize_raw];
	char buffer_enc_a[p->buffersize_enc];
	char* buffer_raw = buffer_raw_a;
	char* buffer_enc = buffer_enc_a;

	while (1) {
		int len = poll(fds, 2, -1);
		if (len < 0) return errorexitp("poll error");
		else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) return errorexit("poll error on tap device");
		else if (fds[1].revents & (POLLHUP | POLLNVAL)) return errorexit("poll error on udp socket");
		if (fds[0].revents & POLLIN) {
			len = read(ttfd, buffer_raw + p->offset_raw, p->buffersize_raw);
			if (session.remote_float == 0 || session.remote_float == 2) {
				len = p->encode(&session, buffer_raw, buffer_enc, len);
				if (len < 0) return len;
				if (session.remote_float == 0) {
					len = write(sfd, buffer_enc + p->offset_enc, len);
				} else {
					len = sendto(sfd, buffer_enc + p->offset_enc, len, 0, (struct sockaddr*)&session.remote_addr, sizeof(session.remote_addr));
				}
			}
		}
		if (fds[1].revents & POLLERR) {
			int out;
			len = sizeof(out);
			getsockopt(sfd, SOL_SOCKET, SO_ERROR, &out, &len);
			fprintf(stderr, "Received error %d on udp socket\n", out);
		}
		if (fds[1].revents & POLLIN) {
			socklen_t recvaddr_len = sizeof(recvaddr);
			if (session.remote_float == 0) {
			 	len = read(sfd, buffer_enc + p->offset_enc, p->buffersize_enc);
			} else {
				len = recvfrom(sfd, buffer_enc + p->offset_enc, p->buffersize_enc, 0, (struct sockaddr*)&recvaddr, &recvaddr_len);
			}
			if (len < 0) {
				long long out;
				len = sizeof(out);
				getsockopt(sfd, SOL_SOCKET, SO_ERROR, &out, &len);
				fprintf(stderr, "Received end of file on udp socket (error %d)\n", out);
			} else {
				len = p->decode(&session, buffer_enc, buffer_raw, len);
				if (len < 0) return len;
				if (len != 0 && session.remote_float != 0 && (session.remote_addr.sin_addr.s_addr != recvaddr.sin_addr.s_addr || session.remote_addr.sin_port != recvaddr.sin_port)) {
					fprintf(stderr, "Remote endpoint has changed to %08X:%d\n", ntohl(recvaddr.sin_addr.s_addr), ntohs(recvaddr.sin_port));
					session.remote_addr = recvaddr;
					session.remote_float = 2;
				}
				write(ttfd, buffer_raw + p->offset_raw, len);
			}
		}
	}
	return 0;
}
#endif

