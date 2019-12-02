/* urlprint: print url log of interface traffic
	  by james@ustc.edu.cn 2017.09.10
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#define MAXLEN 			2048
#define MAX_PACKET_SIZE		65535

struct _EtherHeader {
	uint16_t destMAC1;
	uint32_t destMAC2;
	uint16_t srcMAC1;
	uint32_t srcMAC2;
	uint32_t VLANTag;
	uint16_t type;
	int32_t payload;
} __attribute__ ((packed));

typedef struct _EtherHeader EtherPacket;

int daemon_proc = 0;
int debug = 0;
int print_time = 0;

char dev_name[MAXLEN];
char pcap_fname[MAXLEN];
char filter_string[MAXLEN];
int TotalPorts = 0;
int rev_port = 0;

#define MAXPORTS 64

unsigned int Ports[MAXPORTS];

void add_port(int port)
{
	if (TotalPorts >= MAXPORTS)
		return;
	Ports[TotalPorts] = port;
	TotalPorts++;
}

void get_ports(char *s)
{
	char *p = s;
	while (*p) {
		while (*p && (!isdigit(*p)))
			p++;	// skip blank
		if (*p == 0)
			break;
		int port = atoi(p);
		add_port(port);
		while (*p && isdigit(*p))
			p++;	// skip port
	}
}

int port_in_list(int port)
{
	if (TotalPorts == 0)
		return 1;	// if list is empty, all ports in list
	int i;
	for (i = 0; i < TotalPorts; i++)
		if (Ports[i] == port)
			return 1;
	return 0;
}

void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLEN];

	errno_save = errno;	/* value caller might want printed */
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		syslog(level, "%s", buf);
	} else {
		fflush(stdout);	/* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

void err_msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void Debug(const char *fmt, ...)
{
	va_list ap;
	if (debug) {
		va_start(ap, fmt);
		err_doit(0, LOG_INFO, fmt, ap);
		va_end(ap);
	}
	return;
}

void err_quit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

char *stamp(void)
{
	static char st_buf[200];
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;

	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);

	snprintf(st_buf, 200, "%02d%02d %02d:%02d:%02d.%06ld", tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
	return st_buf;
}

void printPacket(EtherPacket * packet, ssize_t packetSize, char *message)
{
	printf("%s ", stamp());

	if ((ntohl(packet->VLANTag) >> 16) == 0x8100)	// VLAN tag
		printf("%s #%04x (VLAN %d) from %04x%08x to %04x%08x, len=%d\n",
		       message, ntohs(packet->type),
		       ntohl(packet->VLANTag) & 0xFFF, ntohs(packet->srcMAC1),
		       ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	else
		printf("%s #%04x (no VLAN) from %04x%08x to %04x%08x, len=%d\n",
		       message, ntohl(packet->VLANTag) >> 16,
		       ntohs(packet->srcMAC1), ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	fflush(stdout);
}

/* from https://github.com/dlundquist/sniproxy/blob/master/src/tls.c, thanks dustin@null-ptr.net */
/* Copyright (c) 2011 - 2013, Dustin Lundquist <dustin@null-ptr.net> */

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

int parse_server_name_extension(const uint8_t * data, size_t data_len, char **hostname)
{
        size_t pos = 2;         /* skip server name list length */
        size_t len;

        while (pos + 3 < data_len) {
                len = ((size_t) data[pos + 1] << 8) + (size_t) data[pos + 2];

                if (pos + 3 + len > data_len)
                        return -5;

                switch (data[pos]) {    /* name type */
                case 0x00:      /* host_name */
                        *hostname = malloc(len + 1);
                        if (*hostname == NULL) {
                                printf("malloc() failure");
                                return -4;
                        }

                        strncpy(*hostname, (const char *)(data + pos + 3), len);

                        (*hostname)[len] = '\0';

                        return len;
                default:
                        printf("Unknown server name extension name type: %" PRIu8, data[pos]);
                }
                pos += 3 + len;
        }
        /* Check we ended where we expected to */
        if (pos != data_len)
                return -5;

        return -2;
}

int parse_extensions(const uint8_t * data, size_t data_len, char **hostname)
{
        size_t pos = 0;
        size_t len;

        /* Parse each 4 bytes for the extension header */
        while (pos + 4 <= data_len) {
                /* Extension Length */
                len = ((size_t) data[pos + 2] << 8) + (size_t) data[pos + 3];

                /* Check if it's a server name extension */
                if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
                        /* There can be only one extension of each type, so we break
                           our state and move p to beinnging of the extension here */
                        if (pos + 4 + len > data_len)
                                return -5;
                        return parse_server_name_extension(data + pos + 4, len, hostname);
                }
                pos += 4 + len; /* Advance to the next extension header */
        }
        /* Check we ended where we expected to */
        if (pos != data_len)
                return -5;

        return -2;
}

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
static int parse_tls_header(const uint8_t * data, size_t data_len, char **hostname)
{
        uint8_t tls_content_type;
        uint8_t tls_version_major;
        uint8_t tls_version_minor;
        size_t pos = TLS_HEADER_LEN;
        size_t len;

        if (hostname == NULL)
                return -3;

        /* Check that our TCP payload is at least large enough for a TLS header */
        if (data_len < TLS_HEADER_LEN)
                return -1;

        /* SSL 2.0 compatible Client Hello
         *
         * High bit of first byte (length) and content type is Client Hello
         *
         * See RFC5246 Appendix E.2
         */
        if (data[0] & 0x80 && data[2] == 1) {
		if(debug)
                	printf("Received SSL 2.0 Client Hello which can not support SNI.");
                return -2;
        }

        tls_content_type = data[0];
        if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
#ifdef DEBUG2
                printf("Request did not begin with TLS handshake.");
#endif
                return -5;
        }
        tls_version_major = data[1];
        tls_version_minor = data[2];
        if (tls_version_major < 3) {
		if(debug)
                	printf("Received SSL %" PRIu8 ".%" PRIu8 " handshake which can not support SNI.", tls_version_major, tls_version_minor);

                return -2;
        }

        /* TLS record length */
        len = ((size_t) data[3] << 8) + (size_t) data[4] + TLS_HEADER_LEN;
        data_len = MIN(data_len, len);

        /* Check we received entire TLS record length */
        if (data_len < len)
                return -1;

        /*
         * Handshake
         */
        if (pos + 1 > data_len) {
                return -5;
        }
        if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
#ifdef DEBUG3
                printf("Not a client hello");
#endif

                return -5;
        }
        /* Skip past fixed length records:
           1        Handshake Type
           3        Length
           2        Version (again)
           32       Random
           to       Session ID Length
         */
        pos += 38;

        /* Session ID */
        if (pos + 1 > data_len)
                return -5;
        len = (size_t) data[pos];
        pos += 1 + len;

        /* Cipher Suites */
        if (pos + 2 > data_len)
                return -5;
        len = ((size_t) data[pos] << 8) + (size_t) data[pos + 1];
        pos += 2 + len;

        /* Compression Methods */
        if (pos + 1 > data_len)
                return -5;
        len = (size_t) data[pos];
        pos += 1 + len;

        if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
#ifdef DEBUG3
                printf("Received SSL 3.0 handshake without extensions");
#endif
                return -2;
        }

        /* Extensions */
        if (pos + 2 > data_len)
                return -5;
        len = ((size_t) data[pos] << 8) + (size_t) data[pos + 1];
        pos += 2;

        if (pos + len > data_len)
                return -5;
        return parse_extensions(data + pos, len, hostname);
}
char *process_tcp_packet(char *buf, int len, char *ip)
{
	static char url[MAXLEN];
	char *p, *purl, *host;
	int method;
	url[0] = 0;
	if (len <= 10)
		return url;
	buf[len - 1] = 0;
	if (memcmp(buf, "GET ", 4) == 0) {
		method = 0;	// GET 
		purl = buf + 4;
	} else if (memcmp(buf, "POST ", 5) == 0) {
		method = 1;	// POST
		purl = buf + 5;
	} else			// return null
		return url;
	p = purl;
	while (*p && (*p != '\r') && (*p != '\n'))
		p++;
	if (*p) {
		*p = 0;
		p++;
	}
	if (strncasecmp(purl, "http://", 7) == 0) {	// proxy request
		snprintf(url, MAXLEN - 1, "%s %s", method == 0 ? "GET" : "POST", purl);
		return url;
	}
	host = memmem(p, len - (p - buf), "Host: ", 6);
	if (host) {
		host = host + 6;
		char *phost = host;
		while (*phost && (*phost != '\r') && (*phost != '\n'))
			phost++;
		*phost = 0;
		while( (phost > host) && (*(phost-1)=='.'))  // skip host last ...
			phost--;
		if(*purl=='/')
			snprintf(url, MAXLEN - 1, "%s http://%s%s", method == 0 ? "GET" : "POST", host, purl);
		else
			snprintf(url, MAXLEN - 1, "%s http://%s/%s", method == 0 ? "GET" : "POST", host, purl);
	} else {
		if(*purl=='/')
			snprintf(url, MAXLEN - 1, "%s http://%s%s", method == 0 ? "GET" : "POST", ip, purl);
		else
			snprintf(url, MAXLEN - 1, "%s http://%s/%s", method == 0 ? "GET" : "POST", ip, purl);
	}
	return url;
}

void process_packet(const char *buf, int len)
{
	unsigned char *packet;
	int port;
	char sip[MAXLEN], dip[MAXLEN];
	char *url;

	if (debug)
		printf("pkt, len=%d\n", len);
	if (len < 54)
		return;
	packet = (unsigned char *)(buf + 12);	// skip ethernet dst & src addr
	len -= 12;
	if (debug)
		printf("proto: 0x%02X%02X\n", packet[0], packet[1]);

	if ((packet[0] == 0x81) && (packet[1] == 0x00)) {	// skip 802.1Q tag 0x8100
		if (debug)
			printf("802.1Q pk\n");
		packet += 4;
		len -= 4;
	}
	if ((packet[0] == 0x08) && (packet[1] == 0x00)) {	// IPv4 packet 0x0800
		if (debug)
			printf("ipv4 pk\n");
		packet += 2;
		len -= 2;

		struct iphdr *ip = (struct iphdr *)packet;
		if (ip->version != 4)
			return;	// check ipv4
		if (ntohs(ip->frag_off) & 0x1fff)
			return;	// not the first fragment
		if (ip->protocol != IPPROTO_TCP)
			return;	// not tcp packet
		if (ntohs(ip->tot_len) > len)
			return;	// tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr *)(packet + ip->ihl * 4);
		if (tcph->syn)
			return;
		if (!tcph->ack)
			return;
		port = ntohs(tcph->dest);
		if (debug)
			printf("tcp pkt, dport=%d\n", port);
		if (!(rev_port ^ port_in_list(port)))
			return;
		int tcp_payload_len = len - ip->ihl * 4 - tcph->doff * 4;
		if (tcp_payload_len <= 10)
			return;
		inet_ntop(AF_INET, (void *)&ip->daddr, dip, 200);

		if (port == 443) {
			 char *hostname;
                        int n = parse_tls_header(packet + ip->ihl * 4 + tcph->doff * 4, tcp_payload_len, &hostname);
#ifdef DEBUG3
                        printf("tls get %d\n", n);
#endif
                        if (n <= 0)
                                return;
#ifdef DEBUG3
                        printf("tls get hostname: %s\n", hostname);
#endif
			inet_ntop(AF_INET, (void *)&ip->saddr, sip, 200);
			if (print_time)
				printf("%s %s:%d - %s:%d GET https://%s/\n", stamp(), sip, ntohs(tcph->source), dip, port, hostname);
			else
				printf("%s:%d - %s:%d GET https://%s/\n", sip, ntohs(tcph->source), dip, port, hostname);
			
			return;
		}


		url = process_tcp_packet((char *)packet + ip->ihl * 4 + tcph->doff * 4, tcp_payload_len, dip);

		if (url[0]) {
			inet_ntop(AF_INET, (void *)&ip->saddr, sip, 200);
			if (print_time)
				printf("%s %s:%d - %s:%d %s\n", stamp(), sip, ntohs(tcph->source), dip, port, url);
			else
				printf("%s:%d - %s:%d %s\n", sip, ntohs(tcph->source), dip, port, url);
		}
	} else if ((packet[0] == 0x86) && (packet[1] == 0xdd)) {	// IPv6 packet, 0x86dd
		if (debug)
			printf("ipv6 pk\n");
		packet += 2;
		len -= 2;

		struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
		if ((ip6->ip6_vfc & 0xf0) != 0x60)
			return;	// check ipv6
		if (ip6->ip6_nxt != IPPROTO_TCP)
			return;	// not tcp packet
		if (ntohs(ip6->ip6_plen) > len)
			return;	// tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr *)(packet + 40);
		port = ntohs(tcph->dest);
		if (tcph->syn)
			return;
		if (!tcph->ack)
			return;
		if (!(rev_port ^ port_in_list(port)))
			return;
		int tcp_payload_len = len - 40 - tcph->doff * 4;
		if (tcp_payload_len <= 10)
			return;

		inet_ntop(AF_INET6, (void *)&ip6->ip6_dst, dip, 200);

                if (port == 443) {
                         char *hostname;
                        int n = parse_tls_header(packet + 40 + tcph->doff * 4, tcp_payload_len, &hostname);
#ifdef DEBUG3
                        printf("tls get %d\n", n);
#endif
                        if (n <= 0)
                                return;
#ifdef DEBUG3
                        printf("tls get hostname: %s\n", hostname);
#endif
			inet_ntop(AF_INET6, (void *)&ip6->ip6_src, sip, 200);
                        if (print_time)
                                printf("%s %s:%d - %s:%d GET https://%s/\n", stamp(), sip, ntohs(tcph->source), dip, port, hostname);
                        else
                                printf("%s:%d - %s:%d GET https://%s/\n", sip, ntohs(tcph->source), dip, port, hostname);

                        return;
                }

		url = process_tcp_packet((char *)packet + 40 + tcph->doff * 4, tcp_payload_len, dip);

		if (url[0]) {
			inet_ntop(AF_INET6, (void *)&ip6->ip6_src, sip, 200);
			if (print_time)
				printf("%s [%s]:%d - [%s]:%d %s\n", stamp(), sip, ntohs(tcph->source), dip, port, url);
			else
				printf("[%s]:%d - [%s]:%d %s\n", sip, ntohs(tcph->source), dip, port, url);
		}
	}
}

void process_pcap_packet(void)
{
	pcap_t *handle;
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	const char *buf;
	int len;
	if (dev_name[0])
		handle = pcap_open_live(dev_name, MAX_PACKET_SIZE, 0, 1000, errbuf);
	else
		handle = pcap_open_offline(pcap_fname, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap open %s error %s\n", dev_name[0] ? dev_name : pcap_fname, errbuf);
		exit(0);
	}
	if (filter_string[0]) {
		struct bpf_program pgm;
		if (pcap_compile(handle, &pgm, filter_string, 1, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "pcap_filter compile error\n");
			exit(0);
		}
		if (pcap_setfilter(handle, &pgm) == -1) {
			fprintf(stderr, "pcap_setfilter error\n");
			exit(0);
		}
	}
	while (1) {
		int r = pcap_next_ex(handle, &header, (const u_char **)&buf);
		if (r == 0)
			continue;
		if (r < 0)
			exit(0);
		len = header->len;
		if (len <= 0)
			continue;
/*		if (debug) {
			printPacket((EtherPacket *) (buf), len, "from local  rawsocket:");
		}
*/
		process_packet(buf, len);
	}
}

void usage(void)
{
	printf("Usage:\n");
	printf("./urlprint [ -d ] [ -t ] -i ifname | -r pcap_file [ -p port1,port2 ] [ -x ] [ -f filter_string ] \n");
	printf(" options:\n");
	printf("    -d               enable debug\n");
	printf("    -t               print timestamp\n");
	printf("    -i ifname        interface to monitor\n");
	printf("    -p port1,port2   tcp ports to monitor\n");
	printf("    -x !port list,   revers port select\n");
	printf("    -f filter_string pcap filter\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "dti:r:p:xf:")) != EOF)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 't':
			print_time = 1;
			break;
		case 'i':
			strncpy(dev_name, optarg, MAXLEN);
			break;
		case 'r':
			strncpy(pcap_fname, optarg, MAXLEN);
			break;
		case 'p':
			get_ports(optarg);
			break;
		case 'x':
			rev_port = 1;
			break;
		case 'f':
			strncpy(filter_string, optarg, MAXLEN);
			break;
		}
	if ((dev_name[0] == 0) && (pcap_fname[0] == 0))
		usage();
	if (debug) {
		printf("         debug = 1\n");
		printf("       pcap if = %s\n", dev_name);
		printf("     pcap file = %s\n", pcap_fname);
		printf("      revports = %d\n", rev_port);
		printf("         ports = ");
		int n;
		if (TotalPorts == 0)
			printf("all");
		else
			for (n = 0; n < TotalPorts; n++)
				printf("%d ", Ports[n]);
		printf("\n");
	}

	process_pcap_packet();

	return 0;
}
