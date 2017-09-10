/* urlprint: print url log of interface traffic
	  by james@ustc.edu.cn 2017.09.10
*/

// kernel use auxdata to send vlan tag, we use auxdata to reconstructe vlan header
#define HAVE_PACKET_AUXDATA 1

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

#define MAXLEN 			2048
#define MAX_PACKET_SIZE		2048

#ifdef HAVE_PACKET_AUXDATA
#define VLAN_TAG_LEN   4
struct vlan_tag {
	u_int16_t vlan_tpid;	/* ETH_P_8021Q */
	u_int16_t vlan_tci;	/* VLAN TCI */
};
#endif

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

int32_t ifindex;

int fdraw;
char dev_name[MAXLEN];
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

/**
 * Open a rawsocket for the network interface
 */
int32_t open_rawsocket(char *ifname, int32_t * rifindex)
{
	unsigned char buf[MAX_PACKET_SIZE];
	int32_t ifindex;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	int n;

	int32_t fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1)
		err_sys("socket %s - ", ifname);

	// get interface index
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
		err_sys("SIOCGIFINDEX %s - ", ifname);
	ifindex = ifr.ifr_ifindex;
	*rifindex = ifindex;

	memset(&sll, 0xff, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
		err_sys("bind %s - ", ifname);

	/* flush all received packets. 
	 *
	 * raw-socket receives packets from all interfaces
	 * when the socket is not bound to an interface
	 */
	int32_t i;
	do {
		fd_set fds;
		struct timeval t;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		memset(&t, 0, sizeof(t));
		i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
		if (i > 0) {
			recv(fd, buf, i, 0);
		};

		Debug("interface %d flushed", ifindex);
	}
	while (i);

	/* Enable auxillary data if supported and reserve room for
	 * reconstructing VLAN headers. */
#ifdef HAVE_PACKET_AUXDATA
	int val = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) == -1 && errno != ENOPROTOOPT) {
		err_sys("setsockopt(packet_auxdata): %s", strerror(errno));
	}
#endif				/* HAVE_PACKET_AUXDATA */

	Debug("%s opened (fd=%d interface=%d)", ifname, fd, ifindex);

	n = 40 * 1024 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
	if (debug) {
		socklen_t ln;
		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0) {
			Debug("RAW socket RCVBUF setting to %d\n", n);
		}
	}

	return fd;
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

char *process_tcp_packet(char *buf, int len, char *ip, int port)
{
	static char url[MAXLEN];
	char *p, *purl, *host;
	int method;
	url[0] = 0;
	if (len <= 10)
		return url;
	buf[len] = 0;
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
	host = memmem(p, len - (p - buf), "Host: ", 6);
	if (host) {
		host = host + 6;
		char *phost = host;
		while (*phost && (*phost != '\r') && (*phost != '\n'))
			phost++;
		*phost = 0;
		if (port != 80)
			snprintf(url, MAXLEN - 1, "%s http://%s:%d%s", method == 0 ? "GET" : "POST", host, port, purl);
		else
			snprintf(url, MAXLEN - 1, "%s http://%s%s", method == 0 ? "GET" : "POST", host, purl);
	} else {
		if (port != 80)
			snprintf(url, MAXLEN - 1, "%s http://%s:%d%s", method == 0 ? "GET" : "POST", ip, port, purl);
		else
			snprintf(url, MAXLEN - 1, "%s http://%s%s", method == 0 ? "GET" : "POST", ip, purl);
	}
	return url;

}

void process_packet(u_int8_t * buf, int len)
{
	u_int8_t *packet;
	int VLANdot1Q = 0;
	int port;
	char sip[MAXLEN], dip[MAXLEN];
	char *url;

	if (len < 54)
		return;
	packet = buf + 12;	// skip ethernet dst & src addr
	len -= 12;

	if ((packet[0] == 0x81) && (packet[1] == 0x00)) {	// skip 802.1Q tag 0x8100
		packet += 4;
		len -= 4;
		VLANdot1Q = 1;
	}
	if ((packet[0] == 0x08) && (packet[1] == 0x00)) {	// IPv4 packet 0x0800
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
		if (!(rev_port ^ port_in_list(port)))
			return;
		int tcp_payload_len = len - ip->ihl * 4 - tcph->doff * 4;
		if (tcp_payload_len <= 10)
			return;

		inet_ntop(AF_INET, (void *)&ip->daddr, dip, 200);

		url = process_tcp_packet((char *)packet + ip->ihl * 4 + tcph->doff * 4, tcp_payload_len, dip, port);

		if (url[0]) {
			inet_ntop(AF_INET, (void *)&ip->saddr, sip, 200);
			printf("%s:%d - %s:%d %s\n", sip, ntohs(tcph->source), dip, port, url);
		}
	} else if ((packet[0] == 0x86) && (packet[1] == 0xdd)) {	// IPv6 packet, 0x86dd
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
		url = process_tcp_packet((char *)packet + 40 + tcph->doff * 4, tcp_payload_len, dip, port);

		if (url[0]) {
			inet_ntop(AF_INET6, (void *)&ip6->ip6_src, sip, 200);
			printf("[%s]:%d - [%s]:%d %s\n", sip, ntohs(tcph->source), dip, port, url);
		}
	}
}

void process_raw_packet(void)
{
	u_int8_t buf[MAX_PACKET_SIZE + VLAN_TAG_LEN];
	int len;

	while (1) {		// read from eth rawsocket
#ifdef HAVE_PACKET_AUXDATA
		struct sockaddr from;
		struct iovec iov;
		struct msghdr msg;
		union {
			struct cmsghdr cmsg;
			char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
		} cmsg_buf;
		msg.msg_name = &from;
		msg.msg_namelen = sizeof(from);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = &cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);
		msg.msg_flags = 0;

		iov.iov_len = MAX_PACKET_SIZE;
		iov.iov_base = buf;
		len = recvmsg(fdraw, &msg, MSG_TRUNC);
		if (len <= 0)
			continue;
		if (len >= MAX_PACKET_SIZE) {
			err_msg("recv long pkt from raw, len=%d", len);
			len = MAX_PACKET_SIZE;
		}
#else
		len = recv(fdraw, buf, MAX_PACKET_SIZE, 0);
#endif
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
	printf("./urlprint [ -d ] -i ifname [ -p port1,port2 ]\n");
	printf(" options:\n");
	printf("    -d             enable debug\n");
	printf("    -i ifname      interface to monitor\n");
	printf("    -p port1,port2 tcp ports to monitor\n");
	printf("    -x !port list, revers port select\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int i = 1;
	int got_one = 0;
	do {
		got_one = 1;
		if (argc - i <= 0)
			break;
		if (strcmp(argv[i], "-d") == 0)
			debug = 1;
		else if (strcmp(argv[i], "-x") == 0)
			rev_port = 1;
		else if (strcmp(argv[i], "-i") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			strncpy(dev_name, argv[i], MAXLEN - 1);
		} else if (strcmp(argv[i], "-p") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			get_ports(argv[i]);
		} else
			got_one = 0;
		if (got_one)
			i++;
	}
	while (got_one);
	if (dev_name[0] == 0)
		usage();
	if (debug) {
		printf("         debug = 1\n");
		printf("    moniter if = %s\n", dev_name);
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

	fdraw = open_rawsocket(dev_name, &ifindex);
	process_raw_packet();

	return 0;
}
