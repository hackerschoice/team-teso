/*
 * Console front-end to the portscanner. GUI front-end to come =)
 */

#define PORTSCAN_MAIN
#include "portscan.h"

int parse_opts(int argc,char **argv);
int init_socks(void);
int start_port_scan(void);
void power_down(void);
int summary(void);
int get_services(void);
int ping_host(void);
int parse_host(char *hostname);
void parse_ports(char *port_list);
void usage(char *program);

/*
 * Gets next ip. Might be from file, or from netmask.
 */

int nextip(void)
{
	char		line[30];
	struct in_addr	temp;

	if (infile) {
		while(fgets(line,30,infile)) 
			if (inet_aton(line,&dest)) return(1);
		fclose(infile);
		return(0);
	}

	temp.s_addr = ntohl(dest.s_addr);
	temp.s_addr ++;
	if (temp.s_addr > ntohl(last_dest.s_addr)) return(0);
	dest.s_addr = htonl(temp.s_addr);
	return(1);
}

int main(int argc,char **argv)
{	

	puts("Portscan by Smiler\n");
	parse_opts(argc,argv);
	init_socks();
	atexit (power_down);
	switch (opts.scanstyle) {
	case SYN:
	case XMAS:
	case FIN:
	case RPC:
		start_port_scan();
		break;
	case P_SYN:
	case P_LINUX:
	case P_PING:
	case P_RPC:
		start_parallel_scan();
		break;
	}
	return(1);
}

/*
 * Wrapper to port_scan() and rpc_scan(). Pings host, gets local ip, etc.
 */

int start_port_scan(void)
{
	int resu;

	do {
		Print("Scanning %s\n",inet_ntoa(dest));
		if ((resu = ping_host()) == 0) {
			if (!opts.scandead) {
				Print("Host is dead =\\\n");
				continue;
			} else {
				rtt = 50000;
			}
		} else if (resu < 0) {
			continue;
		} 
		Print("Lag time: %lu\n",rtt);
		if (opts.scanstyle == RPC)
			rpc_scan();
		else
			port_scan();
		summary();
		if (opts.aeroscan) aeroscan();
	} while(nextip());
	return(1);
}

/*
 * Print summary
 */

int summary(void)
{
	int		ctr;
	struct servent	*srv;

	Print("Open ports:\n");
	for (ctr = 0;ctr < portcount;ctr++)
		if (ports[ctr].result == P_OPEN) {
			Print("%d\t",ports[ctr].port);
			srv = getservbyport(htons(ports[ctr].port),"tcp");
		if (srv)
			Print("%s\n",srv->s_name);
		else
			Print("\n");
		}
	Print("\n");
        return(1);
}


/*
 * See whether host is alive. Sends up to 3 pings.
 * TODO: Exponential backoff.
 */

int ping_host(void)
{
	ip_hdr 			*ip;
	struct sockaddr_in 	dst;
	fd_set 			rset;
	int			sends;
	unsigned char 		icmpbuf[IP_H + ICMP_ECHO_H],
				recvbuf[30];
	struct timeval 		send,
				now,
				tv;

	bzero(&dst,sizeof(struct sockaddr_in));
	dst.sin_addr.s_addr = dest.s_addr;
	dst.sin_port        = 0;
	dst.sin_family      = AF_INET;

	libnet_build_ip(ICMP_ECHO_H, 0, libnet_get_prand(PRu16),
			0, 64, IPPROTO_ICMP, local.s_addr, dest.s_addr,
			NULL, 0, icmpbuf);
	libnet_build_icmp_echo(ICMP_ECHO, 0, libnet_get_prand(PRu16), 0,
		NULL, 0, icmpbuf + IP_H);
	libnet_do_checksum(icmpbuf, IPPROTO_ICMP, ICMP_ECHO_H);
	gettimeofday(&send,NULL);
	if (Sendto(icmpfd,icmpbuf + IP_H,ICMP_ECHO_H,0,(SA *)&dst,sizeof(dst)) < 0) {
		Print("%s is a broadcast, skipping\n\n",inet_ntoa(dest));
		return(-1);
	}
	sends = 1;

	while (1) {
		FD_ZERO(&rset);
		FD_SET(icmpfd,&rset);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		select(icmpfd+1,&rset,NULL,NULL,&tv);
		gettimeofday(&now,NULL);
		if (FD_ISSET(icmpfd,&rset)) {
			recv(icmpfd, recvbuf, sizeof(recvbuf), 0);
			ip = (ip_hdr *)recvbuf;
			if (ip->ip_src.s_addr == dest.s_addr) {
				rtt = TIMEVAL_SUBTRACT(now,send);
				return(1);
			}
		}
		if (TIMEVAL_SUBTRACT(now,send)>(50000)) {
			if (sends > 2) 
				break;
			gettimeofday(&send,NULL);
			Sendto(icmpfd,icmpbuf,8,0,(SA *)&dst,sizeof(dst));
			sends++;
		}
	}
	return(0);
}

int init_socks(void)
{
	int flags;
	struct sockaddr_in sin;
	struct libnet_link_int *llayer;

	rawfd = libnet_open_raw_sock(IPPROTO_RAW);

	if (opts.interface && !memcmp("lo",opts.interface, 2)) {
		local.s_addr = inet_addr("127.0.0.1");
		dlt_len = 4;
		goto skip;
	}

	if (libnet_select_device(&sin, &opts.interface, errbuf) < 0) {
		fprintf(stderr,"libnet: %s", errbuf);
		exit(-1);
	}
	local.s_addr = sin.sin_addr.s_addr;

	/* try and get link layer header length */
	llayer = libnet_open_link_interface(opts.interface, errbuf);
	if (!llayer) {
		fprintf(stderr,"libnet: %s", errbuf);
		exit(-1);
	}	

	dlt_len = llayer->linkoffset;
	libnet_close_link_interface(llayer);
	free(llayer);

skip:
	pcap_d = pcap_open_live(opts.interface, 1024, 1, 0, errbuf);
	if (pcap_d == NULL) {
		puts(errbuf);
		exit(-1);
	}

	icmpfd = Socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	flags = fcntl(icmpfd,F_GETFL);
	if (fcntl(icmpfd,F_SETFL,flags|O_NONBLOCK) < 0) {
		perror("fcntl");
		exit(-1);
	}
	return(1);
}

void power_down(void)
{
	pcap_close(pcap_d);
	close(icmpfd);
	if (infile) fclose(infile);
	if (logfile) fclose(logfile);
	return;
}

int parse_opts(int argc,char **argv)
{
	char opt,*argv0,parallel; 

	local.s_addr  = -1;
	argv0 = strdup(argv[0]);

	opts.randomize= 0;
	opts.scandead = 0;
	opts.aeroscan = 0;	
	opts.scanstyle= SYN;
	opts.frag     = 0;
	opts.verbose  = 0;
	opts.interface = NULL;

	rpc_prog      = 0;

	parallel = 0;
	ports = NULL;
	logfile = infile = NULL;

	while((opt = getopt(argc,argv,"s:i:R:o:rp:dAvfI:")) != -1) {
		switch (opt) {
		case 'i':
			if (!strcmp(optarg,"--")) {
				infile = stdin;
				break;
			}
			infile = fopen(optarg,"r");
			if (infile == NULL) {
				perror("open");
				exit(-1);
			}		
			break;
		case 'I':
			opts.interface = strdup(optarg);
			break;
		case 'o':
			logfile = fopen(optarg,"w");
			if (logfile == NULL) {
				perror("open");
				exit(-1);
			}
			break;
		case 'r':
			opts.randomize++;
			break;
		case 'd':
			opts.scandead++;
			break;
		case 'p':
			parse_ports(optarg);
			break;
		case 'A':
			opts.aeroscan++;
			break;
		case 'f':
			opts.frag++;
			break;
		case 's':
			switch (*optarg) {
			case 'X':
				opts.scanstyle = XMAS;
				break;
			case 'S':
				opts.scanstyle = SYN;
				break;
			case 'F':
				opts.scanstyle = FIN;
				break;
			case 'P':
				opts.scanstyle = P_PING;
				parallel++;
				break;
			case 'R':
				opts.scanstyle = RPC;
				break;
			case 'T':
				opts.scanstyle = P_SYN;
				parallel++;
				break;
			case 'L':
				opts.scanstyle = P_LINUX;
				parallel++;
				break;
			case 'K':
				opts.scanstyle = P_RPC;
				parallel++;
				break;
			}
			break;
		case 'R':
			rpc_prog = atol(optarg);
			break;
		case 'v':
			opts.verbose++;
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	/* sanity checks, etc. */

	if (!argc && !infile)
		usage(argv0);

	if (argc && !parse_host(argv[0]))
		usage(argv0);

	if ((opts.scanstyle == P_SYN)||(opts.scanstyle==P_LINUX)) {
		if (ports == NULL) {
			ports = (port *)xmalloc(sizeof(port));
			ports[0].port = 80;
			portcount = 1;
		} else {
			ports = (port *)realloc(ports,sizeof(port));
			portcount = 1;
		}
		Print("Using port %d to scan\n",ports[0].port);
	}

	if (parallel && opts.aeroscan) {
		printf("Cant have OS detection with parallel scanning!\n");
		exit(-1);
	}

	if ((opts.scanstyle == RPC) && opts.aeroscan) {
		printf("Cant have OS detection with RPC scanning!\n");
		exit(-1);
	}

	if ((ports == NULL) && !parallel)  
		get_services();

	if (!portcount && (opts.scanstyle != P_PING)&&(opts.scanstyle !=P_RPC))
		usage(argv0);

	if ((opts.scanstyle == P_PING)||(opts.scanstyle == P_RPC)) {
		if (ports) { /* Dont need ports for P_PING */
			portcount = 0;
			free(ports);
		}
	}

	if (((opts.scanstyle == RPC) || (opts.scanstyle == P_RPC)) &&
		!rpc_prog)
		usage(argv0);


	switch (opts.scanstyle) {
	case SYN:
		Print("Scanning SYN style\n");
		break;
	case FIN:
		Print("Scanning FIN style\n");
		break;
	case XMAS:
		Print("Scanning XMAS style\n");
		break;
	case P_PING:
		Print("Scanning PING style\n");
		break;
	case RPC:
		Print("Scanning RPC style\n");
		break;
	case P_SYN:
		Print("Scanning P_SYN style\n");
		break;
	case P_LINUX:
		Print("Scanning P_LINUX style\n");
		break;
	case P_RPC:
		Print("Scanning P_RPC style\n");
		break;
	default:
		printf("Bug in parse_opts() !\n");
		exit(-1);	
	}
	if (infile) nextip();
	free(argv0);
	return(1);
}

/*
 * Pull the services from the /etc/services file
 */

int get_services(void)
{
	struct servent *service;

	portcount = 0;
	ports     = NULL;
	setservent(1);
	while ((service = getservent())) {
		if (!strcmp(service->s_proto,"tcp")) {
			portcount++;
			ports = (port *)realloc(ports,sizeof(port)*portcount);
			ports[portcount-1].port = ntohs(service->s_port);
			ports[portcount-1].result = 0;
		}				
	}
	endservent();
	return(1);
}

/*
 * Parse hostname, with or without bit mask
 * www.mci.net/24
 */

int parse_host(char *hostname)
{
	char *ptr;
	int mask;

	if ((ptr = strchr(hostname,'/'))) *ptr = 0;

	if (!(dest.s_addr = libnet_name_resolve(hostname, LIBNET_RESOLVE))){
		herror("resolv");
		return 0;
	}

	if (ptr == NULL) {
		last_dest.s_addr = dest.s_addr;
		return(1);
	} else {
		mask = atoi(ptr+1);
		if ((mask <= 0) || (mask >= 32)) return(0);
		dest.s_addr = ntohl(dest.s_addr);
		last_dest.s_addr = dest.s_addr;
		dest.s_addr &= ~(u_int32_t)((2<<(31-mask))-1);
		last_dest.s_addr |= (u_int32_t)((2<<(31-mask))-1);
		dest.s_addr = htonl(dest.s_addr);
		last_dest.s_addr = htonl(last_dest.s_addr);
	}
	return(1);
}

/*
 * Parse a port list.
 * e.g 1-20,30,40-50,60-100
 */

void parse_ports(char *port_list)
{
	char *list;
        char *ptr1,*ptr2,*endptr;
        int ctr,a,start,end;

        ports = NULL;
        portcount = 0;

	list = xmalloc(strlen(port_list)+2);
	sprintf(list,"%s,",port_list);
        ptr1 = ptr2 = list;
        while((ptr1 = strchr(ptr1,','))) {
                end = start = strtol(ptr2,&endptr,10);
                if (endptr==ptr2) {
                        continue;
                } else if (*endptr=='-') {
                        end = strtol(endptr+1,NULL,10);
                }
                if (start>end) continue;
                a = portcount;
                portcount += end - start + 1;
                ports =(port *)realloc(ports,sizeof(port)*portcount);
                for (ctr = start;ctr <= end; ctr++) {
                        ports[a].port = ctr;
                        ports[a].result = 0;
                        ports[a].send.tv_sec = 0;
                        ports[a].numsends = 0;
                        a++;
                }
                ptr2 = ptr1 + 1;
                ptr1++; /* For the subsequent call to strchr() */
        }
	free(list);
        return;

}

void usage(char *program)
{
	char *ptr;

	if ((ptr = strrchr(program,'/'))) ptr++;
	else ptr = program;

	fprintf(stderr,"Usage: %s hostname <options>\n",ptr);
	fputs(  "\t-i input file\n" \
		"\t-o output file\n" \
		"\t-I interface\n" \
		"\t-p <ports>\n" \
		"\t-d scan even if no ECHO_REPLY is received\n" \
		"\t-r randomize order of scan\n" \
		"\t-f fragmented scanning\n" \
		"\t-sS SYN scanning\n" \
		"\t-sF FIN scanning\n" \
		"\t-sX XMAS scanning\n" \
		"\t-sP Parallel PING scanning\n" \
		"\t-sT Parallel SYN scanning\n" \
		"\t-sL Parallel LINUX scanning\n" \
		"\t-sK Parallel RPC scanning\n" \
		"\t-sR RPC scanning\n"	\
		"\t-R RPC program number\n" \
		"\t-A Remote OS detection\n",stderr);
	exit(0);
}
