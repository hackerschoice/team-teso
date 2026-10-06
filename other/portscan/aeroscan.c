/*
 * Begin ugly code.
 * Just a clone of fyodor's osscan.c
 */

#include "portscan.h"

#define DEBUG
#define TCPOPTS "\003\003\012\001\002\004\001\011\010\012" \
		"\077\077\077\077\000\000\000\000\000\000"

#define OPTSLEN 20

unsigned char *opts_ptr = TCPOPTS;

#define ACK_ZERO 0
#define ACK_SEQ 1
#define ACK_INC 2

#define LPORT 3303

#define CLOSEDPORT 38325

struct test {
	unsigned char response;
	unsigned char acktype;
	unsigned char flags;
	unsigned short window;
	unsigned char tcpopts[10];
	unsigned char DF;
} tests[7];

struct test_desc {
	unsigned char flags;
	unsigned char open;
} descs[] = {	{TH_SYN|0x40,1},
		{0,1},
		{TH_SYN|TH_FIN|TH_URG|TH_PUSH,1},
		{TH_ACK,1},
		{TH_SYN,0},
		{TH_ACK,0},
		{TH_FIN|TH_URG|TH_PUSH,0} };

 
void *get_responses(void *arg);
int aerocheck(void);
int parse_line(char *line);
int dump_flags(char *out,unsigned char in);
int find_open(void);
#ifdef DEBUG
int debug_pkt(int resp);
#endif
int dump_opts(char *out,tcp_hdr *tcp);


int		recvd = 0;
u_int32_t	seq;


int aeroscan(void)
{
	unsigned short	port,
			tmp_port;
	int 		i,
			j;
	pthread_t	tid;
	unsigned char	pkt_buffer[1024];
	struct tcpoption tcpopts;

	memcpy(tcpopts.tcpopt_list, opts_ptr, OPTSLEN);

	Print("Determining OS\n");
	if ((port = find_open()) == 0) {
		Print("No open ports !\n");
		return(0);
	}

	seq = libnet_get_prand(PRu32);

	bzero(tests,sizeof(struct test)*7);

	if (pthread_create(&tid, NULL, get_responses, NULL))
		exit(1);

	libnet_build_ip(IP_H + TCP_H + OPTSLEN, 0, libnet_get_prand(PRu16),
		0, 64, IPPROTO_TCP, local.s_addr, dest.s_addr, NULL,
		0, pkt_buffer);

	for (j = 0; j < 2; j++)
	for (i = 0; i < 7; i++) {
		if (tests[i].response) continue;
		if (descs[i].open)
			tmp_port = port;
		else
			tmp_port = CLOSEDPORT;

		/* send packet with options */
		libnet_build_tcp(LPORT + i, tmp_port, seq,
			0, descs[i].flags, 0x512, 0, NULL, 0,
			pkt_buffer + IP_H);

		libnet_insert_tcpo(&tcpopts, OPTSLEN, pkt_buffer);
		libnet_do_checksum(pkt_buffer, IPPROTO_TCP, IP_H + TCP_H + OPTSLEN);
		libnet_write_ip(rawfd, pkt_buffer, IP_H + TCP_H + OPTSLEN);
		usleep(rtt/2);
	}

	usleep(200000);
	pthread_detach(tid);

	if (!aerocheck()) 
		Print("Unknown OS\n");
	return(1);
}

/* begin fuqn messy code... */
int aerocheck(void)
{
	FILE *osfile;
	int linecount = 0;
	int match_count;
	char line[80],os[80];

	osfile = fopen("./osfile","r");
	if (!osfile) return(0);
	match_count = 0;
	while (fgets(line,80,osfile)) {
		linecount++;
		if (*line == '*')  {
			strcpy(os,line+2);
			match_count = 0;
		} 
		if (*line!='F') 
			continue;
		if (match_count == -1) continue;
		if (parse_line(line) != 1) {
			match_count = -1;
		} else {
			match_count++;
			if (match_count==7) {
				Print("%s",os);
				return(1);
			}
		}
	}
	return(0);
}

/* Hiya charlie */
int parse_line(char *line)
{
	int resp,i,j,flag;
	char string[20],*ptr;
	int argcount,argcount2;
	char *args[15],*other_args[5];

	resp = atoi(line+1);
	if (!strncasecmp((line+4),"No Response",11))
		if (!tests[resp].response)
			return(1);
		else
			return(0);

	argcount = parse_args(line+3,args," \r\n",15);
	for (i = (argcount-1);i>= 0; i--) {
/* Flags{AS} Window{2332,4452} */
		ptr = strchr(args[i],'{');
		if (!ptr) continue;
		*ptr = 0;

		/* put the thing to be tested into ascii form */
		if (!strcasecmp("window",args[i])) {
			sprintf(string,"%X",tests[resp].window);
		} else if (!strcasecmp("flags",args[i])) {
			dump_flags(string,tests[resp].flags);
		} else if (!strcasecmp("options",args[i])) {
			strcpy(string,tests[resp].tcpopts);
		} else if (!strcasecmp("ack",args[i])) {
			switch (tests[resp].acktype) {
			case ACK_ZERO:
				sprintf(string,"O");
				break;
			case ACK_SEQ:
				sprintf(string,"S");
				break;
			case ACK_INC:
				sprintf(string,"S++");
			}
		} else if (!strcasecmp("df",args[i])) {
			sprintf(string,"%d",tests[resp].DF);
		} else continue;

		/* Then separate up the possibilitys */
		argcount2 = parse_args(ptr+1,other_args,",}",5);
		flag = 0;
		/* And test each one */
		for (j = argcount2-1;j>=0;j--) 
			if (!strcasecmp(string,other_args[j])) {
				flag = 1; /* Found a match */
				break;
			}
		if (!flag) return(0); /* If a match isnt found... */
	}
	return(1);

}

int dump_opts(char *out,tcp_hdr *tcp)
{
	int	len,
		opcode;
	u_char	*ptr;

	len = (tcp->th_off<<2) - TCP_H;
	ptr = (unsigned char *)tcp + TCP_H;
	while (len>0) {
		opcode = *ptr++;
		len--;
		switch (opcode) {
		case 0:
			*out++='L';
			break;
		case 1:
			*out++='N';
			break;
		case 2:
			*out++='M';
			ptr++;
			if (ntohs(*((u_int16_t *)ptr)) == 265)
				*out++='E';
			ptr+=2;
			len-=3;
			break;
		case 3:
			*out++='W';
			ptr+=2;
			len-=2;
			break;
 		case 8:
			*out++='T';
			ptr+=9;
			len-=9;
		}
	}
	*out++ = 0;
	return(1);
}

int dump_flags(char *out,unsigned char flags)
{
	if (flags&0x40) *out++ = 'X';
	if (flags&TH_ACK) *out++ = 'A';
	if (flags&TH_URG) *out++ = 'U';
	if (flags&TH_PUSH) *out++ = 'P';
	if (flags&TH_RST) *out++ = 'R';
	if (flags&TH_SYN) *out++ = 'S';
	if (flags&TH_FIN) *out++ = 'F';
	*out++ = 0;                          
	return(1);
}

void _get_responses(u_char *inf, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	ip_hdr	*ip;
	tcp_hdr	*tcp;
	int	resp;

	ip = (ip_hdr *)(pkt + dlt_len);

	if (ip->ip_p != IPPROTO_TCP) return;

	tcp = (tcp_hdr *)(pkt + dlt_len + (ip->ip_hl << 2));

	resp = ntohs(tcp->th_dport) - LPORT;
	if ((resp < 0)||(resp > 6)) return;

	if (tests[resp].response != 0) return;

	recvd++;
	tests[resp].response = 1;
	if (ntohl(tcp->th_ack)==seq) 
		tests[resp].acktype = ACK_SEQ;
	else if (ntohl(tcp->th_ack)==(seq+1)) 
		tests[resp].acktype = ACK_INC;
	else 
		tests[resp].acktype = ACK_ZERO;

	tests[resp].flags = tcp->th_flags;
	tests[resp].window = ntohs(tcp->th_win);

	dump_opts(tests[resp].tcpopts,tcp);

	if (ntohs(ip->ip_off)&IP_DF) tests[resp].DF = 1;
	else tests[resp].DF = 0;
#ifdef DEBUG
	debug_pkt(resp);
#endif
	return;
}

void *get_responses(void *arg)
{
	pcap_loop(pcap_d, -1, _get_responses, NULL);
	return NULL;
}

#ifdef DEBUG
int debug_pkt(int resp)
{
	char temp[10],*ptr;
	int blah;

	ptr = temp;
	if (tests[resp].flags&TH_RST) *ptr++='R';
	if (tests[resp].flags&TH_FIN) *ptr++='F';
	if (tests[resp].flags&TH_SYN) *ptr++='S';
	if (tests[resp].flags&TH_ACK) *ptr++='A';
	if (tests[resp].flags&TH_URG) *ptr++='U';
	if (tests[resp].flags&TH_PUSH) *ptr++='P';
	if (tests[resp].flags&0x40) *ptr++='X';
	*ptr=0;

	printf("F%d>Flags{%s} Window{%X}",resp,temp,tests[resp].window);
	printf(" Options{%s} ",tests[resp].tcpopts);
	blah = tests[resp].acktype;
	if (blah == ACK_ZERO) printf("ACK:O ");
	if (blah == ACK_SEQ) printf("ACK:S ");
	if (blah == ACK_INC) printf("ACK:S++ ");
	printf("DF:%d\n",tests[resp].DF);
	return(1);
}
#endif /* DEBUG */

int find_open(void)
{
	int i;

	for (i = 0;i < portcount;i++) {
		if (ports[i].result == P_OPEN)
			return(ports[i].port);
	}
	return(0);
}
