/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns / id queue handling routines
 */

#ifndef	Z_DNS_H
#define	Z_DNS_H


#include <sys/time.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <libnet.h>


/* dns flags (for use with libnet)
 */
#define	DF_RESPONSE	0x8000
#define	DF_OC_STD_Q	0x0000
#define	DF_OC_INV_Q	0x0800
#define	DF_OC_STAT	0x1800
#define	DF_AA		0x0400
#define	DF_TC		0x0200
#define	DF_RD		0x0100
#define	DF_RA		0x0080
#define	DF_RCODE_FMT_E	0x0001
#define	DF_RCODE_SRV_E	0x0002
#define	DF_RCODE_NAME_E	0x0003
#define	DF_RCODE_IMPL_E	0x0004
#define	DF_RCODE_RFSD_E	0x0005


#define	SEG_COUNT_MAX	16

typedef struct libnet_ip_hdr		ip_hdr;
typedef struct libnet_udp_hdr		udp_hdr;
typedef HEADER				dns_hdr;	/* HEADER is in arpa/nameser.h */

void	dns_handle (dns_hdr *dns, unsigned char *dns_data, unsigned int plen, int print);

int	dns_segmentify (dns_hdr *dns, unsigned char *dns_data,
		unsigned char *d_quer[], unsigned char *d_answ[], unsigned char *d_auth[],
		unsigned char *d_addi[]);
void	dns_seg_q (unsigned char **wp, unsigned char *d_arry[], int c, int max_size);
void	dns_seg_rr (unsigned char **wp, unsigned char *d_arry[], int c, int max_size);
int	dns_labellen (unsigned char *wp);

/* dns_printpkt
 *
 * print a packet into the dns window
 */

void	dns_printpkt (char *os, size_t osl, dns_hdr *dns, unsigned char *data,
		unsigned char *d_quer[], unsigned char *d_answ[], unsigned char *d_auth[],
		unsigned char *d_addi[], int print);
int	dns_p_print (char *os, size_t len, dns_hdr *dns, unsigned char *d_quer[],
		unsigned char *d_answ[], unsigned char *d_auth[], unsigned char *d_addi[]);
void	dns_p_q (unsigned char *dns_start, char *os, size_t len, unsigned char *wp);
void	dns_p_rr (unsigned char *dns_start, char *os, size_t len, unsigned char *wp);
void	dns_p_rdata (unsigned char *dns_start, char *rdstr, size_t len, u_short rtype,
		unsigned char *rdp, u_short rdlen);
int	dns_dcd_label (unsigned char *dns_start, unsigned char **qname, char *os, size_t len, int dig);

#endif

