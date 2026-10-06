/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns / id queue handling routines
 */

#ifndef	Z_DNS_H
#define	Z_DNS_H


#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

/* dns classes, rfc1035
 */

#define	CL_IN		0x01	/* internet class */
#define	CL_CS		0x02	/* CSNET class (obsolete) */
#define	CL_CH		0x03	/* CHAOS class */
#define	CL_HS		0x04	/* hesiod class */
#define	CL_ANY		0xff	/* ANY qclass */


/* dns types, rfc1035
 */

#define	TY_A		0x01	/* a host address */
#define	TY_NS		0x02	/* authoritative nameserver */
#define	TY_MD		0x03	/* mail destination, obsolete */
#define	TY_MF		0x04	/* mail forwarder, obsolete */
#define	TY_CNAME	0x05	/* cannonical name */
#define	TY_SOA		0x06	/* start of a zone */
#define	TY_MB		0x07	/* mailbox domain name (exper.) */
#define	TY_MG		0x08	/* mail group member (exper.) */
#define	TY_MR		0x09	/* mail rename domain (exper.) */
#define	TY_NULL		0x0a	/* NULL pointer (exper.) */
#define	TY_WKS		0x0b	/* well known service */
#define	TY_PTR		0x0c	/* domain name pointer */
#define	TY_HINFO	0x0d	/* host information */
#define	TY_MINFO	0x0e	/* mailbox information */
#define	TY_MX		0x0f	/* mail exchange */
#define	TY_TXT		0x10	/* text strings */
#define	TY_ANY		0xff	/* any types */


/* resource record type values (same as TY_*, just for look in code)
 * rfc1035
 */

#define	RR_A		0x01	/* a host address */
#define	RR_NS		0x02	/* authoritative nameserver */
#define	RR_MD		0x03	/* mail destination, obsolete */
#define	RR_MF		0x04	/* mail forwarder, obsolete */
#define	RR_CNAME	0x05	/* cannonical name */
#define	RR_SOA		0x06	/* start of a zone */
#define	RR_MB		0x07	/* mailbox domain name (exper.) */
#define	RR_MG		0x08	/* mail group member (exper.) */
#define	RR_MR		0x09	/* mail rename domain (exper.) */
#define	RR_NULL		0x0a	/* NULL pointer (exper.) */
#define	RR_WKS		0x0b	/* well known service */
#define	RR_PTR		0x0c	/* domain name pointer */
#define	RR_HINFO	0x0d	/* host information */
#define	RR_MINFO	0x0e	/* mailbox information */
#define	RR_MX		0x0f	/* mail exchange */
#define	RR_TXT		0x10	/* text strings */


/* dns flags (for use with libnet, kinda stupid)
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

#endif

