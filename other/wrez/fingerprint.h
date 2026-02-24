
#ifndef	FINGERPRINT_H
#define	FINGERPRINT_H

/* fp_get
 *
 * get a 32 bit host fingerprint hash build out of 'struct utsname' uname
 * output
 *
 * return hash value
 */
unsigned int fp_get (void);

#endif

