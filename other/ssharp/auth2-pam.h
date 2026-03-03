/* $Id: auth2-pam.h,v 1.1.1.1 2001/09/19 14:44:59 stealth Exp $ */

#include "includes.h"
#ifdef USE_PAM

int	auth2_pam(Authctxt *authctxt);

#endif /* USE_PAM */
