#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/telnet.h>
#include "ring.h"
#include "defines.h"
#include "externs.h"
#include "environ.h"
#include "array.h"

class enviro {
 protected:
    char *var;	        /* pointer to variable name */
    char *value;        /* pointer to variable's value */
    int doexport;       /* 1 -> export with default list of variables */

    void clean() { if (var) delete []var; if (value) delete []value; }
 public:
    enviro() { var = value = NULL; doexport = 0; }
    ~enviro() { clean(); }

    const char *getname() const { return var; }
    const char *getval() const { return value; }

    void define(const char *vr, const char *vl) {
	clean();
	var = strcpy(new char[strlen(vr)+1], vr);
	value = strcpy(new char[strlen(vl)+1], vl);
    }

    void clear() { clean(); var = value = NULL; }

    void setexport(int ex) { doexport = ex; }
    int getexport() const { return doexport; }
};

static array<enviro> vars;

static enviro *env_find(const char *var) {
    for (int i=0; i<vars.num(); i++) if (vars[i].getname()) {
	if (!strcmp(vars[i].getname(), var))
	    return &vars[i];
    }
    return NULL;
}

static void env_put(const char *var, const char *val, int exp) {
    enviro *ep = env_find(var);
    if (!ep) {
	int x = vars.num();
	vars.setsize(x+1);
	ep = &vars[x];
    }	
    ep->define(var, val);
    ep->setexport(exp);
}

static void env_copy(void) {
    extern char **environ;

    char *s;
    int i;
    
    for (i=0; environ[i]; i++) {
	s = strchr(environ[i], '=');
	if (s) {
	    *s=0;
	    env_put(environ[i], s+1, 0);
	    *s='=';
	}
    }
}

/*
 * Special case for DISPLAY variable.  If it is ":0.0" or
 * "unix:0.0", we have to get rid of "unix" and insert our
 * hostname.
 */
static void env_fix_display(void) {
    enviro *ep = env_find("DISPLAY");
    if (!ep) return;
    ep->setexport(1);

    if (strncmp(ep->getval(), ":", 1) && strncmp(ep->getval(), "unix:", 5)) {
	return;
    }
    char hbuf[256];
    const char *cp2 = strrchr(ep->getval(), ':');
    int maxlen = sizeof(hbuf)-strlen(cp2)-1;
    gethostname(hbuf, maxlen);
    hbuf[maxlen] = 0;  /* ensure null termination */

    /*
     * dholland 7/30/96 if not a FQDN ask DNS
     */
    if (!strchr(hbuf, '.')) {
	struct hostent *h = gethostbyname(hbuf);
	if (h) {
	    strncpy(hbuf, h->h_name, maxlen);
	    hbuf[maxlen] = 0; /* ensure null termination */
	}
    }

    strcat(hbuf, cp2);

    ep->define("DISPLAY", hbuf);
}

/*********************************************** interface ***********/

void env_init(void) {
    env_copy();
    env_fix_display();

    /*
     * If USER is not defined, but LOGNAME is, then add
     * USER with the value from LOGNAME.  By default, we
     * don't export the USER variable.
     */
    if (!env_find("USER")) {
	enviro *ep = env_find("LOGNAME");
	if (ep) env_put("USER", ep->getval(), 0);
    }

    enviro *ep = env_find("PRINTER");
    if (ep) ep->setexport(1);
}

void env_define(const char *var, const char *value) {
    env_put(var, value, 1);
}

void env_undefine(const char *var) {
    enviro *ep = env_find(var);
    if (ep) {
	/*
	 * We don't make any effort to reuse cleared environment spaces.
	 * It's highly unlikely to be worth the trouble.
	 */
	ep->clear();
    }
}

void env_export(const char *var) {
    enviro *ep = env_find(var);
    if (ep) ep->setexport(1);
}

void env_unexport(const char *var) {
    enviro *ep = env_find(var);
    if (ep) ep->setexport(0);
}

void env_send(const char *var) {
    if (my_state_is_wont(TELOPT_ENVIRON)) {
	fprintf(stderr, "Cannot send '%s': Telnet ENVIRON option disabled\n",
		var);
	return;
    }

    enviro *ep = env_find(var);
    if (!ep) {
	fprintf(stderr, "Cannot send '%s': variable not defined\n", var);
	return;
    }
    env_opt_start_info();
    env_opt_add(ep->getname());
    env_opt_end(0);
}

void env_list(void) {
    for (int i=0; i<vars.num(); i++) if (vars[i].getname()) {
	printf("%c %-20s %s\n", vars[i].getexport() ? '*' : ' ',
	       vars[i].getname(), vars[i].getval());
    }
}

void env_iterate(int *iter, int /*exported_only*/) {
    *iter = 0;
}

const char *env_next(int *iter, int exported_only) {
    while (*iter>=0 && *iter<vars.num()) {
	int k = (*iter)++;

	if (!vars[k].getname()) continue; // deleted variable

	if (vars[k].getexport() || !exported_only) {
	    return vars[k].getname();
	}
    }
    return NULL;
}

const char *env_getvalue(const char *var, int exported_only) {
    enviro *ep = env_find(var);
    if (ep && (!exported_only || ep->getexport()))
    	return ep->getval();
    return NULL;
}
