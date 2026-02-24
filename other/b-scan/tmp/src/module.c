#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <bscan/module.h>
#include <bscan/system.h>

struct _mods mods[MAX_MODULES];
/* modstructures not initialized */
int modcount = -1;

/*
#ifdef HAVE_DLSYM
#define MAKE_DLSYM(x, y) mods[modcount].##x = dlsym(handle, ##y);\
        if ((error = dlerror()) != NULL) {\
                fprintf(stderr, ##y":%s\n", error); return(1); }
#endif
*/

/* I think this is more correct, and also gets rid of some compile warnings.
 * hope this doesn't break anything. -typo */
#ifdef HAVE_DLSYM
#define MAKE_DLSYM(x, y) mods[modcount].x = dlsym(handle, y);\
        if ((error = dlerror()) != NULL) {\
                fprintf(stderr, y":%s\n", error); return(1); }
#endif

/*  SunOS 4.1.3 support */
#ifndef RTLD_NOW
#define RTLD_NOW        0x00001
#endif
/* OpenBSD support */
#ifndef RTLD_GLOBAL
#define RTLD_GLOBAL     0x00000
#endif

/* we really hate theo for this shit of dl* work */
#if defined(__OpenBSD__)
# if !(defined(__mips) || defined(__powerpc))
#  define DLSYM_AOUT 1
# else
#  define DLSYM_AOUT 0
# endif
#endif
#if DLSYM_AOUT == 1
# define DLSYM_UNDERSCORE "_"
#else
# define DLSYM_UNDERSCORE /**/
#endif


/*
 * init the module structures. NOT the modules! 
 */
void
init_modules ()
{
    int c = 0;

    while (c < MAX_MODULES)
    {
	mods[c].init = NULL;
	mods[c].fini = NULL;
	mods[c].musage = NULL;
	mods[c].modname = NULL;
	mods[c].modid = 0;
 	mods[c].modarg = NULL;
	mods[c++].callmdl = NULL;
    }
    modcount = 0;
}


/*
 * Load a module
 * Return 0 on success, != 0 on error [no space left, EACCESS, ...]
 */
int
add_module (char *fname, char *modarg)
{
#ifdef HAVE_DLSYM
    void *handle;
    char *error;

    if (modcount == -1)
	init_modules ();

    if (modcount >= MAX_MODULES)
	return (2);		/* array to small! */

    handle = dlopen (fname, RTLD_NOW | RTLD_GLOBAL);

    if ((error = dlerror ()) != NULL)
    {
	fprintf (stderr, "%s\n", error);
	return (1);
    }

    MAKE_DLSYM (init, DLSYM_UNDERSCORE"init");
    MAKE_DLSYM (fini, DLSYM_UNDERSCORE"fini");
    MAKE_DLSYM (musage, DLSYM_UNDERSCORE"musage");
    MAKE_DLSYM (callmdl, DLSYM_UNDERSCORE"callmdl");

    mods[modcount].modid = modcount;
    mods[modcount].modarg = modarg;	/* not encoded arg */

    modcount++;

#endif
    return 0;
}

/*
 * split a 'space seperated string' into many arguements
 * decode esc-sequences
 */
void
split_margs (const char *moptarg, char ***margvp, int *margcp)
{
    char *ptr, *opt;
    int off;
    char ch, ch2;

    if (margcp == NULL)
	return;

    if (margvp == NULL)
	return;

    if (moptarg == NULL)
	return;

    moptarg = strdup(moptarg);

    /*
     * convert "   modname   -a arg1 -b    arg2" to
     *         "modname -a arg1 -b arg2"
     */
    opt = (char *) calloc (1, strlen (moptarg) + 1);
    off = 0;
    ch2 = ' ';
    ptr = (char *) moptarg;
    while ((ch = *ptr++) != '\0')
    {
	if ((ch == ' ') && (ch2 == ' '))
	    continue;
	opt[off++] = ch;
	ch2 = ch;
    }
    if (ch2 == ' ')
	opt[off - 1] = '\0';

    /*
     * split argument-string into char *argv[] array
     */
    *margcp = 0;
    while ((ptr = strchr (opt, ' ')) != NULL)
    {
	*ptr++ = '\0';

	(*margvp) = realloc (*margvp, ((*margcp) + 1) * sizeof (char *));

        ctoreal(opt, opt);	/* decode esc-sequences */
	*(*margvp + *margcp) = opt;
	(*margcp)++;
	opt = ptr;
    }
    (*margvp) = realloc (*margvp, ((*margcp) + 2) * sizeof (char *));
    ctoreal(opt, opt);
    *(*margvp + (*margcp)++) = opt;
    *(*margvp + (*margcp)) = NULL;	/* terminate the array */

}

/*
 * load and init the module.
 * this function can exit
 * return 0 on success
 */
int
loadinit_mod(char *optar)
{
    char **margv = NULL;
    int margc = 0;
    extern int optind;
    extern struct _opt *opt;

    split_margs (optar, &margv, &margc);
    if (add_module (margv[0], optar) == 0)
    {
        int oldoptind = optind;
        int m = modcount - 1;
        optind = 1;

        if (mods[m].init ((char **) &mods[m].modname, margc, margv, opt) != 0)
        {
            fprintf (stderr, "- [%d]: '%s' init FAILED\n",
					 mods[m].modid, margv[0]);
            mods[m].musage ();
            exit (-1);
         } else
            fprintf (stderr, "+ [%d]: '%s' initialized\n",
                                         mods[m].modid, mods[m].modname);
         optind = oldoptind;     /* restore old optind value */
    } else
    {
         fprintf (stderr, "+ [-]; '%s' failed\n", optar);
         exit (-1);
    }

    return(0);
}


