
#define MAX_MODULES     8

#define MOD_FIRSTPKG	0x00
#define MOD_RCV		0x01

#define RMOD_OK		0x00
#define RMOD_SKIP	0x01
#define RMOD_ERROR	0x02
#define RMOD_ABRT	0x04

struct _mods
{
    int (*init) (char **, int, char **, void *);  /* init the module stuff */
    int (*fini) ();		/* finish the module */
    void (*musage) ();		/* print out usage informations */
    int (*callmdl) (int, void *);	/* call a function */
    const char *modname;	/* name of the module after init */
    int modid;			/* id of the module. who needs this ? */
    char *modarg;		/* arg to module */
};

int add_module (char *, char *);
void split_margs (const char *, char ***, int *);
int loadinit_mod (char *);

