VOID_LINE	"b-scan:"
LOCAL_IP	"SourceAddress"
STATIC_MAC	"StaticSpoofedMacAddress"
SPOOF_MAC	"MacAddress"
INTERFACE	"Interface"
SPREADMODE	"SpreadScan"
PACKETS_PS	"PacketsPerSecond"
PATIENCY	"MaxWaitDelay"
VERBOSE		"Verbose"
LOAD_MOD	"addModule"

%{
/*
 * options with a "bool" are allowed to take "yes", "1" and "true"
 * and the negated counterparts (case insensitive) as argument.
 * all others take their argument as supplyed on the command line.
 *
 *
 * VOID_LINE        lines beginning with this string will be passed directly to stderr
 * LOCAL_IP         -s option 
 * STATIC_MAC       -m        bool
 * SPOOF_MAC        -M
 * INTERFACE        -i
 * SPREADMODE       -X        bool
 * PACKETS_PS       -l
 * PATIENCY         -d
 * VERBOSE          -v        bool
 * MODULE	    -L
 */
%}


%{
#include <bscan/cf_prse.h>
#include <bscan/module.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* defines from bscan.h. why not include? because it sucks! using libnet-config for pff! */
#define OPT_VERB        0x1
#define OPT_SETARP      0x4
#define OPT_SPREADSCAN  0x8


char *
getArg (char *s)
{
  int x = strlen (s);

  while (s[x] != ' ' && s[x] != '\t')
    --x;
  return (s + x + 1);
}


int
evaluateBoolArg (char *s)
{
  s = getArg (s);

  if (!strcasecmp (s, "yes") || !strcasecmp (s, "true") || !strcasecmp (s, "1"))
    return (1);
  else if (!strcasecmp (s, "no") || !strcasecmp (s, "false") || !strcasecmp (s, "0"))
    return (0);
  else
    return (-1);
}


void
set_s_opt (char *s)
{
  s = getArg (s);
  FileOpt.srcAddr = inet_addr (s);
}


void
set_m_opt (char *s)
{
  s = getArg (s);
  if (evaluateBoolArg (s))
    FileOpt.flags |= OPT_SETARP;
}


void set_M_opt (char *s)
{
  s = getArg (s);
  sscanf (s, "%hx:%hx:%hx:%hx:%hx:%hx", &FileOpt.mac[0], &FileOpt.mac[1],
	&FileOpt.mac[2], &FileOpt.mac[3], &FileOpt.mac[4], &FileOpt.mac[5]);
}


void set_i_opt (char *s)
{
  s = getArg (s);
  FileOpt.device = (char *) malloc (strlen (s) + 1);
  memset (FileOpt.device, 0, strlen (s) + 1);
  memcpy (FileOpt.device, s, strlen (s));
}

void set_X_opt (char *s)
{
  s = getArg (s);
  if (evaluateBoolArg (s))
    FileOpt.flags |= OPT_SPREADSCAN;
}


void set_l_opt (char *s)
{
  s = getArg (s);
  FileOpt.limit = atoi (s);
}


void set_d_opt (char *s)
{
  s = getArg (s);
  FileOpt.delay = atoi (s);
}


void set_v_opt (char *s)
{
  s = getArg (s);
  if (evaluateBoolArg (s))
    FileOpt.flags |= OPT_VERB;
}

void set_L_opt (char *s)
{
  s = s + strlen ("addModule") + 1;
  while (*s == ' ' || *s == '\t')
    s++;
  loadinit_mod (s);
}

%}
%%

^{VOID_LINE}[\t !-?a-zA-Z0-9]*	fprintf (stderr, "%s\n", yytext);
^{LOCAL_IP}[\t .0-9]*		set_s_opt (yytext);
^{STATIC_MAC}[\t a-zA-Z0-9]*	set_m_opt (yytext);
^{SPOOF_MAC}[\t :a-fA-F0-9]*	set_M_opt (yytext);
^{INTERFACE}[\t a-zA-Z0-9]*	set_i_opt (yytext);
^{SPREADMODE}[\t a-zA-Z0-9]*	set_X_opt (yytext);
^{PACKETS_PS}[\t a-zA-Z0-9]*	set_l_opt (yytext);
^{PATIENCY}[\t a-zA-Z0-9]*	set_d_opt (yytext);
^{VERBOSE}[\t a-zA-Z0-9]*	set_v_opt (yytext);
^{LOAD_MOD}[\t !-?\-_.:,;a-zA-Z0-9]*	set_L_opt (yytext);

[\n\t a-zA-Z0-9]
.

%%

int yywrap () { return (1);}

int
readConfFile (char *s)
{
  if ((yyin = fopen (s, "r")) == NULL)
    return 0;
  yylex ();
  return 1;
}
