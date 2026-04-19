#!/usr/bin/perl

# xterm popup daemon for ssharp (C) 2002 Stealth

my %xterms = ();

for (;;) {
	opendir D, "/tmp" or die "$!";
	my @allfiles = readdir D;
	closedir D;
	@allfiles = grep /ssharp-/, @allfiles;

	foreach (@allfiles) {
		next if defined $xterms{$_};
		$xterms{$_} = 1;
		# TAKE CARE: this is a security vulnerability (locally)
		system("xterm -T $_ -e /usr/local/bin/mss-client /tmp/$_ &");
		sleep(1);
	}
}

		
