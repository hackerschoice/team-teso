#!/usr/bin/perl

# This script belongs to the EoE hostbased IDS which is
# (C) 1999 by S. Krahmer.
# Please look at LICENSE.


# add your programs that you wish to monitor here
# there are 3 things here you can specify:
#
#	WARN   will mail you a warning
#	NOTICE will just print out a message
#	KILL   will mail you a warning and kill the specific process
#	       that caused the warning
%bad_progz = (

    # warn on a rootshell
	WARN => ["[0-9]+:0:[0-9]+:.+:.+sh"],

    # kill rootshells executed by inetd directly,
    # this is rather an overflow
	KILL => ["[0-9]+:0:[0-9]+:inetd:.+sh"]
);

# notice the admin when something strange happens
sub handle_request {
	my ($what, $prog) = @_;
	
	# first give errie to stdout
	printf("%s: %s\n", $what, $prog);
	
	
	# in case we should kill the process
	if ($what eq "KILL") {
		
		# just to rip out the PID of the string, sure
		# it matchs :-)
		if ($prog =~ /[0-9]+:[0-9]+:([0-9]+):.+/) {
			kill 9, $1;
		}

		# ! change this to your beepers adress !		
		open MAIL, "|/bin/mail root" or die("Can't  open mailpipe");
		print MAIL `date`;
		printf MAIL "\nKILLED: %s\n\n", $prog;
		printf MAIL `netstat --inet`."\n".`w`;
		close MAIL;
	}
		
	# or simply warn?
	if ($what eq "WARN") {
	
		# ! and this too !
		open MAIL, "|/bin/mail root"  or die("Can't open mailpipe");
	
		print MAIL `date`;
		printf MAIL "\nWARNING: %s\n\n", $prog;
		print MAIL `netstat --inet`."\n".`w`;
		close MAIL;
	}
	
}

# open the EoE device
open EOE, "/dev/exec" or die("Can't open /dev/exec");

# Place your ioctl() here, but you maybe wish to monitor euid 0,
# which is default.

# read forever, looking whether some1 executes
# programs that he shouldn't
while ((read EOE, $s, 1000) > 0) {
	foreach $stage (keys %bad_progz) {
		foreach $l (0 .. $#{$bad_progz{$stage}}) {
			my $expression = $bad_progz{$stage}[$l];
			if ($s =~ m/$expression/) {
				handle_request($stage, $s);
			}
		}
	}
}
close EOE;
printf("Huh? Something went wrong. EoE logger terminated.\n");
