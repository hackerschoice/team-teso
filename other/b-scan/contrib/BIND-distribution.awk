#!/usr/bin/env awk
#
# cat outlog | grep "VERSION.BIND" | awk -f BIND-distribution.awk
#

BEGIN {
	FS = "\""
	hostcount = 0
}

/^[0-9\.]+ VERSION\.BIND\. \"[^\"]+\"$/ {
	# count one to the overall distribution countage
	distribution[$2] += 1

	# count the overall distributions
	hostcount += 1
}

END {
	for (distrib in distribution) {
		printf ("/%s//%d/%.2f/\n", distrib, \
			distribution[distrib], \
			(distribution[distrib] * 100) / hostcount)
	}
}

