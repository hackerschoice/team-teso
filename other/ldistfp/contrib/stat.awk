#!/usr/bin/env awk
#
# stat.awk - part of the ldistfp distribution,
# by scut <scut@bsd.at>
#
# little statistic script to determine linux distribution usage using
# ldistfp machine output logs:
#
# rm -f outlog
# for host in `cat ip-in`; do
#	ldistfp -s -m $host 2>/dev/null >>outlog
# done
# cat outlog | awk -f stat.awk
#

BEGIN {
	FS = "/"
	hostcount = 0
}


{
	# count one to the overall distribution countage
	distribution[$3] += 1

	# count the individual distribution versions
	diststring = $3 " " $4
	distribution_ver[diststring] += 1

	# count identd usage
	identd_version[$5] += 1

	# count the overall distributions
	hostcount += 1
}

END {
	for (distrib in distribution) {
		printf ("/%s//%d/%.2f/\n", distrib, \
			distribution[distrib], \
			(distribution[distrib] * 100) / hostcount)
		for (subdist in distribution_ver) {
			if (subdist ~ distrib)
				printf ("/%s/%s/%d/%.2f/\n", \
					distrib, subdist, \
					distribution_ver[subdist], \
					(distribution_ver[subdist] * 100) \
					/ hostcount)
		}
	}
}

