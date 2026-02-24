
/* ripped from:
 *   kim holviala (kimmy/pulp)
 *   sed
 *
 * i'm sorry for ripping this, but as i just cut code from it, it does not
 * matter that much gpl-wise. uhhohh.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define byte unsigned char
#define word unsigned short
#define dword unsigned long

#define OK 0
#define ERROR 1

#define MAXSIZE 20000

#define TRUE 1
#define FALSE 0


byte _buffer[MAXSIZE], lzbuffer[MAXSIZE];
byte * buffer=0;
word lenght=0, lzlenght=0, hufflimit1=0, hufflimit2=0, lenlimit=0, decodelenght=0;
int maxhuffman=0, dummy=0;
int bitpos=0;

char *rotorchar = "-/|\\";

char *info = "Six-2-Four v1.0 - Exepacker for 4Kb-intros.\n"
	     "Copyright (c) Kim Holviala a.k.a Kimmy/PULP Productions 1997.\n"
	     "Linux version - Sed (sed@free.fr) october 1999\n"
	     "                Licenced under the terms of the GNU General Public Licence.\n";

char *help = "    Usage: 624 [-s] infile [outfile]\n\n"
             "    Where: -s      - use super duper compression\n"
             "           infile  - tinlinked file shorter than 20000 bytes\n"
             "This program is EMAILWARE. You're free to use this even with commercial\n"
             "programs, AFTER you email me to <kimmy@iki.fi> and tell me the name of\n"
             "your favorite dark beer!\n"
	     "The Linux version you are running in licenced under the terms\nof the GNU General Public Licence.\n"
	     "It requires nasm (available at http://www.web-sites.co.uk/nasm/index.html)\n"
	     "and tinlink 1.0 (available at http://sed.free.fr/tinlink/index.html)\n";



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Write one bit to the lzbuffer
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

void writebit(word bit) {
    byte mask = 1;

    mask <<= bitpos;

    if (bit == 0) lzbuffer[lzlenght] &= 255-mask;
    else lzbuffer[lzlenght] |= mask;

    if (++bitpos > 7) {

        bitpos = 0;
        lzlenght++;

	/* it's possible to have a bigger file than the original, in that case,
	 * we must stop
	 */
	if (lzlenght >= MAXSIZE) {
	    fprintf(stderr, "\nSorry, but the compressed file would be too big.\n");
	    exit(1);
	}
    }
}



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Write n bits to the lzbuffer
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

void writedata(word b, word mask) {

    do {
        writebit(b & mask);
        mask >>= 1;

    } while (mask > 0);
}



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Write one "huffman"-coded number to the lzbuffer
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

void writehuffman(word number) {

    word mask;


    number--;

    if (number < (hufflimit1 * 2)) {

        writebit(0);
        mask = hufflimit1;
    }
    else {
        number -= (hufflimit1 * 2);

        writebit(1);
        mask = hufflimit2;
    }


    do {
        writebit(number & mask);
        mask >>= 1;

    } while (mask > 0);
}



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Return log2 (if that's what it is?)
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

word log2(word l) {

    switch (l) {
        case 1: return 0;
        case 2: return 1;
        case 4: return 2;
        case 8: return 3;
        case 16: return 4;
        case 32: return 5;
        case 64: return 6;
        case 128: return 7;
        case 256: return 8;
        case 512: return 9;
        case 1024: return 10;
        case 2048: return 11;
        case 4096: return 12;
    }

    return 0;
}



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Compress the file
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

void squeeze(void) {

    int count1=0, count2=0;
    word bestlen=0, bestpos=0, len=0;
    byte b=0;


    lzlenght = 0;
    bitpos=0;

    for (count1 = 0; count1 < lenght; count1++) {

        bestlen = 0;
        b = buffer[count1];

        for (count2 = (count1 - 1); count2 > (count1 - maxhuffman); count2--) {

            if (count2 < 0) break;

            if (buffer[count2] == b) {

                for (len = 1; len < maxhuffman; len ++) {

                    if ((count1 + len) > lenght) break;
                    if (buffer[count1 + len] != buffer[count2 + len]) break;
                }

                if (len > bestlen) {

                    bestlen = len;
                    bestpos = count1 - count2;
                }
            }

        }

        if (bestlen == 1 && bestpos < 17) {

            writebit(1);
            writebit(0);
            writedata(bestpos - 1, 8);

            continue;
        }

        if (bestlen > 1) {

            if (bestlen < lenlimit) {

                for (count2 = 0; count2 < bestlen; count2++) writebit(1);
                writebit(0);
            }
            else {
                for (count2 = 0; count2 < lenlimit; count2++) writebit(1);
                writehuffman(bestlen - 1);
            }

            count1 += bestlen - 1;
            writehuffman(bestpos);

            continue;
        }

        writebit(0);
        writedata(b, 128);
    }

    lzlenght++;
}



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Find the best compression values
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

void compress(void) {

    word besthl1=0, besthl2=0, bestll=0, bestlzlen;
    byte rotor = 0;


    lenlimit = 9;
    bestlzlen = 60000;

    for (hufflimit1 = 4; hufflimit1 <= 64; hufflimit1 *= 2)
    for (hufflimit2 = hufflimit1 * 4; hufflimit2 <= 2048; hufflimit2 *= 2) {

	fflush(stdout);
	rotor++;
	rotor&=3;

        maxhuffman = (hufflimit2 + hufflimit1) * 2;

        squeeze();

        if (lzlenght < bestlzlen) {

            besthl1 = hufflimit1;
            besthl2 = hufflimit2;
            bestlzlen = lzlenght;
        }
    }

    hufflimit1 = besthl1;
    hufflimit2 = besthl2;
    maxhuffman = (hufflimit2 + hufflimit1) * 2;
    bestlzlen = 60000;

    for (lenlimit = 5; lenlimit <= 15; lenlimit++) {

	fflush(stdout);
	rotor++;
	rotor&=3;

        squeeze();

        if (lzlenght < bestlzlen) {

            bestll = lenlimit;
            bestlzlen = lzlenght;
        }
    }

    lenlimit = bestll;

    squeeze();
}



/*北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
 *
 *  Main
 *
 *北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北*/

int
main (int argc, char *argv[])
{
    FILE *out;
    FILE *fp;
    char *destfile="un624.linux.compressed.bin.712SAk", *srcfile, slow;
    char *aoutfile="a.out";
    long ratio;
    unsigned long starting_offset, new_offset, memory;
    char tin[1024];

    buffer=_buffer;


    if (argc<2) {
	puts(help);
	fprintf(stderr, "Bad number of arguments.\n");
	return ERROR;
    }

    if (argv[1][0] == '-') {
	if (argv[1][1] != 's' || argv[1][2]) {
	    puts(help);
	    fprintf(stderr, "Unkown option '%s'\n", argv[1]);
	    return ERROR;
	}
	if (argc < 3 || argc > 4) {
	    puts(help);
	    fprintf(stderr, "Bad number of arguments.\n");
	    return ERROR;
	}
        slow = TRUE;
        srcfile = argv[2];
	if (argc==4)
	    aoutfile=argv[3];
    }
    else {
	if (argc < 2 || argc > 3) {
	    puts(help);
	    fprintf(stderr, "Bad number of arguments.\n");
	    return ERROR;
	}
        slow = FALSE;
        srcfile = argv[1];
	if (argc==3)
	    aoutfile=argv[2];
    }


    if ((fp = fopen(srcfile, "rb")) == NULL) {

        printf("File not found!\n");
        return ERROR;
    }

    lenght = (word) fread(buffer, 1, MAXSIZE, fp);
    if (lenght == 0) {

        printf("Error reading from file!\n");
        fclose(fp);

        return ERROR;
    }

#if 0
    lenght-=74;
    buffer+=74;
#endif

#if 0
    if (fread(&dummy, 1, 1, fp) != 0) {
        printf("File too big (must be < 20000 bytes)!\n");
        fclose(fp);
        return ERROR;
    }
#endif

    fclose(fp);


    if (slow == TRUE) compress();
    else {
        hufflimit1 = 16;
        hufflimit2 = 128;
        lenlimit = 9;
        maxhuffman = (hufflimit2 + hufflimit1) * 2;
        squeeze();
    }


    if ((fp = fopen(aoutfile, "wb")) == NULL) {
        printf("Cannot create file '%s'\n", aoutfile);
        return ERROR;
    }
    fwrite(lzbuffer, 1, lzlenght, fp);
    fclose(fp);

    printf ("%d:%d:%d:%d:%d\n",
	    lzlenght, lenlimit-1, log2(hufflimit1)+1, log2(hufflimit2)+1, (hufflimit1 * 2)+1);
#if 0
    fprintf (stderr, "%%define data_length %d\n"
	    "%%define llstuff %d\n"
	    "%%define hl1stuff %d\n"
	    "%%define hl2stuff %d\n"
	    "%%define hf2stuff %d\n",
	    lzlenght, lenlimit-1, log2(hufflimit1)+1, log2(hufflimit2)+1, (hufflimit1 * 2)+1);
#endif

#if 0
    ratio = ((long) lenght - (long) lzlenght) * 100 / ((long) lenght);
    printf("Done!\n\nInput/Output ratio: %i/%i bytes (saved %ld%%)\n",
           lenght, lzlenght, ratio);

    /* Ok, let's now create the asm file */
    /* the unpack routine is placed before the place where the unpacked code is said to be,
     * according to the elf header (is it clean ? mmm, I guess not...).
     */
    buffer-=74;
    starting_offset=*(unsigned long *)((char *)buffer+24);
    memory=*(unsigned long *)((char *)buffer+64);
    new_offset=starting_offset-lzlenght-74;
    new_offset&=~4095;
    new_offset+=74;
    memory+=starting_offset - new_offset+4095;
    memory&=~4095;

    if (!(out=fopen("624.a.out.asm.816HDq", "wb"))) {
      perror("624.a.out.asm.816HDq");
      return ERROR;
    }
    fprintf(out, "BITS 32\n"
	    "org 0x%lx\n"
	    "%%define decompress_to 0x%lx\n"
	    "%%define data_length %d\n"
	    "%%define llstuff %d\n"
	    "%%define hl1stuff %d\n"
	    "%%define hl2stuff %d\n"
	    "%%define hf2stuff %d\n",
	    new_offset, starting_offset, lzlenght, lenlimit-1, log2(hufflimit1)+1, log2(hufflimit2)+1, (hufflimit1 * 2)+1);
    fprintf(out, "%s", unpacker);
    fprintf(out, "incbin \"%s\";\n", destfile);
    fclose(out);

    /* ok, let's nasm it and tinlink it */
    /* don't worry about all those sprintf in a fixed size buffer, overflow is not possible */
    sprintf(tin, "nasm -f bin -o 624.a.out.compressed.0012Aq 624.a.out.asm.816HDq");
    fprintf(stderr, "%s\n", tin);
    system(tin);
    sprintf(tin, "tinlink -o %s -c 624.a.out.compressed.0012Aq -m %ld -s %p", aoutfile, memory, (unsigned char *)new_offset);
    fprintf(stderr, "%s\n", tin);
    system(tin);
    sprintf(tin, "rm 624.a.out.compressed.0012Aq 624.a.out.asm.816HDq %s", destfile);
    fprintf(stderr, "%s\n", tin);
    system(tin);
    return OK;
#endif
}
