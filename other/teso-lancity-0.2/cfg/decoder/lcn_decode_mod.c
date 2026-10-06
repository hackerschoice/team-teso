/*

a little hacked version by zap^teso.
changed get_4 to big-endian,
i think get_16, get_32 and get_64 is fixed (not sure)
but it ain't too important anyway

*/

/*
 *
 * LCN
 *
 *	Program to decode ".md5" file which
 *	was previously generated via LCN
 *
 *	Command line:
 *
 *		cat *.md5 | a.out
 *
 *
 *
 *
 *
 *	DATE	W	HO	WHY
 *	09/24/97	eoc	support all TLVs for V3.20
 *
 */
#include        <stdio.h>
/*#include        "lcn.h" */

static char SCCS_ID[] = "\n@(#)lcn_decode.c	1.2 9/24/97  \n";

FILE *ofp;
char *temp_file = "temp";
char c,
   t;
char param_32[32];
char param_16[16];
char param_64[64];

main (in_file_cnt, in_file_nam)

   int in_file_cnt;
   char *in_file_nam[];

{
   printf ("%s\n", SCCS_ID);

   if (!(ofp = fopen (temp_file, "w")))
   {
      printf ("cannot open file %s for output \n", temp_file);
      exit (1);
   }

/*
** The .md5 file is in ascii-hexadecimal.
** convert back to binary.
**
** Write the converted file to temp
**
*/

   printf ("\n Hex dump of *.md5 follows\n\n");

   while ((c = getchar ()) != EOF)
   {
      putchar (c);

      if (c >= '0' && c <= '9')
      {
	 c -= '0';
      }
      else if (c >= 'A' && c <= 'F')
      {
	 c -= ('A' - 10);
      }
      else
      {
	 printf (" \ninput format error.  Hex value %0x\n",c);
      }

      t = getchar ();
      putchar (t);

      if (t >= '0' && t <= '9')
      {
	 t -= '0';
      }
      else if (t >= 'A' && t <= 'F')
      {
	 t -= ('A' - 10);
      }
      else
      {
	 printf (" \ninput format error.  Hex value %0x\n",t);
      }

      putc (c << 4 | t, ofp);


   }
   fclose (ofp);

   printf ("\n\n");

   if (!(ofp = fopen (temp_file, "r")))
   {
      printf ("cannot open file %s for input \n", temp_file);
      exit (1);
   }

/*
**
** Decode Type / Value / Length
** Do very little Error checking
**
*/

   while ((c = getc (ofp)) != EOF)
   {
      switch (c)
      {
      case 0:
	 printf ("Type: %d  (Pad)\n", c);
	 break;

      case 1:
	 printf ("TxFrequency (in Hz)\t", c);
	 checklen (4);
	 printf ("%d\n", get_4() );
	 break;

      case 2:
	 printf ("RxFrequency (in Hz)\t", c);
	 checklen (4);
	 printf ("%d\n", get_4() );
	 break;

      case 3:
	 printf ("HRN\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 4:
	 printf ("MaxLoopDel\t", c);
	 checklen (4);
	 printf ("%d\n", get_4 ());
	 break;

      case 5:
	 printf ("Digest Option\t", c);
	 checklen (16);
	 get_16 ();
	 printf ("%04x%04x%04x%04x\n",
		 param_16[0], param_16[1], param_16[2], param_16[3]);
	 break;

      case 6:
	 printf ("Change Key\t", c);
	 checklen (64);
	 get_64 ();
	 printf ("%s\n", param_64);
	 break;


      case 7:
	 printf ("Key ID\t", c);
	 t = getc (ofp);
	 printf ("LENGTH: %d \n", t);
	 for (; t; t--)
	 {
	    putchar (c);
	    getc (ofp);

	 }
	 break;

      case 8:
	 printf ("ACCESS\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 9:
	 printf ("READONLY\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 10:
      case 11:
	 printf ("RESERVED CODE %d\t", c);
	 t = getc (ofp);
	 printf ("LENGTH: %d \n", t);
	 for (; t; t--)
	 {
	    putchar (c);
	    getc (ofp);

	 }
	 break;

      case 12:
	 printf ("Max Ethernet Nodes\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 13:
      case 14:
	 printf ("RESERVED CODE %d\t", c);
	 t = getc (ofp);
	 printf ("LENGTH: %d \n", t);
	 for (; t; t--)
	 {
	    putchar (c);
	    getc (ofp);

	 }
	 break;

      case 15:
	 printf ("MaxCDMs\t", c);
	 checklen (4);
	 printf ("%d\n", get_4 ());
	 break;

      case 16:
	 printf ("Default Gateway\t", c);
	 checklen (4);
	 get_ip ();
	 printf ("\n");
	 break;

      case 17:
	 printf ("SNMP READ\t", c);
	 checklen (32);
	 get_32 ();
	 printf ("%s\n", param_32);
	 break;

      case 18:
	 printf ("SNMP WRITE\t", c);
	 checklen (32);
	 get_32 ();
	 printf ("%s\n", param_32);
	 break;

      case 19:
	 printf ("SNMP TRAP\t", c);
	 checklen (32);
	 get_32 ();
	 printf ("%s\n", param_32);
	 break;

      case 20:
	 printf ("Max Concatenation\t", c);
	 checklen (1);
	 t = getc (ofp);
	 switch (t)
	 {
	 case 0:
	    printf ("1518/1\n");
	    break;
	 case 1:
	    printf ("1518/21\n");
	    break;
	 case 2:
	    printf ("3036/43\n");
	    break;
	 case 3:
	    printf ("4554/65\n");
	    break;
	 case 4:
	    printf ("6112/87\n");
	    break;
	 default:
	    printf ("ERROR\n");
	 }
	 break;

      case 21:
	 printf ("Access Priority\t", c);
	 checklen (1);
	 t = getc (ofp);
	 switch (t)
	 {
	 case 1:
	    printf ("High\n");
	    break;
	 case 2:
	    printf ("Normal\n");
	    break;
	 case 3:
	    printf ("Lown");
	    break;
	 default:
	    printf ("ERROR\n");
	 }
	 break;

      case 22:
	 printf ("Max Forward Rate\t", c);
	 checklen (4);
	 printf ("%d\n", get_4 ()/1000);
	 break;

      case 23:
	 printf ("Max Return Rate\t", c);
	 checklen (4);
	 printf ("%d\n", get_4 ()/1000);
	 break;

      case 24:
	 printf ("minContention\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 25:
	 printf ("Authorized NM IP\n", c);
	 checklen (20);
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 break;

      case 26:
	 printf ("Authorized NM MAC\n", c);
	 checklen (30);
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 break;


      case 27:
	 printf ("Supported MAC\n", c);
	 checklen (24);
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 break;

      case 28:
	 printf ("Encryption\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 29:
	 printf ("Off Network Gateway\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;

      case 30:
	 printf ("Key Server\t", c);
	 checklen (4);
	 get_ip ();
	 printf ("\n");
	 break;

      case 31:
	 printf ("Encrypted Network\n", c);
	 checklen (40);
	 get_ip ();
	 printf ("\t  subnet mask ");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\t  subnet mask ");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\t  subnet mask ");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\t  subnet mask ");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\t  subnet mask ");
	 get_ip ();
	 printf ("\n");
	 break;


      case 32:
	 printf ("Supported IP\n", c);
	 checklen (16);
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 break;

      case 33:
	 printf ("SW REV ");
	 checklen (4);
	 printf ("%d\n", get_4 ());
	 break;

      case 34:
	 {
	    int i;

	    printf ("SW Upgrade filename ");
	    c = getc (ofp);
	    for (i = 0; i < c; i++)
	       printf ("%c", getc (ofp));
	    printf ("\n");
	 }
	 break;


      case 35:
	 printf ("TFTP Server\t", c);
	 checklen (4);
	 get_ip ();
	 printf ("\n");
	 break;

      case 36:
      case 37:
	 printf ("RESERVED CODE %d\t", c);
	 t = getc (ofp);
	 printf ("LENGTH: %d \n", t);
	 for (; t; t--)
	 {
	    putchar (c);
	    getc (ofp);

	 }
	 break;


      case 38:
	 printf ("FILTER PROVISION %d\t", c);
	 t = getc (ofp);
	 printf ("LENGTH: %d \n", t);
	 for (; t; t--)
	 {
/*	    putchar (c);	*/
	    getc (ofp);		

	 }
	 break;


      case 39:
	 printf ("LCN-LESS\t", c);
	 checklen (1);
	 printf ("%d\n", getc (ofp));
	 break;


      case 40:
	 printf ("Supported MAC-16\n", c);
	 checklen (96);
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 get_mac ();
	 printf ("\n");
	 break;


      case 41:
	 printf ("Supported IP-16\n", c);
	 checklen (64);
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 get_ip ();
	 printf ("\n");
	 break;



      default:
	 printf ("Type: %d UNKNOWN\t", c);
	 t = getc (ofp);
	 printf ("LENGTH: %d \n", t);
	 for (; t; t--)
	    getc (ofp);

	 break;


      }

   }

   fclose (ofp);
}



/*
** Check Length filed for expected
*/

checklen (length)
   int length;

{
   char c;

   c = getc (ofp);
   if (c != length)
   {
      printf ("Length error Actual(d) %d Expected(d) % d\n", c, length);
   }

}


/*
** Return 4 bytes
*/

int
get_4 ()
{
   char c[4];
   int r;

   c[3] = getc (ofp);
   c[2] = getc (ofp);
   c[1] = getc (ofp);
   c[0] = getc (ofp);

   r = *((unsigned int *) c);
   return r;
}


/*
** Return 16 bytes
*/

int
get_16 ()

{
   int i;

   for (i = 0; i < 16; i++)
      param_16[15-i] = getc (ofp);
}


/*
** Return 32 bytes
*/

int
get_32 ()

{
   int i;

   for (i = 0; i < 32; i++)
      param_32[31-i] = getc (ofp);
}



/*
** Return 64 bytes
*/

int
get_64 ()

{
   int i;

   for (i = 0; i < 64; i++)
      param_64[63-i] = getc (ofp);
}



/*
** Reuturn IP address
*/

get_ip ()
{

   printf ("\t%d", getc (ofp));
   printf (".");
   printf ("%d", getc (ofp));
   printf (".");
   printf ("%d", getc (ofp));
   printf (".");
   printf ("%d", getc (ofp));
}

/*
** Return MAC address
*/


get_mac ()
{

   printf ("\t%d", getc (ofp));
   printf (":");
   printf ("%d", getc (ofp));
   printf (":");
   printf ("%d", getc (ofp));
   printf (":");
   printf ("%d", getc (ofp));
   printf (":");
   printf ("%d", getc (ofp));
   printf (":");
   printf ("%d", getc (ofp));
}
