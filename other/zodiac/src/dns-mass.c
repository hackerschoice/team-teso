/* zodiac - advanced dns spoofer
 *
 * by team teso
 *
 * mass routines (mass resolving, mass versioning, etc...)
 */


/* dm_resolve
 *
 * dns mass resolve function. resolves at a fixed rate `rate' per second
 * names from file `hostfile', one per line. outputs to `ipfile'.
 * to do this it spawns two threads, one collecting and one packet-firing
 * thread. timeout `timeout' is used per lookup.
 * beware, it might eat system resources :)
 *
 * return in any case
 */

void
dm_resolve (
