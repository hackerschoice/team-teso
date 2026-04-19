/* Due to new proc hiding technique, from a hidden shell
 * there cant be any processes started which are visible
 * since the parent (shell) is invisible. So we have to 
 * make init the parent and then start the process. Then
 * it is visible
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


int main(int argc, char **argv, char **env)
{
	if (fork()) {
		exit(0);
	}
	if (argc > 1)
	        execve(argv[1],argv+1, env);
	return -1;
}


