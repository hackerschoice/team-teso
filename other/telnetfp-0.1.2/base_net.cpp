class tcp_socket
{
  private:
  int sock;

  public:

  int sopen (char *host, int port)
  {
    int x = -1;
    struct hostent *foo = NULL;
    struct sockaddr_in addr;

    memset ((struct sockaddr_in *) &addr, 0, sizeof (struct sockaddr_in));

    if ((addr.sin_addr.s_addr = inet_addr (host)) == -1)
      {
	if ((foo = gethostbyname (host)) == NULL)
	  return -2;
	addr.sin_addr.s_addr = *(unsigned long *) (foo->h_addr_list[0]);
      }
    addr.sin_family = PF_INET;
    addr.sin_port = htons (port);
    sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);

    x = connect (sock, (struct sockaddr *) &addr, sizeof (struct sockaddr_in));
    if (x != 0 || sock < 0)
      return -1;

    return 0;
  }


  char *sread (int x)
  {
    char *y = NULL;
    y = (char *) malloc (x + 1);
    memset (y, 0x00, x + 1);
    if (read (sock, y, x) < 1)
      {
	free (y);
	return NULL;
      } 
    return y;
  }


  int swrite (char *x)
  {
    return write (sock, x, strlen (x));
  }


  void sclose ()
  {
    close (sock);
  }


  void
  init ()
  {
    sock = 0;
  }
};
