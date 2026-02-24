#include <libnet.h>

struct _libnet
{
    int packet_size;
    u_char *packet;
    char err_buf[LIBNET_ERRBUF_SIZE];
    u_char *device;
    struct libnet_link_int *network;
};

void prepare_libnet (struct _libnet *lnet);
int play_arpg (struct _libnet *, u_char *, u_char *, u_char *, u_char *);
