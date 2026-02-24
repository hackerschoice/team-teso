struct confFileOpt
{
  unsigned short flags;
  unsigned int limit;
  char *device;  
  unsigned long int delay;
  unsigned long srcAddr;
  unsigned short mac[5];
} FileOpt;

int readConfFile (char *);
