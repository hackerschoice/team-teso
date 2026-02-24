/*
 * DevMemPatt.cpp:
 * written by palmers / teso
 */
#include <DevMemPatt.hpp>


  DevMemPatt::DevMemPatt ()
  {
    rw = new rwKernel ();
  }


  DevMemPatt::DevMemPatt (rwKernel *a)
  {
    rw = a;
  }


  DevMemPatt::~DevMemPatt ()
  {
  }


  int DevMemPatt::compare_data_snippet (unsigned char *x, struct sfp *y)
  {
    bool		i = false;
    int			ret = -1;
    short		a = 0,
			b = 0;

  while ((b < y->length) && (a < READ_BUFF_SIZE))
    {
      if ((x[a] == y->fp[b].val) || (y->fp[b].type == WWCARD))
        {
          if (i == false)
            {
              i = true;
              ret = a;
            }
          b++;
        }
      else if (i == true)
        {
          i = false;
          ret = -1;
          b = 0;
        }
      a++;
    }
  return ret;
  }


  unsigned int DevMemPatt::find_patt (unsigned int s, \
		unsigned int e, unsigned short l, unsigned char *snipp)
  {
    bool		i = false;
    int			ret = -1;
    unsigned short	a = 0,
			b = 0;
    unsigned char	*readBuff = NULL;

    readBuff = new unsigned char[READ_BUFF_SIZE];

    while (s < e)
      {
        rw->read (readBuff, READ_BUFF_SIZE, s);
        while ((b < l) && (a < READ_BUFF_SIZE))
          {
            if (readBuff[a] == snipp[b])
              {
                if (i == false)
                  {
                    i = true;
                    ret = a;
                  }
                b++;
              }
            else if (i == true)
              {
                i = false;
                ret = -1;
                b = 0;
              }
            a++;
          }
        if (ret != -1)
	  {
	    if (ret == 0)
	      return s;
	    s = s + ret - READ_BUFF_SIZE;
	  }
        s += READ_BUFF_SIZE;
      }
    return 0;
  }


  unsigned int DevMemPatt::find_patt (struct sfp *a)
  {
    int			x = -1;
    unsigned int	s = a->start_addr,
			e = a->stop_addr;
    unsigned char	*readBuff = NULL;

    readBuff = new unsigned char[READ_BUFF_SIZE];

    while (s < e)
      {
        rw->read (readBuff, READ_BUFF_SIZE, s);
        if ((x = compare_data_snippet (readBuff, a)) != -1)
	  {
	    if (x == 0)
	      return s;
	    s = s + x - READ_BUFF_SIZE;
	  }
        s += READ_BUFF_SIZE;
      }
    return 0;
  }

