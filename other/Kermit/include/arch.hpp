/* 
 * maybe used for porting ...
 * (ignore this file.)
 */
#ifdef __ALWAYS_UNDEFINED
template <class Ad_t, bool BE, unsigned short A>
class Architecture
{
private:
  le_replace (unsigned char *, AddressType);
  be_replace (unsigned char *, AddressType);

public:
  typedef Ad_t	AddressType;	/* type capable for holding a memory address as integer */
  bool BigEndian;		/* true if machine uses big endian */
  unsigned short Align;		/* data alignment - needed? (sanity checks) */

  Architecture ()
  {
    BigEndian = BE;
    Align = A;
  }

  replaceAddress  (unsigned char *, AddressType);
};


Architecture<unsigned int, false, 4>	x86;
// ...

#define x86	this_arch;
#endif
