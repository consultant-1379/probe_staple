#include <staple/TCPConn.h>

std::ostream& operator<<(std::ostream& o, const TCPConnId& p)
{
   p.Print(o);
   return o;
}
