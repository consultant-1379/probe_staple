#ifndef RANGELIST_H
#define RANGELIST_H

#include <list>
#include <staple/Type.h>

// Range
// -----
// Contains information on a contiguous range
class Range {                                   // [start,end)
public:
   unsigned long     start;                     // Start position of the range
   unsigned long     end;                       // End position of the range 

   Range(unsigned long p_start=0, unsigned long p_end=0)
   {
      start = p_start;
      end = p_end;
   }
};

// Range list
// ----------
// Contains a list of contiguous ranges
class RangeList {                               // [start,end)
public:
   unsigned long           start;
   unsigned long           end;
   std::list<Range>        rangeList;           // Ordered list of ranges

   RangeList()
   {
      start = 0;
      end = 0;
      rangeList.clear();
   }
   bool InsertRange (unsigned long, unsigned long);
   void Print(std::ostream&);
};

#endif
