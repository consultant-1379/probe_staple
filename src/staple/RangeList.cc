#include <staple/RangeList.h>
// TODOs:
// List is always searched from the start, that is a problem because:
//  - typically we add new data to the end
//  - list never shrinks
//  - during monitoring loss periods (e.g., because of high CPU load) this will generate a positive feedback loop which we can never escape
bool RangeList::InsertRange (unsigned long p_start, unsigned long p_end)
{
   // Sanity check
   if (p_start >= p_end) return false;

   // Update overall range list
   if ((p_start<start) || (rangeList.empty())) start = p_start;
   if ((p_end>end) || (rangeList.empty())) end = p_end;

   // Find the range that overlaps (or directly connects) with this range (go from left to right)
   std::list<Range>::iterator index = rangeList.begin();
   while ((index != rangeList.end()) && (index->start <= p_end))
   {
      // Process only if there is a chance to overlap/connect (speed up the loop)
      if (index->end >= p_start)
      {
         // Extend to right / super-range
         if (p_end > index->end)
         {
            // Extend to right
            index->end = p_end;
            // Also a super-range?
            if (p_start < index->start) index->start = p_start;
            // Right merging may be needed
            std::list<Range>::iterator rightIndex = index;
            rightIndex++;
            while ((rightIndex != rangeList.end()) && (rightIndex->start <= index->end))
            {
               if (rightIndex->end > index->end) index->end = rightIndex->end;
               rangeList.erase(rightIndex);
               rightIndex = index;
               rightIndex++;
            }
            return true;
         }

         // Extend to left only
         if ((p_end <= index->end) && (p_start < index->start))
         {
            index->start = p_start;
            // No merging is necessary (since we go from left to right)
            return true;
         }

         // Sub-range -> nothing to do
         if ((p_start >= index->start) && (p_end <= index->end)) return true;
      }
      index++;
   }
   
   // No overlap -> insert new range (could be merged with the empty case?)
   Range range = Range(p_start,p_end);
   rangeList.insert(index, range);
   return true;
}

void RangeList::Print(std::ostream& outStream)
{
   outStream << "Range " << start << " - " << end << "\n";
   std::list<Range>::iterator index = rangeList.begin();
   while (index != rangeList.end())
   {
      outStream << " - subrange " << index->start << " - " << index->end << "\n";
      index++;
   }
}
