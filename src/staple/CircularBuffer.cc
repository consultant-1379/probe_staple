#include <string.h>

#include <staple/CircularBuffer.h>
#include <staple/Type.h>

bool CircularBuffer::Extend(unsigned long p_size)
{
   // Only size increase is allowed
   if (p_size <= size) return false;
   // Allocate new buffer
   unsigned char* pNewBuffer = new unsigned char[p_size];
   // Move old buffer to the new one
   if (pBuffer!=NULL)
   {
      memcpy(pNewBuffer, pBuffer+firstSeqPos, size-firstSeqPos);
      memcpy(pNewBuffer+(size-firstSeqPos), pBuffer, firstSeqPos);
      delete[] pBuffer;
   }
   // Set new buffer descriptors (firstSeq remains intact)
   pBuffer = pNewBuffer;
   size = p_size;
   firstSeqPos = 0;
}

void CircularBuffer::SetFirstSeq(unsigned long p_seq)
{
   // Advance the buffer
   if (size==0)
   {
      // Empty buffer
      firstSeq = p_seq;
      firstSeqPos = 0;
   }
   else
   {
      // Non-empty buffer
      signed long newFirstSeqPos = (firstSeqPos + ((signed long)p_seq-firstSeq)) % size;
      if (newFirstSeqPos < 0) newFirstSeqPos += size;
      firstSeqPos = newFirstSeqPos;
      firstSeq = p_seq;
   }
}

bool CircularBuffer::CopyTo(unsigned long p_firstSeq, unsigned long p_size, unsigned char* p_buffer)
{
   // If there are no overlapping bytes - return
   if ((size==0) || (p_firstSeq >= (firstSeq+size))) return false;
   if ((p_firstSeq+p_size) <= firstSeq) return true;

   // Crop data if needed
   unsigned long cropFirstSeq = p_firstSeq;
   unsigned long cropSize = p_size;
   if (p_firstSeq < firstSeq)
   {
      // Crop the start
      cropFirstSeq = firstSeq;
      cropSize = p_size - (firstSeq-p_firstSeq);
   }
   if ((cropFirstSeq+cropSize) > (firstSeq+size))
   {
      // Crop the end
      cropSize = firstSeq+size-cropFirstSeq;
   }

   // Copy with wrap-around-check
   unsigned long copyFromPos = cropFirstSeq-p_firstSeq;
   unsigned long copyToPos = ((cropFirstSeq-firstSeq) + firstSeqPos) % size;
   if ((copyToPos+cropSize) <= size)
   {
      // No wrap-around
      memcpy(pBuffer+copyToPos, p_buffer+copyFromPos, cropSize);
   }
   else
   {
      // Wrap-around
      memcpy(pBuffer+copyToPos, p_buffer+copyFromPos, size-copyToPos);
      memcpy(pBuffer, p_buffer+copyFromPos+(size-copyToPos), cropSize-(size-copyToPos));
   }

   return true;
}
