#ifndef CIRCULARBUFFER_H
#define CIRCULARBUFFER_H

// Fixed-size circular buffer (bytes have a sequence number)
class CircularBuffer {
public:
   unsigned char* pBuffer;             // Pointer to the start of the physical buffer in the memory
   unsigned long  size;                // Size of the physical buffer
   unsigned long  firstSeq;            // The sequence number of the first byte that the circular buffer holds
   unsigned long  firstSeqPos;         // Position of the first seq byte in the physical buffer (relative to pBuffer start)

   CircularBuffer()
   {
      pBuffer = NULL;
      size = 0;
      firstSeq = 0;
      firstSeqPos = 0;
   }

   ~CircularBuffer()
   {
      if (pBuffer!=NULL) delete [] pBuffer;
   }

   void Allocate(unsigned long p_size, unsigned long p_firstSeq = 0)
   {
      pBuffer = new unsigned char[p_size];
      size = p_size;
      firstSeq = p_firstSeq;
      firstSeqPos = 0;
   }

   void Free()
   {
      if (pBuffer!=NULL) delete [] pBuffer;
      pBuffer = NULL;
      size = 0;
      firstSeq = 0;
      firstSeqPos = 0;
   }

   unsigned char operator[](unsigned long p_seq)
   {
      return pBuffer[(firstSeqPos + (p_seq-firstSeq)) % size];
   }

   bool Extend(unsigned long);
   void SetFirstSeq(unsigned long);
   bool CopyTo(unsigned long, unsigned long, unsigned char*);
};

#endif
