#include <staple/PacketTrainList.h>
#include <list>

#include <staple/Type.h>
#include <staple/Packet.h>

/*
** -----------------------------------------------------------------------------------------
** Class PacketTrain
** -----------------------------------------------------------------------------------------
*/

// Returns true if the input data range at least PARTIALLY OVERLAPS with the packet train
bool PacketTrain::TestPartialOverlap (unsigned long p_firstSeq, unsigned long p_lastSeq)
{
   if (((p_firstSeq < firstSeq) && (p_lastSeq <= firstSeq)) || ((p_firstSeq >= lastSeq) && (p_lastSeq > lastSeq)))
   {
      return false;
   }
   else
   {
      return true;
   }
}

// Finds a packet based on its starting and ending SEQ
// Returns an iterator pointing to the packet (returns end() if no matching packet found)
// firstSeq = the sequence number of the first byte in the packet
// lastSeq = the sequence number of the first byte beyond the packet
std::list<PacketTrainTCPPacket>::iterator PacketTrain::TestPacket (unsigned long p_firstSeq, unsigned long p_lastSeq)
{
   if (TestPartialOverlap(p_firstSeq, p_lastSeq) == true)
   {
      std::list<PacketTrainTCPPacket>::iterator index = packetList.begin();
      while (index != packetList.end())
      {
         if ((p_firstSeq == (*index).seq) && (p_lastSeq == (*index).seq+(*index).len))
         {
            break;
         }
         index++;
      }
      return index;
   }
   else
   {
      return packetList.end();
   }
}

// Finds a packet based on its starting SEQ (length does not matter)
// Returns an iterator pointing to the packet (returns end() if no matching packet found)
// seq = the sequence number of the first byte in the packet
std::list<PacketTrainTCPPacket>::iterator PacketTrain::TestPacketSeq (unsigned long p_seq)
{
   if (TestPartialOverlap(p_seq, p_seq) == true)
   {
      std::list<PacketTrainTCPPacket>::iterator index = packetList.begin();
      while (index != packetList.end())
      {
         if (p_seq == (*index).seq)
         {
            break;
         }
         index++;
      }
      return index;
   }
   else
   {
      return packetList.end();
   }
}

// Appends a CONSECUTIVE packet at the END of the packet train
// Returns true on success
bool PacketTrain::InsertPacketToBack (PacketTrainTCPPacket& p_packet)
{
   // Empty packet -> error
   if (p_packet.len == 0) return false;

   // Is it the first packet?
   if (packetList.empty()==true)
   {
      packetList.push_back(p_packet);
      firstSeq = p_packet.seq;
      lastSeq = p_packet.seq + p_packet.len;
      return true;      
   }

   // Or is it a consecutive packet?
   if (p_packet.seq == lastSeq)
   {
      packetList.push_back(p_packet);
      lastSeq += p_packet.len;
      return true;
   }

   return false;
}

// Appends a CONSECUTIVE packet at the START of the packet train
// Returns true on success
bool PacketTrain::InsertPacketToFront (PacketTrainTCPPacket& p_packet)
{
   // Empty packet -> error
   if (p_packet.len == 0) return false;

   // Is it the first packet?
   if (packetList.empty()==true)
   {
      packetList.push_front(p_packet);
      firstSeq = p_packet.seq;
      lastSeq = p_packet.seq + p_packet.len;
      return true;      
   }

   // Or is it a consecutive packet?
   if ((p_packet.seq + p_packet.len) == firstSeq)
   {
      packetList.push_front(p_packet);
      firstSeq -= p_packet.len;
      return true;
   }

   return false;
}

// Removes the first packet from the packet train
// Returns true if successful
bool PacketTrain::RemoveFirstPacket()
{
   if (packetList.empty()==true)
   {
      return false;
   }
   else
   {
      firstSeq += packetList.front().len;
      packetList.pop_front();
      return true;
   }
}

void PacketTrain::Print(std::ostream& outStream) const
{
   outStream << "firstSeq " << firstSeq << " lastSeq " << lastSeq << " number of packets " << packetList.size() << "\n";
}

/*
** -----------------------------------------------------------------------------------------
** Class PacketTrainList
** -----------------------------------------------------------------------------------------
*/

// Returns an iterator to the packet train whose data range at least PARTIALLY OVERLAPS with
// the input data range (end() if no overlap)
std::list<PacketTrain>::iterator PacketTrainList::TestPartialOverlap (unsigned long p_firstSeq, unsigned long p_lastSeq)
{
   std::list<PacketTrain>::iterator index = packetTrainList.begin();
   while (index != packetTrainList.end())
   {
      if ((*index).TestPartialOverlap(p_firstSeq, p_lastSeq) == true)
      {
         break;
      }
      index++;
   }
   return index;
}

// Inserts a non-overlapping packet into the packet train list
// Returns true on success
bool PacketTrainList::InsertPacket (PacketTrainTCPPacket& p_packet)
{
   // Empty packet
   if (p_packet.len == 0) return false;

   // First packet in the list?
   if (packetTrainList.empty() == true)
   {
      // Create first packet train
      PacketTrain packetTrain;
      packetTrain.Init();
      packetTrain.InsertPacketToFront(p_packet);

      packetTrainList.push_back(packetTrain);
      firstSeq = p_packet.seq;
      lastSeq = p_packet.seq + p_packet.len;
      return true;
   }

   // CONSECUTIVE packet at the END?
   if (p_packet.seq == lastSeq)
   {
      packetTrainList.back().InsertPacketToBack(p_packet);
      lastSeq = p_packet.seq + p_packet.len;
      return true;      
   }

   // NON-CONSECUTIVE packet past the END?
   if (p_packet.seq > lastSeq)
   {
      // Create new packet train
      PacketTrain packetTrain;
      packetTrain.Init();
      packetTrain.InsertPacketToFront(p_packet);

      packetTrainList.push_back(packetTrain);
      lastSeq = p_packet.seq + p_packet.len;
      return true;
   }

   // NON-OVERLAPPING packet somewhere else?
   std::list<PacketTrain>::iterator trainIndex;
   trainIndex = TestPartialOverlap(p_packet.seq,p_packet.seq+p_packet.len);
   if (trainIndex == packetTrainList.end())
   {
      // Find the train that is proceding the packet
      trainIndex = packetTrainList.begin();
      while (trainIndex != packetTrainList.end())
      {
         if ((p_packet.seq+p_packet.len) <= (*trainIndex).firstSeq)
         {
            std::list<PacketTrain>::iterator nextTrain = trainIndex;

            // Is it the first train?
            if (nextTrain == packetTrainList.begin())
            {
               // Does the packet fit to the first train?
               if ((p_packet.seq+p_packet.len) == (*nextTrain).firstSeq)
               {
                  // Append packet
                  (*nextTrain).InsertPacketToFront(p_packet);
               }
               else
               {
                  // Create new first packet train
                  PacketTrain packetTrain;
                  packetTrain.Init();
                  packetTrain.InsertPacketToFront(p_packet);
                  packetTrainList.push_front(packetTrain);
               }
               firstSeq = p_packet.seq;
            }
            else
            {
               std::list<PacketTrain>::iterator lastTrain = --trainIndex;
               // No connection to packet trains
               if ((p_packet.seq!=(*lastTrain).lastSeq) && ((p_packet.seq+p_packet.len)!=(*nextTrain).firstSeq))
               {
                  // Create new packet train
                  PacketTrain packetTrain;
                  packetTrain.Init();
                  packetTrain.InsertPacketToFront(p_packet);
                  // Insert it before the next train
                  packetTrainList.insert(nextTrain,packetTrain);
               }
               // Connection to the last packet train
               if ((p_packet.seq==(*lastTrain).lastSeq) && ((p_packet.seq+p_packet.len)!=(*nextTrain).firstSeq))
               {
                  // Append packet
                  (*lastTrain).InsertPacketToBack(p_packet);
               }
               // Connection to the next packet train
               if ((p_packet.seq!=(*lastTrain).lastSeq) && ((p_packet.seq+p_packet.len)==(*nextTrain).firstSeq))
               {
                  // Append packet to the next train
                  (*nextTrain).InsertPacketToFront(p_packet);
               }
               // Connection to both packet trains
               if ((p_packet.seq==(*lastTrain).lastSeq) && ((p_packet.seq+p_packet.len)==(*nextTrain).firstSeq))
               {
                  // Merge last and next train by the new packet
                  if ((*lastTrain).packetList.size() > (*nextTrain).packetList.size())
                  {
                     // Append new packet to the last train
                     (*lastTrain).InsertPacketToBack(p_packet);
                     // Copy packets from nextTrain to lastTrain
                     while ((*nextTrain).packetList.empty() != true)
                     {
                        (*lastTrain).packetList.push_back((*nextTrain).packetList.front());
                        (*nextTrain).packetList.pop_front();
                     }
                     // Inflate lastTrain's data range
                     (*lastTrain).lastSeq = (*nextTrain).lastSeq;
                     // Erase nextTrain
                     packetTrainList.erase(nextTrain);
                  }
                  else
                  {
                     // Append new packet to the next train
                     (*nextTrain).InsertPacketToFront(p_packet);
                     // Copy packets from lastTrain to nextTrain
                     while ((*lastTrain).packetList.empty() != true)
                     {
                        (*nextTrain).packetList.push_front((*lastTrain).packetList.back());
                        (*lastTrain).packetList.pop_back();
                     }
                     // Inflate nextTrain's data range
                     (*nextTrain).firstSeq = (*lastTrain).firstSeq;
                     // Erase lastTrain
                     packetTrainList.erase(lastTrain);
                  }
               }
            }
            return true;
         }
         trainIndex++;
      }
   }

   return false;
}

// Removes the first packet from the packet train list
// Returns true if successful
bool PacketTrainList::RemoveFirstPacket()
{
   bool success = false;

   std::list<PacketTrain>::iterator index = packetTrainList.begin();

   while (index != packetTrainList.end())
   {
      // Try to remove the first packet from the first train
      if ((*index).RemoveFirstPacket() == true)
      {
         // Packet removed
         success = true;

         // If the train became empty -> erase it
         if ((*index).firstSeq == (*index).lastSeq)
         {
            packetTrainList.pop_front();
         }

         // Stop
         break;
      }
      // Packet removal was not successful (first train was empty)
      else
      {
         // Erase it
         packetTrainList.pop_front();
         // Continue with the NEW first train
         index = packetTrainList.begin();
      }
   }

   // Update firstSeq
   if (packetTrainList.empty() == true)
   {
      firstSeq = lastSeq = 0;
   }
   else
   {
      firstSeq = packetTrainList.front().firstSeq;
   }

   return success;
}

void PacketTrainList::Print(std::ostream& outStream) const
{
   outStream << "firstSeq " << firstSeq << " lastSeq " << lastSeq << " number of packet trains " << packetTrainList.size() << "\n";
}
