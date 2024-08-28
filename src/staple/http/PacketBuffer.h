#ifndef PACKETBUFFER_H
#define PACKETBUFFER_H

#include <deque>
#include <stdint.h>

#include <staple/Staple.h>
#include <staple/http/globals.h>

class TCPPacket;

/* A PacketBuffer contains a sequence of TCP packets ordered by their
   sequence number.  The packet buffer makes it possible to compensate
   for duplicated, reordered, and retransmitted packets. Packet are
   added with 'add' and removed with 'get'. The buffer will make sure
   that packets returned by 'get' come in the appropriate order (with
   no gaps, missing packets are indicated by a NULL return value from
   'get'). This holds regardless of the order the packets were
   inserted into the buffer with 'add' (modulo the maxSize parameter,
   see constructor below).
*/

class PacketBuffer
{
public:
	/* Create a new PacketBuffer. maxSize is the maximum amount of
	 * payload data that the buffer will store. To be able to deal
	 * with retransmitted packets maxSize must be larger than the
	 * bandwidth-delay product (BDP) of the link. If maxSize is
	 * smaller than the BDP, then retransmitted packet will come
	 * too late and will be treated as capture losses.
	 *
	 * The default is set to 250 kB which is OK for an RTT of
	 * 100ms and a bandwidth of 20 Mbit/s (100 ms * 20 Mbit/s = 2
	 * Mbit = 250 kB).
	 */
	explicit PacketBuffer(Staple& staple, int maxSize = 1024*250);
	~PacketBuffer();

	/* Test if the the sequence of operations
	 * packetBuffer.add(packet); TCPPacket* p = packetBuffer.get()
	 * would result in that 'p' is identical to 'packet'.
	 *
	 * As 'add' copies the packet one can use this method to test
	 * if it is safe to use 'packet' right away, without adding it
	 * to the PacketBuffer and the invoking get() to get the same
	 * packet.
	 *
	 * Returns true if 'p' would be identical to 'packet' and
	 * false otherwise. If true is returned 'packet' can be used
	 * right away and a copy of the packet can be avoided.
	 *
	 * NOTE: This method is not const! The internal state of the
	 * PacketBuffer (in particular the next expected sequence
	 * number) is changed when this method is called and true is
	 * returned. If false is returned no internal state is
	 * changed.
	 */
	bool tryAddGet(const TCPPacket& packet);

	/* Copy the packet and add it to the packet buffer. Return
	 * false if there isn't room for the packet in the buffer and
	 * true otherwise.
	 */
	bool add(const TCPPacket& p);

	/* Extract one packet from the buffer. The caller takes
	   ownership and is responsible for calling delete. Returns
	   NULL if no packet is available. Payload processing should
	   start at offset 'offset'. If packets overlap each other
	   then *offset may become non-zero.
	*/
	TCPPacket* get(/*int offset* */); // offset isn't implemented yet.

	/*
	  Get sequence number of next non-NULL packet returned by
	  get. Note that more packets may need to be added to the
	  buffer before get returns a non-NULL packet.
	*/
	int getNextSeqNo() const { return nextSeqNo_; }

	void finishTCPSession();
	bool hasPackets() const;

	/* Set nextSeqNo_ to sequence number of first packet in
	   buffer. This makes the next 'get' return a non-NULL
	   pointer.

	   Intended usage is to make it possible to deal with capture
	   losses, when some packets are simply lost and we will never
	   see them (no retransmission). E.g., if we are processing
	   the body of a HTTP response it is probably no big deal to
	   skip a packet. We only need to keep track of the number of
	   bytes we have skipped.

	   FIXME: What should be done if we have no packets? assertion
	   failure?
	*/
	// Not yet implemented.
	// void advanceSeqNo();


	// Useful for debugging and logging.
	int numPackets() const { return packets_.size(); }

	/* Update ACK. */
	void updateAck(uint32_t ack);

private:
	DISALLOW_COPY_AND_ASSIGN(PacketBuffer);

	Staple& staple_;
	void checkInvariant();

	static const uint32_t INSANELY_LARGE_SEQ_ACK;
	void updateNextSeqNo(uint32_t inc);

	/* Ordered according to seq no. */
	std::deque<TCPPacket*> packets_;

        /* seq no of next non-NULL get. */
	uint32_t nextSeqNo_;

	/* Maximum ack seen in the other direction (acking data
	 * buffered in this PacketBuffer).
	 */
	uint32_t ack_;

	/* No more than maxSize_ + one packet worth of payload will be
	 * buffered.
	 */
	int maxSize_;

	/* Number of bytes buffered payload. */
	int bytesUsed_;

	/* True if we got the first packet, otherwise false. */
	bool gotFirstPacket_;

	/* True if this session is alive, otherwise false. */
	bool alive_;
};

#endif
