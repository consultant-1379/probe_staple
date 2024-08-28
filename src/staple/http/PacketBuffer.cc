#include <assert.h>

#include <limits>
#include <staple/Packet.h>
#include <staple/http/log.h>
#include "PacketBuffer.h"

using std::deque;

static const bool PBUF_DEBUG = false;
const uint32_t PacketBuffer::INSANELY_LARGE_SEQ_ACK = 10*1024*1024;

PacketBuffer::PacketBuffer(Staple& staple, int maxSize) : staple_(staple)
{
	ack_ = 0;
	nextSeqNo_ = 0;
	maxSize_ = maxSize;
	bytesUsed_ = 0;
	gotFirstPacket_ = false;
	alive_ = true;
}

PacketBuffer::~PacketBuffer()
{
	if (PBUF_DEBUG)
		log(staple_, "PacketBuffer::~PacketBuffer ", this, " nextSeqNo: ", nextSeqNo_, " size: ", packets_.size());

	for (deque<TCPPacket*>::iterator it = packets_.begin(); it != packets_.end(); ++it)
		delete *it;
}

/* Return true if x+y overflows and otherwise false. */
static bool willOverflow(uint32_t x, uint32_t y)
{
	if (x + y < x)
		return true;
	else
		return false;
}

void PacketBuffer::updateNextSeqNo(uint32_t inc)
{
	if (willOverflow(nextSeqNo_, inc)) {
		/* The rest of the code isn't aware of overflows in
		 * the sequence number, so we skip the update of
		 * nextSeqNo_ which will result in that we ignore the
		 * rest of the session. No interesting sessions should
		 * be this long anyway (the sequence numbers are
		 * relative so any such session have sent more than 4
		 * GB payload in at least one direction).
		 */
		WARN("PacketBuffer::updateNextSeqNo nextSeqNo_ += inc will overflow, ignoring rest of session.",
		     " nextSeqNo_: ", nextSeqNo_,
		     " inc: ", inc);
	} else {
		nextSeqNo_ += inc;
	}
}

bool PacketBuffer::tryAddGet(const TCPPacket& p)
{
	assert(alive_);
	checkInvariant();

	// Check for duplicate packet.
	if (gotFirstPacket_ && p.seq < nextSeqNo_)
		return false;

	if (!packets_.empty()) {
		if (p.seq < packets_.front()->seq) {
			// Check for overlapping packet.
			if (p.seq + p.TCPPLLen > packets_.front()->seq)
				return false;

			// Front of list is correct place! Continue.
		} else {
			// Front of list is not correct place, return.
			return false;
		}
	}

	// Check for packet length mismatch. This will be fixed by
	// PacketBuffer::get so we cannot use the packet right away.
	if (p.TCPPLLen != p.payloadSavedLen)
		return false;

	if (!gotFirstPacket_) {
		nextSeqNo_ = p.seq;
		gotFirstPacket_ = true;
	} else {
		if (p.seq != nextSeqNo_)
			return false;
	}

	updateNextSeqNo(p.TCPPLLen);
	checkInvariant();

	return true;
}

bool PacketBuffer::add(const TCPPacket& p)
{
	assert(alive_);
	checkInvariant();

	TCPPacket* packet = new TCPPacket(p);
	packet->pL2Packet = p.pL2Packet->clone();

	deque<TCPPacket*>::iterator it;

	if (PBUF_DEBUG)
		log(staple_, "PacketBuffer::add ", this,
		    " gotFirst: ", gotFirstPacket_,
		    " nextSeq: ", nextSeqNo_,
		    " size: ", packets_.size(), ' ',
		    *packet);

	if (gotFirstPacket_ && packet->seq < nextSeqNo_) {
		WARN("PacketBuffer::add Skipping duplicate packet. "
		     "nextSeqNo: ", nextSeqNo_, ' ', *packet);
		delete packet;
		return true;
	}

	for (it = packets_.begin(); it != packets_.end(); ++it) {
		// Find the correct place in the packets_ list for the
		// new packet.
		if (packet->seq < (*it)->seq) {
			if (packet->seq + packet->TCPPLLen > (*it)->seq) {
				WARN("PacketBuffer::add Overlapping packet ",
				     " next seq: ", (*it)->seq, ' ',
				     *packet);
				delete packet;
				return true;
			}

			// Correct place found! Break out of the loop.
			break;
		} else if (packet->seq == (*it)->seq) {
			if (packet->TCPPLLen != (*it)->TCPPLLen)
				WARN("PacketBuffer::add Duplicate seq no, but not same length."
				     " next seq: ", (*it)->seq,
				     " next TCPPLLen: ", (*it)->TCPPLLen, ' ',
				     *packet);
			delete packet;
			return true;
		}
		// else we try the next packet in the list.
	}

	uint32_t prevSeq;
	if (it == packets_.begin()) {
		// Not really the previous seq, but close enough.
		prevSeq = nextSeqNo_;
	} else {
		TCPPacket* prev = *(it-1);
		if (prev->seq + prev->TCPPLLen > packet->seq) {
			WARN("PacketBuffer::add Overlapping packet (with previous)",
			     " prev seq: ", prev->seq, " prev len: ", prev->TCPPLLen, ' ',
			     *packet);
			delete packet;
			return true;
		}

		prevSeq = prev->seq;
	}

	if (packet->seq - prevSeq > INSANELY_LARGE_SEQ_ACK) {
		WARN("PacketBuffer::add Insanely large seq, ignoring packet.",
		     " prev seq: ", prevSeq, " new seq: ", packet->seq, ' ',
		     *packet);
		delete packet;
		return true;
	}

	if (bytesUsed_ > maxSize_) {
		delete packet;
		return false;
	}

	packets_.insert(it, packet);
	bytesUsed_ += packet->payloadSavedLen;

	if (!gotFirstPacket_) {
		nextSeqNo_ = packet->seq;
		gotFirstPacket_ = true;
	}
	checkInvariant();
	return true;
}

void PacketBuffer::checkInvariant()
{
	if (!packets_.empty()) {
		assert(nextSeqNo_ <= packets_.front()->seq);
		if (PBUF_DEBUG) {
			/* This check is a bit expensive if packets_
			 * is large, so we only do it if PBUF_DEBUG is
			 * true.
			 */
			for (size_t i = 1; i < packets_.size(); i++) {
				assert(packets_[i-1]->seq + packets_[i-1]->TCPPLLen <= packets_[i]->seq);
			}
		}
	}
}

TCPPacket* PacketBuffer::get(/*int offset* */)
{
	checkInvariant();
	if (packets_.empty()) {
		if (PBUF_DEBUG)
			log(staple_, "PacketBuffer::get ", this, " ret: NULL, empty buffer");
		return NULL;
	}

	TCPPacket* p = packets_.front();
	if (p->seq == nextSeqNo_) {
		packets_.pop_front();

		if (p->TCPPLLen != p->payloadSavedLen) {
			WARN("PacketBuffer::get TCPPLen != payloadSavedLen ",
			     p->TCPPLLen, ' ', p->payloadSavedLen);
			assert(p->TCPPLLen > p->payloadSavedLen);
		}

		updateNextSeqNo(p->TCPPLLen);
		bytesUsed_ -= p->payloadSavedLen;
		if (PBUF_DEBUG)
			log(staple_, "PacketBuffer::get ", this, " ret: ", *p);
		checkInvariant();
		return p;
	} else if (!alive_ || maxSize_ < bytesUsed_ || nextSeqNo_ < ack_) {
		/* Either the connection is not alive, we have filled
		 * our buffer space, or we have received ACKs for data
		 * we haven't seen (i.e., capture loss). Let's create
		 * a fake packet with a payload to reach the next
		 * packet we have. The payload will not be there
		 * (payloadSavedLen is set to 0), but this allows
		 * users of the PacketBuffer to keep going. With some
		 * luck the fake packet will be in some part of the
		 * TCP stream that we don't care about (such as in the
		 * middle of a HTTP response).
		 */
		TCPPacket* ret = new TCPPacket(p->staple);
		ret->Init();

		ret->payload = new Byte[0];
		ret->payloadSavedLen = 0;
		ret->pL2Packet = p->pL2Packet->clone();
		ret->pL2Packet->l2SavedLen = 0;
		ret->pL2Packet->pL3Packet = ret;

		/* Try to set rest of IPPacket and TCPPacket fields to
		 * something reasonable.
		 */
		ret->srcIP = p->srcIP;
		ret->dstIP = p->dstIP;
		ret->match = p->match;
		ret->direction = p->direction;
		ret->IPPktLen = 0; // Set below.
		ret->IPId = p->IPId;
		ret->IPFlags = p->IPFlags;
		ret->fragOffset = 0;
		ret->srcPort = p->srcPort;
		ret->dstPort = p->dstPort;
		ret->TCPFlags = p->TCPFlags;
		ret->seq = nextSeqNo_;
		ret->ack = p->ack;
		ret->rwnd = p->rwnd;
		ret->options = 0;
		ret->TCPPLLen = 0; // Set below.
		ret->sackBlockNum = 0;
		ret->tsValue = 0;
		ret->tsEcho = 0;
		ret->wndScaleVal = p->wndScaleVal;

		uint32_t holeLen = std::numeric_limits<uint32_t>::max();
		if (nextSeqNo_ < ack_)
			holeLen = ack_ - nextSeqNo_;

		assert(nextSeqNo_ < p->seq);
		if (p->seq - nextSeqNo_ < holeLen)
			holeLen = p->seq - nextSeqNo_;

		if (0xffff - 20 /* IP header */ - 20 /* TCP header */ < holeLen)
			holeLen = 0xffff - 20 - 20;
		ret->TCPPLLen = holeLen;
		ret->IPPktLen =
			ret->TCPPLLen +
			20 /* IP header */ +
			20 /* TCP header */;

		if (nextSeqNo_ < ack_) {
			WARN("PacketBuffer::get possible capture drop nextSeqNo_ < ack_, inserting fake packet. "
			     "next seq: ", nextSeqNo_, " ack_: ", ack_, " length: ", ret->TCPPLLen,
			     ' ', *p);
		} else if (!alive_) {
			WARN("PacketBuffer::get possible capture drop !alive_, inserting fake packet. "
			     "next seq: ", nextSeqNo_, " length: ", ret->TCPPLLen,
			     ' ', *p);
		} else {
			WARN("PacketBuffer::get possible capture drop buffer full, inserting fake packet. "
			     "next seq: ", nextSeqNo_, " length: ", ret->TCPPLLen,
			     ' ', *p);
		}

		updateNextSeqNo(ret->TCPPLLen);
		checkInvariant();
		return ret;
	} else {
		if (PBUF_DEBUG)
			log(staple_, "PacketBuffer::get ", this, " ret: NULL, don't have next seq ", nextSeqNo_);
		return NULL;
	}
}

void PacketBuffer::finishTCPSession()
{
	alive_ = false;
}

bool PacketBuffer::hasPackets() const
{
	return !packets_.empty();
}

void PacketBuffer::updateAck(uint32_t ack)
{
	if (ack_ < ack) {
		if (INSANELY_LARGE_SEQ_ACK < ack - ack_ &&
		    nextSeqNo_ < ack &&
		    INSANELY_LARGE_SEQ_ACK < ack - nextSeqNo_)
			WARN("PacketBuffer::updateAck Insanely large ack update, ignoring.",
			     " old ack: ", ack_, " new ack: ", ack, " nextSeqNo_: ", nextSeqNo_);
		else
			ack_ = ack;
	}
}
