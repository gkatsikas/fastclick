/*
 * httpout.{cc,hh} -- exit point of an HTTP path in the stack of the middlebox
 * Romain Gaillard
 * Tom Barbette
 *
 */

#include <click/config.h>
#include <click/router.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/string.hh>
#include "httpout.hh"
#include "httpin.hh"

CLICK_DECLS

HTTPOut::HTTPOut()
{
    #if HAVE_BATCH
        in_batch_mode = BATCH_MODE_YES;
    #endif
}

int HTTPOut::configure(Vector<String> &conf, ErrorHandler *errh)
{
    ElementCastTracker visitor(router(),"HTTPIn");
    router()->visit_upstream(this, -1, &visitor);
    if (visitor.size() != 1) {
        return errh->error("Found no or more than 1 HTTPIn element. Specify which one to use with OUTNAME");
    }
    _in = static_cast<HTTPIn*>(visitor[0]);

    return 0;
}

int
HTTPOut::maxModificationLevel(Element* stop) {
    int r = StackSpaceElement<fcb_httpout>::maxModificationLevel(_in);
    if (r >= MODIFICATION_RESIZE) {
        _in->_resize = true;
        click_chatter("HTTPOut in resize mode.");
    }
    return r | _in->maxModificationLevel(stop);
}

int HTTPOut::initialize(ErrorHandler *errh) {
    maxModificationLevel(_in); //Force computation of resize if the further stack does not call maxMod
    return 0;
}

void HTTPOut::push_batch(int, struct fcb_httpout* fcb, PacketBatch* flow)
{
    Packet* lastPacket = 0;
    bool doClose = false;

    auto fnt = [this,fcb,&doClose,&lastPacket](Packet*p) -> Packet* {

        // Check that the packet contains HTTP content
        if(!p->isPacketContentEmpty() && _in->fcb_data()->contentLength > 0)
        {
            if (_in->_buffer > 0) {
                    
                WritablePacket *packet = p->uniqueify();

                assert(packet != NULL);
                FlowBuffer &flowBuffer = fcb->flowBuffer;
                flowBuffer.enqueue(packet);
                lastPacket = packet;

                // Check if we have the whole content in the buffer
                if(isLastUsefulPacket(packet))
                {
                        //click_chatter("Last usefull, flushing !");
                    // Compute the new Content-Length
                    FlowBufferIter it = flowBuffer.begin();

                    uint64_t newContentLength = 0;
                    while(it != flowBuffer.end())
                    {
                        newContentLength += (*it)->getPacketContentSize();
                        ++it;
                    }

                    PacketBatch *toPush = flowBuffer.dequeueAll();

                    int sz = toPush->count();
                    Packet* next = toPush->next();
                    Packet* tail = toPush->tail();
                    char bufferHeader[25];

                    sprintf(bufferHeader, "%lu", newContentLength);
                    WritablePacket* newHead = setHeaderContent(fcb, toPush, "Content-Length", bufferHeader);
                    if (newHead != toPush) {
                        toPush = PacketBatch::start_head(newHead);
                        toPush->set_next(next);
                        toPush->set_count(sz);
                        toPush->set_tail(tail);
                    }

                    // Flush the buffer
                    output_push_batch(0, toPush);
                } //TODO : when going out of max buffer size, jump to the "non-buffering" mode

                return NULL;
            } else { //Do not buffer, or buffer is exhausted (todo)
                //TODO : Go to chunk if need be
                if (isLastUsefulPacket(p) && _in->_fill == RESIZE_FILL_END) {
                    if (_in->fcb_data()->contentRemoved > 0) {
                        WritablePacket* packet = p->uniqueify();
                        int am = _in->fcb_data()->contentRemoved;
                        int pos = packet->getPacketContentSize() - 1;
                        packet = insertBytes(packet, pos, _in->fcb_data()->contentRemoved);
                        //click_chatter("%d %d %d",pos,packet->getPacketContent() - packet->data(), _in->fcb_data()->contentRemoved);
                        memset(packet->getPacketContent() + pos + 1 , ' ',am);
                        return packet; 
                    } else if (_in->fcb_data()->contentRemoved < 0) {
                        click_chatter("fill_end method does not work with HTTP payload that is growing after all modifications have been done. The transfer mode should have been changed to chunked, or the content buffered but it is too late for that.");
                    }
                }
                
                //THis needs to intercept and recreate the close also
                //It will not work as it
                //TODO : if keepalive was not specified, we can just close prematurely
                 if (_in->fcb_data()->CLRemoved) {
                    fcb->seen += p->getPacketContentSize();
                    //click_chatter("Seen %d/%d-%d",fcb->seen, _in->fcb_data()->contentLength, _in->fcb_data()->contentRemoved);
                    if (fcb->seen >= _in->fcb_data()->contentLength - _in->fcb_data()->contentRemoved) {
                        WritablePacket *packet = p->uniqueify();
                        click_tcp* tcph = packet->tcp_header();
                        // Change the flags of the packet
//                        tcph->th_flags |= TH_FIN;
//                        doClose = true;
                        return packet;
                    }
                }
                return p;
            }
        } else {
            return p;
        }
    };


    if (!_in->_resize)
        goto end;

    EXECUTE_FOR_EACH_PACKET_DROPPABLE(fnt, flow, [](Packet*){});
    if (lastPacket)
            requestMorePackets(lastPacket); 

    if (doClose) {
        fcb_stack->acquire(1);
        lastPacket = flow->tail()->clone(true);
    }

end:
    if (flow)
        output_push_batch(0,flow);
    if (doClose) {
        closeConnection(lastPacket, true);
        lastPacket->kill();
    }
}

WritablePacket* HTTPOut::setHeaderContent(struct fcb_httpout *fcb, WritablePacket* packet,
    const char* headerName, const char* content)
{
    unsigned char* source = getPayload(packet);

    // We set the content pointer to the TCP payload as we want to manipulate HTTP headers
    // and the current content pointer is set to the HTTP payload
    uint16_t offsetTcp = getPayloadOffset(packet);
    packet->setContentOffset(offsetTcp);

    unsigned char* beginning = (unsigned char*)searchInContent((char*)source, headerName,
        getPayloadLength(packet));

    if(beginning == NULL)
        return packet;

    beginning += strlen(headerName) + 1;

    uint32_t lengthLeft = getPayloadLength(packet) - (beginning - source);

    unsigned char* end = (unsigned char*)searchInContent((char*)beginning, "\r\n", lengthLeft);
    if(end == NULL)
        return packet;

    // Skip spaces at the beginning of the string
    while(beginning < end && beginning[0] == ' ')
        beginning++;

    uint32_t startPos = beginning - source;
    uint32_t newSize = strlen(content);
    uint32_t endPos = startPos + newSize;
    uint32_t prevSize = end - beginning;
    uint32_t prevEndPos = startPos + prevSize;
    int offset = newSize - prevSize;

    // Ensure that the header has the right size
    if(offset > 0)
        packet = insertBytes(packet, prevEndPos, offset);
    else if(offset < 0)
        removeBytes(packet, endPos, -offset);

    memcpy(beginning, content, newSize);

    return packet;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(HTTPOut)
//ELEMENT_MT_SAFE(HTTPOut)
