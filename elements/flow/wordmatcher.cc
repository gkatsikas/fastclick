/*
 * WordMatcher.{cc,hh} -- remove insults in web pages
 * Romain Gaillard
 * Tom Barbette
 */

#include <click/config.h>
#include <click/router.hh>
#include <click/args.hh>
#include <click/error.hh>
#include "wordmatcher.hh"
#include "tcpelement.hh"

CLICK_DECLS

WordMatcher::WordMatcher() : insults(), _mode(ALERT), _quiet(false)
{
    _all = false;
}

int WordMatcher::configure(Vector<String> &conf, ErrorHandler *errh)
{
    //TODO : use a proper automaton for insults
    _insert_msg = "<font color='red'>Blocked content !</font><br />";
    String mode = "MASK";
    bool all = false;
    if(Args(conf, this, errh)
            .read_all("WORD", insults)
            .read_p("MODE", mode)
            .read_p("MSG", _insert_msg)
            .read("ALL", all)
            .read("QUIET", _quiet)
    .complete() < 0)
        return -1;

    if (all) {
        _all = all;
        errh->warning("Element not optimized for ALL");
    }

    if (mode == "CLOSE") {
        _mode = CLOSE;
    } else if (mode == "MASK") {
        _mode = MASK;
    } else if (mode == "REMOVE") {
        _mode = REMOVE;
    } else if (mode == "REPLACE") {
        _mode = REPLACE;
    } else if (mode == "FULL") {
        _mode = FULL;
    } else if (mode == "ALERT") {
        _mode = ALERT;
    } else {
        return errh->error("Mode must be MASK, REMOVE, REPLACE, ALERT, CLOSE or FULL");
    }


    if (insults.size() == 0) {
        return errh->error("No words given");
    }

    return 0;
}

int
WordMatcher::maxModificationLevel(Element* stop) {
    int mod = StackSpaceElement<fcb_WordMatcher>::maxModificationLevel(stop) | MODIFICATION_STALL;
    if (_mode == FULL || _mode == REMOVE) {
        mod |= MODIFICATION_RESIZE;
    }
    if (_mode == MASK || _mode == REPLACE) {
        mod |= MODIFICATION_REPLACE;
    }
    if (_mode != ALERT && _mode != CLOSE)
        mod |= MODIFICATION_WRITABLE;
    return mod;
}


void WordMatcher::push_batch(int port, fcb_WordMatcher* WordMatcher, PacketBatch* flow)
{
    WordMatcher->flowBuffer.enqueueAll(flow);

    auto iter = WordMatcher->flowBuffer.contentBegin();
    if (!iter.current()) {
        goto finished;
    }


    for(int i = 0; i < insults.size(); ++i)
    {
        const char* insult = insults[i].c_str();
    /*
     The following is left for reference on how to do a byte-to-byte matching, that is obviously not very efficient
        if (_mode == MASK) { //Masking mode
            auto end = WordMatcher->flowBuffer.contentEnd();

            while (iter != end) {
                if (*iter ==  insult[0]) {
                    int pos = 0;
                    typeof(iter) start_pos = iter;
                    do {
                        ++pos;
                        ++iter;
                        if (iter == end) {
                            click_chatter("Middle");
                            //Finished in the middle of a potential match, ask for more packets
                            flow = start_pos.flush();
                            if(!isLastUsefulPacket(start_pos.current())) {
                                click_chatter("request");
                                requestMorePackets(start_pos.current(), false);
                                goto needMore;
                            } else {
                                goto finished;
                            }
                        }
                        if (insult[pos] == '\0') {
                            WordMatcher->counterRemoved += 1;
                            int n = 0;
                            while (n < pos) {
                                *start_pos = '*';
                                ++start_pos;
                                ++n;
                            }
                            pos = 0;
                        }
                    } while (*iter == insult[pos]);
                }
                ++iter;
            }
        }
*/
        {
            int result;
            do {
                //iter = WordMatcher->flowBuffer.search(iter, insult, &result);
                int l = insults[i].length();
                iter = WordMatcher->flowBuffer.searchSSE(iter, insult, l, &result);
                click_chatter("Result %d", result);
                if (result == 1) {
                    if (_mode == REMOVE) {
                        WordMatcher->flowBuffer.remove(iter, l, this);
                        while (iter.leftInChunk() == 0 && iter)
                            iter.moveToNextChunk();
                    } else if (_mode == MASK) {
                        WordMatcher->flowBuffer.replaceInFlow(iter, l, "*", 1, true, this);
                    } else if (_mode == REPLACE) {
                        WordMatcher->flowBuffer.replaceInFlow(iter, l, _insert_msg.c_str(), insults[i].length(), false, this);
                    } else if (_mode == FULL) {
                        WordMatcher->flowBuffer.replaceInFlow(iter, l, _insert_msg.c_str(), _insert_msg.length(), false, this);
                    } else if (_mode == CLOSE) {
                        goto closeconn; 
                    } else { //_mode == ALERT
                        if (!_quiet)
                            click_chatter("Attack found !");
                        if (_all)
                            iter += l;
                    }

                    WordMatcher->counterRemoved += 1;
                }
            } while (result == 1 && iter.leftInChunk() && _all);
            // While we keep finding complete insults in the packet
            if (result == 0) { //Finished in the middle of a potential match
                if(!isLastUsefulPacket(flow->tail())) {
                    requestMorePackets(flow->tail(), false);
                    flow = WordMatcher->flowBuffer.dequeueUpTo(iter.current());
                    // We will re-match the whole last packet, see FlowIDSMatcher for better implementation
                    goto needMore;
                } else {
                    goto finished;
                }
            }
        }
    }
    finished:
    //Finished without being in the middle of an insult. If closeconn was set and there was an insult, we already jumped further.
    output_push_batch(0, WordMatcher->flowBuffer.dequeueAll());
    return;

    closeconn:

    closeConnection(flow, false);
    WordMatcher->flowBuffer.dequeueAll()->fast_kill();

    return;

    needMore:


    if(flow != NULL)
        output_push_batch(0, flow);
    return;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(WordMatcher)
ELEMENT_MT_SAFE(WordMatcher)
