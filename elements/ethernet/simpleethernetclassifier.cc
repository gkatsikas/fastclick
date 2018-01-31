/*
 * simpleethernetclassifier.{cc,hh} -- Simple Ethernet classifier
 * Georgios Katsikas
 *
 * Copyright (c) 2017-present KTH Royal Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <click/nameinfo.hh>
#include "simpleethernetclassifier.hh"

#define DEBUG_MODE            false
#define VERBOSE_MODE           true

#define ETHERTYPE_OFFSET         12
#define ETHERTYPE_ARP_OFFSET     20
#define ETHERTYPE_VLAN_IP_OFFSET 16

#define ETHERTYPE_ARP_REQ    0x0001
#define ETHERTYPE_ARP_RES    0x0002

CLICK_DECLS

static NameDB *dbs[2];

static const StaticNameDB::Entry type_entries[] = {
    { "arp",       ETH_CLASSIFIER_TYPE::ARP       },
    { "arp req",   ETH_CLASSIFIER_TYPE::ARP_REQ   },
    { "arp res",   ETH_CLASSIFIER_TYPE::ARP_RES   },
    { "ipv4",      ETH_CLASSIFIER_TYPE::IPV4      },
    { "ipv6",      ETH_CLASSIFIER_TYPE::IPV6      },
    { "mpls",      ETH_CLASSIFIER_TYPE::MPLS      },
    { "vlan",      ETH_CLASSIFIER_TYPE::VLAN      },
    { "vlan ipv4", ETH_CLASSIFIER_TYPE::VLAN_IPV4 },
    { "vlan ipv6", ETH_CLASSIFIER_TYPE::VLAN_IPV6 }
};

static const StaticNameDB::Entry type_hex_values[] = {
    { "arp",       ETHERTYPE_ARP     },
    { "arp req",   ETHERTYPE_ARP_REQ },
    { "arp res",   ETHERTYPE_ARP_RES },
    { "ipv4",      ETHERTYPE_IP      },
    { "ipv6",      ETHERTYPE_IP6     },
    { "mpls",      ETHERTYPE_MPLS    },
    { "vlan",      ETHERTYPE_8021Q   },
    { "vlan ipv4", ETHERTYPE_IP      },
    { "vlan ipv6", ETHERTYPE_IP6     }
};

static void
separate_text(const String &text, Vector<String> &words)
{
    const char *s = text.data();
    int len = text.length();
    int pos = 0;
    while (pos < len) {
        while (pos < len && isspace((unsigned char) s[pos]))
            pos++;
        switch (s[pos]) {
            case '&': case '|':
                if (pos < len - 1 && s[pos+1] == s[pos])
                    goto two_char;
                goto one_char;

            case '<': case '>': case '!': case '=':
                if (pos < len - 1 && s[pos+1] == '=')
                    goto two_char;
                goto one_char;

            case '(': case ')': case '[': case ']': case ',': case ';':
            case '?':
                one_char:
                words.push_back(text.substring(pos, 1));
                pos++;
                break;

                two_char:
                words.push_back(text.substring(pos, 2));
                pos += 2;
                break;

            default: {
                int first = pos;
                while (pos < len && (isalnum((unsigned char) s[pos]) ||
                       s[pos] == '-' || s[pos] == '.' || s[pos] == '/' ||
                       s[pos] == '@' || s[pos] == '_' || s[pos] == ':'))
                    pos++;

                if (pos == first)
                    pos++;

                words.push_back(text.substring(first, pos - first));

                break;
            }
        }
    }
}

SimpleEthernetClassifier::SimpleEthernetClassifier()
{
    _debug_mode   = DEBUG_MODE;
    _verbose      = VERBOSE_MODE;
    _has_wildcard = false;

    _dropped_packets = 0;

    _root    = new TreeNode("root", "none", 0, 0, 0, -1);
    _wilcard = NULL;

    _tc_to_offset = new HashTable<String, HashTable<unsigned short, unsigned short>>();
    _eth_type_to_tc_proto  = new HashTable<unsigned short, String>();
    _eth_type_to_tree_node = new HashTable<unsigned short, TreeNode *>();
}

SimpleEthernetClassifier::~SimpleEthernetClassifier()
{
    if (_verbose) {
        click_chatter(
            "\n[%s] Matched packets: %" PRIu64 " - Dropped packets: %" PRIu64 "",
            name().c_str(), matched_packets_nb(), dropped_packets_nb()
        );
    }

    if (_tc_to_offset) {
        delete _tc_to_offset;
        _tc_to_offset = NULL;
    }

    if (_eth_type_to_tc_proto) {
        delete _eth_type_to_tc_proto;
        _eth_type_to_tc_proto = NULL;
    }

    // Recursively deletes the entire tree
    if (_root ) {
        delete _root;
        _root = NULL;
    }

    if (_eth_type_to_tree_node) {
        delete _eth_type_to_tree_node;
        _eth_type_to_tree_node = NULL;
    }
}

void
SimpleEthernetClassifier::static_initialize()
{
    dbs[0] = new StaticNameDB(
        NameInfo::T_ETHERNET_CLASS_TYPE,
        String(),
        type_entries,
        sizeof(type_entries) / sizeof(type_entries[0])
    );

    dbs[1] = new StaticNameDB(
        NameInfo::T_ETHERNET_TYPES_TO_HEX,
        String(),
        type_hex_values,
        sizeof(type_hex_values) / sizeof(type_hex_values[0])
    );

    NameInfo::installdb(dbs[0], 0);
    NameInfo::installdb(dbs[1], 0);
}

void
SimpleEthernetClassifier::static_cleanup()
{
    if (!dbs) {
        return;
    }

    delete dbs[0];
    delete dbs[1];
}

int
SimpleEthernetClassifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
    for (unsigned short port_no = 0; port_no < conf.size(); port_no++) {
        // The traffic class label
        String label = conf[port_no];

        // Split the traffic class into tokens
        Vector<String> words;
        separate_text(label, words);
        String protocol = words[0];
        bool has_subclass = false;
        click_chatter("");

        // Wildcard traffic class that covers the remaining traffic types
        if ((protocol.length() == 1 || protocol.length() == 3) &&
            (protocol == "-" || protocol == "any" || protocol == "all")) {
            // Only one wildcard is allowed
            if (_has_wildcard) {
                click_chatter("Duplicate wildcard rule");
                return -1;
            }

            _wilcard = _root->add_child(label, protocol, 0, 0, 0, port_no);
            _has_wildcard = true;
            continue;
        }

        // There is a subclass. Only one subclass type is currently supported
        if (words.size() > 1) {
            has_subclass = true;
        }

        // Check whether the input traffic class exists in our database.
        int got = 0;
        int32_t tc_type_idx = 0;
        got = NameInfo::query_int(NameInfo::T_ETHERNET_CLASS_TYPE, 0, label, &tc_type_idx);
        if (!got) {
            click_chatter("Failed to retrieve the class name of %s", label.c_str());
            return -1;
        }

        /**
         * Store the header offsets and values of this traffic class
         */
        if (!create_patterns(label, tc_type_idx, errh)) {
            return -1;
        }

        /**
         * Find the primary pattern of this traffic class.
         * This value is used to classify incoming packets in stage 1.
         */
        int primary_proto = 0;
        got = NameInfo::query_int(NameInfo::T_ETHERNET_TYPES_TO_HEX, 0, protocol, &primary_proto);
        if (!got) {
            errh->error(
                "Failed to retrieve the hex type of %s",
                protocol.c_str()
            );
            return -1;
        }

        /**
         * Some of the supported classification options
         * are not currently supported by Click.
         */
        if (!is_supported_by_click(primary_proto)) {
            errh->error(
                "Ethernet type %s is not currently supported by Click",
                label.c_str()
            );
            return -1;
        }

        /**
         * Retrieve the header offset associated with the identified protocol.
         */
        unsigned short primary_offset = find_offset(label, primary_proto, errh);

        /**
         * Add a node in the classification tree.
         */
        TreeNode *added_node = _root->add_child(
            protocol, protocol, primary_offset,
            sizeof(primary_offset), primary_proto, port_no
        );

        // This case should never happen
        if (!added_node && !has_subclass) {
            errh->error(
                "Failed to create a pattern for %s",
                label.c_str()
            );
            return -1;
        }
        // This traffic class requires to branch our tree
        else if (has_subclass) {
            TreeNode *child = add_subclass(label, protocol, port_no, errh);

            if (!child) {
                errh->error(
                    "Failed to create a pattern for %s", label.c_str()
                );
                return -1;
            }
        }

        /**
         * Map the input type to a traffic class, such that
         * we can fetch the output port when we see this type.
         */
        _eth_type_to_tc_proto->find_insert(primary_proto, protocol);

        TreeNode *parent = _root->base_lookup(protocol);
        if (!parent) {
            errh->error(
                "Unavailable classifier for %s",
                label.c_str()
            );
            return -1;
        }
        _eth_type_to_tree_node->find_insert(primary_proto, parent);
    }

    /**
     * Parse the classification tree and activate
     * all the nodes according to the user's input.
     */
    _root->activate(conf);

    if (_verbose)
        _root->print_node();

    if (_debug_mode)
        print_debug_info();

    return 0;
}

bool
SimpleEthernetClassifier::is_supported_by_click(int tc_type_idx)
{
    ETH_CLASSIFIER_TYPE tc_type = enum_of_index(tc_type_idx);

    /**
     * Currently, Click does not support MPLS.
     */
    if (tc_type == ETH_CLASSIFIER_TYPE::MPLS) {
        return false;
    }

    return true;
}

bool
SimpleEthernetClassifier::create_patterns(
        String label, int tc_type_idx, ErrorHandler *errh)
{
    HashTable<unsigned short, unsigned short> offsets;

    ETH_CLASSIFIER_TYPE tc_type = enum_of_index(tc_type_idx);

    switch (tc_type) {
        case ETH_CLASSIFIER_TYPE::ARP:
            offsets.find_insert(ETHERTYPE_ARP,     ETHERTYPE_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::ARP_REQ:
            offsets.find_insert(ETHERTYPE_ARP,     ETHERTYPE_OFFSET);
            offsets.find_insert(ETHERTYPE_ARP_REQ, ETHERTYPE_ARP_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::ARP_RES:
            offsets.find_insert(ETHERTYPE_ARP,     ETHERTYPE_OFFSET);
            offsets.find_insert(ETHERTYPE_ARP_RES, ETHERTYPE_ARP_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::IPV4:
            offsets.find_insert(ETHERTYPE_IP,      ETHERTYPE_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::IPV6:
            offsets.find_insert(ETHERTYPE_IP6,     ETHERTYPE_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::MPLS:
            offsets.find_insert(ETHERTYPE_MPLS,    ETHERTYPE_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::VLAN:
            offsets.find_insert(ETHERTYPE_8021Q,   ETHERTYPE_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::VLAN_IPV4:
            offsets.find_insert(ETHERTYPE_8021Q,   ETHERTYPE_OFFSET);
            offsets.find_insert(ETHERTYPE_IP,      ETHERTYPE_VLAN_IP_OFFSET);
            break;
        case ETH_CLASSIFIER_TYPE::VLAN_IPV6:
            offsets.find_insert(ETHERTYPE_8021Q,   ETHERTYPE_OFFSET);
            offsets.find_insert(ETHERTYPE_IP6,     ETHERTYPE_VLAN_IP_OFFSET);
            break;
        default:
            errh->error(
                "Unexpected traffic class type for %s",
                label.c_str()
            );
            return false;
    }

    _tc_to_offset->find_insert(label, offsets);

    return true;
}

unsigned short
SimpleEthernetClassifier::find_offset(
        String label, unsigned short proto, ErrorHandler *errh)
{
    HashTable<unsigned short, unsigned short> offsets = _tc_to_offset->find(label).value();

    if (offsets.empty()) {
        errh->error(
            "Primary offset for %s is not found",
            label.c_str()
        );
        return -1;
    }

    return offsets.find(proto).value();
}

TreeNode *
SimpleEthernetClassifier::add_subclass(
        String label, String protocol, short port_no, ErrorHandler *errh)
{
    int sec_proto = 0;
    int got = NameInfo::query_int(NameInfo::T_ETHERNET_TYPES_TO_HEX, 0, label, &sec_proto);
    if (!got) {
        errh->error(
            "Failed to retrieve the hex type of %s",
            label.c_str()
        );
        return NULL;
    }

    unsigned short sec_offset = find_offset(label, sec_proto, errh);
    TreeNode *new_node = _root->add_child(
        label, protocol, sec_offset, sizeof(sec_offset), sec_proto, port_no
    );
    new_node->set_active(true);

    return new_node;
}

int
SimpleEthernetClassifier::process(int, Packet *p)
{
    int output_port = -1;
    String proto, label;
    Vector<TreeNode *> children;

    const click_ether *eth = reinterpret_cast<const click_ether *>(p->data());
    uint16_t eth_type = ntohs(eth->ether_type);

    // Find which node of the tree should handle this traffic class
    TreeNode *parent = _eth_type_to_tree_node->find(eth_type).value();
    if (!parent) {
        goto no_match;
    }

    // Increment the pkt_count even if the parent traffic class is not an exact match
    parent->increment_pkt_count();

    // This is an exact match, we are done
    if ((parent->get_children_nb() == 0) && (parent->get_active())) {
        return parent->get_output_port();
    }

    // Extract the traffic class of the protocol
    proto = _eth_type_to_tc_proto->find(eth_type).value();
    // Label might be more specific than protocol, but we start abstract
    label = proto;

    // We descend the tree to find an exact match
    children = parent->exact_lookup_from_parent(label, proto, parent);
    if (children.empty()) {
        goto no_match;
    }

    for (auto child : children) {
        uint16_t next_field;

        // Find the next offset in the header to perform a match
        const unsigned char *next_offset = p->data() + child->get_header_offset();

        // Keep the header field at this offset
        memcpy((void *)(&next_field), next_offset, sizeof(uint16_t));
        next_field = ntohs(next_field);

        // Exact match
        if (next_field == child->get_header_value()) {
            output_port = child->get_output_port();
            if (output_port >= 0) {
                child->increment_pkt_count();
                return output_port;
            }
        }
    }

    no_match:
        _dropped_packets++;
        click_chatter("Unsupported Ethernet type: %x", eth_type);
        return -1;
}

void
SimpleEthernetClassifier::push(int port, Packet *p)
{
    int output_port = process(port, p);
    if (output_port < 0) {
        p->kill();
        return;
    }

    output(output_port).push(p);
}

#if HAVE_BATCH
void
SimpleEthernetClassifier::push_batch(int port, PacketBatch *batch)
{
    auto fnt = [this, port] (Packet *p) { return process(port, p); };
    CLASSIFY_EACH_PACKET(noutputs() + 1, fnt, batch, checked_output_push_batch);
}
#endif

uint64_t
SimpleEthernetClassifier::dropped_packets_nb()
{
    return _dropped_packets;
}

uint64_t
SimpleEthernetClassifier::matched_packets_nb()
{
    uint64_t pkt_count = 0;
    _root->matched_packets_nb(pkt_count);
    return pkt_count;
}

void
SimpleEthernetClassifier::print_debug_info()
{
    click_chatter("\nEthernet type --> Proto");
    for (HashTable<unsigned short, String>::const_iterator it = _eth_type_to_tc_proto->begin();
            it != _eth_type_to_tc_proto->end(); ++it) {
        click_chatter("Eth type: %x --> Proto: %s", it.key(), it.value().c_str());
    }

    click_chatter("\nEthernet type --> Tree node");
    for (HashTable<unsigned short, TreeNode *>::const_iterator it = _eth_type_to_tree_node->begin();
            it != _eth_type_to_tree_node->end(); ++it) {
        click_chatter("Eth type: %x --> Tree node: %s", it.key(), it.value()->get_label().c_str());
    }

    for (HashTable<String, HashTable<unsigned short, unsigned short>>::const_iterator
                it = _tc_to_offset->begin();
                it != _tc_to_offset->end(); ++it) {
        for (HashTable<unsigned short, unsigned short>::const_iterator
                it2 = it.value().begin();
                it2 != it.value().end(); ++it2) {
            click_chatter("Traffic class: %s --> Offset: %d", it.key().c_str(), it2.value());
        }
    }
    click_chatter("");
}

int
SimpleEthernetClassifier::reset_packet_counts()
{
    _root->reset_matched_packets();
    _dropped_packets = 0;

    return 0;
}

static String
count_handler(Element *e, void *)
{
    SimpleEthernetClassifier *sec = static_cast<SimpleEthernetClassifier *>(e);
    return String(sec->matched_packets_nb());
}

static String
dropped_handler(Element *e, void *)
{
    SimpleEthernetClassifier *sec = static_cast<SimpleEthernetClassifier *>(e);
    return String(sec->dropped_packets_nb());
}

static int
reset_count_handler(const String &, Element *e, void *, ErrorHandler *)
{
    SimpleEthernetClassifier *sec = static_cast<SimpleEthernetClassifier *>(e);
    return sec->reset_packet_counts();
}

void
SimpleEthernetClassifier::add_handlers()
{
    add_read_handler("count", count_handler, 0);
    add_read_handler("dropped", dropped_handler, 0);
    add_write_handler("reset_counts", reset_count_handler, 0, Handler::BUTTON);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SimpleEthernetClassifier)
