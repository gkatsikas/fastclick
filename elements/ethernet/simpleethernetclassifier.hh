#ifndef CLICK_SIMPLE_ETHCLASSIFIER_HH
#define CLICK_SIMPLE_ETHCLASSIFIER_HH
#include <click/batchelement.hh>
#include <click/hashtable.hh>
CLICK_DECLS

/*
=c

SimpleEthernetClassifier(pattern1, ..., patternN)

=s classification

classifies Ethernet frames by contents

=d

Classifies Ethernet frames. SimpleEthernetClassifier can have an arbitrary
number of rules.

The SimpleEthernetClassifier element has an arbitrary number of outputs.
Input packets must have their IP header annotation set; CheckIPHeader and MarkIPHeader do
this.

=e

  SimpleEthernetClassifier(
        arp req,
        arp res,
        vlan,
        ipv4,
        ipv6,
        -
  );

=h program read-only
Returns a human-readable definition of the program the SimpleEthernetClassifier
element is using to classify packets.

=a

Classifier, IPClassifier, IPFilter */

// The classifier's expression types
enum ETH_CLASSIFIER_TYPE {
        ARP,
        ARP_REQ,
        ARP_RES,
        IPV4,
        IPV6,
        MPLS,
        VLAN,
        VLAN_IPV4,
        VLAN_IPV6,
        ANY
    };

// Convert enum index to enum
inline ETH_CLASSIFIER_TYPE enum_of_index(int i) {
    return static_cast<ETH_CLASSIFIER_TYPE>(i);
}

class TreeNode {
  private:
    String         label;
    String         protocol;
    unsigned short header_offset;
    unsigned short header_length;
    unsigned short header_value;
    short          output_port;
    uint64_t       pkt_count;
    bool           active;

    Vector<TreeNode *> children;

  public:
    TreeNode(
            String         label,
            String         protocol,
            unsigned short header_offset,
            unsigned short header_length,
            unsigned short header_value,
            short          output_port) {
        this->label         = label;
        this->protocol      = protocol;
        this->header_offset = header_offset;
        this->header_length = header_length;
        this->header_value  = header_value;
        this->output_port   = output_port;
        this->pkt_count     = 0;
        this->active        = false;
    }

    ~TreeNode() {
        this->delete_node();
    }

    void delete_node() {
        if ( this->get_children_nb() == 0 ) {
            return;
        }

        for (unsigned short child_no = 0; child_no < this->get_children_nb(); child_no++) {
            TreeNode *child = this->children.at(child_no);
            if ( child->get_children_nb() == 0 ) {
                delete child;
            }
            else {
                child->delete_node();
            }
        }
    }

    void set_label(String label) {
        this->label = label;
    }

    String get_label() {
        return this->label;
    }

    void set_protocol(String protocol) {
        this->protocol = protocol;
    }

    String get_protocol() {
        return this->protocol;
    }

    void set_header_offset(unsigned short header_offset) {
        this->header_offset = header_offset;
    }

    unsigned short get_header_offset() {
        return this->header_offset;
    }

    void set_header_length(unsigned short header_length) {
        this->header_length = header_length;
    }

    unsigned short get_header_length() {
        return this->header_length;
    }

    void set_header_value(unsigned short header_value) {
        this->header_value = header_value;
    }

    unsigned short get_header_value() {
        return this->header_value;
    }

    void set_output_port(short output_port) {
        this->output_port = output_port;
    }

    short get_output_port() {
        return this->output_port;
    }

    unsigned short get_children_nb() {
        return this->children.size();
    }

    void set_pkt_count(uint64_t pkt_count) {
        this->pkt_count = pkt_count;
    }

    void increment_pkt_count() {
        this->pkt_count++;
    }

    uint64_t get_pkt_count() {
        return this->pkt_count;
    }

    void set_active(bool active) {
        this->active = active;
    }

    bool get_active() {
        return this->active;
    }

    Vector<TreeNode*> get_children() {
        return this->children;
    }

    TreeNode *add_child(
            String         label,
            String         protocol,
            unsigned short header_offset,
            unsigned short header_length,
            unsigned short header_value,
            short          output_port) {
        // The node to be added
        TreeNode *child = new TreeNode(
            label, protocol, header_offset, header_length, header_value, output_port
        );

        // Same basic protocol and label, do not duplicate this node
        TreeNode *exists = this->base_lookup(protocol);
        if ( exists && label.equals(protocol) ) {
            delete child;
            return NULL;
        }
        // Same basic protocol, but different label -> add the new one as its child
        else if ( exists ) {
            exists->children.push_back(child);
        }
        // Otherwise, create a new child node at this one
        else {
            this->children.push_back(child);
        }

        return child;
    }

    TreeNode *base_lookup(String protocol) {
        if ( get_protocol().equals(protocol) ) {
            return this;
        }

        for (unsigned short child_no = 0; child_no < this->get_children_nb(); child_no++) {
            TreeNode *child = this->children.at(child_no);
            if ( child->get_protocol().equals(protocol) ) {
                return child;
            }
        }

        // click_chatter("No base match for protocol %s", protocol.c_str());
        return NULL;
    }

    TreeNode *exact_lookup(String label, String protocol) {
        TreeNode *parent = base_lookup(protocol);
        if ( !parent ) {
            click_chatter(
                "No exact match for protocol %s and label %s",
                protocol.c_str(), label.c_str()
            );
            return NULL;
        }

        for (unsigned short child_no = 0; child_no < parent->get_children_nb(); child_no++) {
            TreeNode *child = parent->children.at(child_no);
            if ( child->get_label().equals(label) &&
                 child->get_protocol().equals(protocol) ) {
                return child;
            }
        }

        click_chatter(
            "No exact match for protocol %s and label %s",
            protocol.c_str(), label.c_str()
        );
        return NULL;
    }

    TreeNode *exact_lookup_from_parent(String label, String protocol, TreeNode *parent) {
        if ( !parent ) {
            click_chatter(
                "No exact match for protocol %s and label %s",
                protocol.c_str(), label.c_str()
            );
            return NULL;
        }

        if ( parent->get_label().equals(label) &&
             parent->get_protocol().equals(protocol) ) {
            return parent;
        }

        for (unsigned short child_no = 0; child_no < parent->get_children_nb(); child_no++) {
            TreeNode *child = parent->children.at(child_no);
            if ( child->get_label().equals(label) &&
                 child->get_protocol().equals(protocol) ) {
                return child;
            }
        }

        click_chatter(
            "No exact match for protocol %s and label %s",
            protocol.c_str(), label.c_str()
        );
        return NULL;
    }

    Vector<TreeNode *> fetch_traffic_patterns(String label, String protocol) {
        Vector<TreeNode *> nodes;

        TreeNode *parent = this->base_lookup(protocol);
        if ( !parent ) {
            click_chatter(
                "No traffic patterns for protocol %s and label %s",
                protocol.c_str(), label.c_str()
            );
            return nodes;
        }

        // This parent is a valid classifier
        nodes.push_back(parent);

        // If no node matches your base protocol, then no luck
        if ( parent->get_label().equals(protocol) ) {
            return nodes;
        }

        nodes.push_back(
            this->exact_lookup_from_parent(label, protocol, parent)
        );

        return nodes;
    }

    String header_value_to_str(unsigned short header_value) {
        char buf[5];
        sprintf(buf, "%04x", header_value);
        return String(buf);
    }

    void activate(Vector<String> &traffic_classes) {
        // Check if this node's label exists in the user's configuration
        for ( String tc : traffic_classes ) {
            if ( tc.equals(this->get_label()) ) {
                this->set_active(true);
            }
        }

        // Ensure that inactive elements do not have a valid output port
        if ( !this->get_active() ) {
            this->set_output_port(-1);
        }

        // Visit all the children recursively
        for (unsigned short child_no = 0; child_no < this->get_children_nb(); child_no++) {
            this->children.at(child_no)->activate(traffic_classes);
        }
    }

    void matched_packets_nb(uint64_t &pkt_count) {
        if ( this->get_active() ) {
            pkt_count += this->get_pkt_count();
        }

        for (unsigned short child_no = 0; child_no < this->get_children_nb(); child_no++) {
           this->children.at(child_no)->matched_packets_nb(pkt_count);
        }
    }

    void reset_matched_packets() {
        if ( this->get_active() ) {
            this->set_pkt_count(0);
        }

        for (unsigned short child_no = 0; child_no < this->get_children_nb(); child_no++) {
           this->children.at(child_no)->reset_matched_packets();
        }
    }

    void print_node() {
        click_chatter("============================================");
        click_chatter("          Label: %s",   get_label().c_str());
        click_chatter("       Protocol: %s",   get_protocol().c_str());
        click_chatter("  Header Offset: %d",   get_header_offset());
        click_chatter("   Field Length: %d",   get_header_length());
        click_chatter("          Value: %04x", get_header_value());
        click_chatter("      Value Str: %s",   header_value_to_str(get_header_value()).c_str());
        click_chatter("       Out Port: %d",   get_output_port());
        click_chatter("       Children: %d",   get_children_nb());
        click_chatter("         Active: %s",   get_active() ? "yes":"no");
        click_chatter("Matched packets: %" PRIu64 "", get_pkt_count());
        click_chatter("============================================");
        click_chatter("\n");

        for (unsigned short child_no = 0; child_no < this->get_children_nb(); child_no++) {
           this->children.at(child_no)->print_node();
        }
    }
};

class SimpleEthernetClassifier : public BatchElement {

  public:

    SimpleEthernetClassifier()  CLICK_COLD;
    ~SimpleEthernetClassifier() CLICK_COLD;

    static void static_initialize();
    static void static_cleanup();

    const char *class_name() const    { return "SimpleEthernetClassifier"; }
    const char *port_count() const    { return "1/-"; }
    const char *processing() const    { return PUSH; }
    const char *flags() const         { return ""; }
    bool can_live_reconfigure() const { return true; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    bool is_supported_by_click(int tc_type_idx);
    bool create_patterns(String label, int tc_type_idx, ErrorHandler *errh);
    unsigned short find_offset(String label, unsigned short proto, ErrorHandler *errh);

    TreeNode *add_subclass(
        String label, String protocol, short port_no, ErrorHandler *errh
    );

    int process(int port, Packet *p);

    uint16_t get_dropped_packets();
    uint16_t matched_packets_nb();
    void reset_matched_packets();

#if HAVE_BATCH
    void push_batch(int, PacketBatch *);
#endif
    void push(int, Packet *);

  private:
    bool _verbose;
    bool _has_wildcard;

    uint16_t _dropped_packets;

    /**
     * A shallow classification tree
     */
    TreeNode *_root;

    /**
     * Points to the traffic class that handles wildcards.
     * This traffic class exists only if has_wildcard is true.
     */
    TreeNode *_wilcard;

    /**
     * Keeps a mapping between traffic classes
     * and the classification nodes of the tree
     */
    HashTable<String, HashTable<unsigned short, unsigned short>> *_tc_to_offset;
    HashTable<unsigned short, String>     *_eth_type_to_tc_label;
    HashTable<unsigned short, String>     *_eth_type_to_tc_proto;
    HashTable<unsigned short, TreeNode *> *_eth_type_to_tree_node;
};

CLICK_ENDDECLS

#endif
