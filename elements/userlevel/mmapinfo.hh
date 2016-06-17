#ifndef CLICK_MMAPINFO_HH
#define CLICK_MMAPINFO_HH

#include <click/element.hh>
#include <click/mmapdevice.hh>

CLICK_DECLS

class MMapInfo : public Element {
	public:
		const char *class_name() const { return "MMapInfo"; }

		int configure_phase() const { return CONFIGURE_PHASE_FIRST; }

		int configure(Vector<String> &conf, ErrorHandler *errh);

		static MMapInfo *instance;
};

CLICK_ENDDECLS

#endif