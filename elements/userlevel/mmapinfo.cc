// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * mmapinfo.{cc,hh} -- library for interfacing with and configuring packet mmap
 * Georgios Katsikas
 *
 * Copyright (c) 2016 KTH Royal Institute of Technology
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
#include <click/args.hh>
#include "mmapinfo.hh"

CLICK_DECLS

int
MMapInfo::configure(Vector<String> &conf, ErrorHandler *errh) {
	if ( instance ) {
		return errh->error("There can be only one instance of MMapInfo!");
	}

	instance = this;
	if (Args(conf, this, errh)
		.read_p("NB_BLOCKS",  MMapDevice::NB_BLOCKS)
		.read_p("BLOCK_SIZE", MMapDevice::BLOCK_SIZE)
		.read  ("MTU",        MMapDevice::MTU_SIZE)
	.complete() < 0)
	return -1;

	return 0;
}

MMapInfo *MMapInfo::instance = 0;

CLICK_ENDDECLS

EXPORT_ELEMENT(MMapInfo)