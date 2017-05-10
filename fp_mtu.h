/*
   p0f - MTU matching
   ------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_MTU_H
#define _HAVE_FP_MTU_H

#include "types.h"

/* Record for a TCP signature read from p0f.fp: */

struct mtu_sig_record {

  uint8_t* name;
  uint16_t mtu;

};

#include "process.h"

struct packet_data;
struct packet_flow;

void mtu_register_sig(uint8_t* name, uint8_t* val, uint32_t line_no);

void fingerprint_mtu(uint8_t to_srv, struct packet_data* pk, struct packet_flow* f);

#endif /* _HAVE_FP_MTU_H */
