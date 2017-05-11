/*
   p0f - TCP/IP packet matching
   ----------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_TCP_H
#define _HAVE_FP_TCP_H

#include "types.h"

/* Simplified data for signature matching and NAT detection: */

struct tcp_sig {

  uint32_t opt_hash;                         /* Hash of opt_layout & opt_cnt       */
  uint32_t quirks;                           /* Quirks                             */

  uint8_t  opt_eol_pad;                      /* Amount of padding past EOL         */
  uint8_t  ip_opt_len;                       /* Length of IP options               */

  int8_t  ip_ver;                           /* -1 = any, IP_VER4, IP_VER6         */

  uint8_t  ttl;                              /* Actual TTL                         */

  int32_t mss;                              /* Maximum segment size (-1 = any)    */
  uint16_t win;                              /* Window size                        */
  uint8_t  win_type;                         /* WIN_TYPE_*                         */
  int16_t wscale;                           /* Window scale (-1 = any)            */

  int8_t  pay_class;                        /* -1 = any, 0 = zero, 1 = non-zero   */

  uint16_t tot_hdr;                          /* Total header length                */
  uint32_t ts1;                              /* Own timestamp                      */
  uint64_t recv_ms;                          /* Packet recv unix time (ms)         */

  /* Information used for matching with p0f.fp: */

  struct tcp_sig_record* matched;       /* NULL = no match                    */
  uint8_t  fuzzy;                            /* Approximate match?                 */
  uint8_t  dist;                             /* Distance                           */

};

/* Methods for matching window size in tcp_sig: */

#define WIN_TYPE_NORMAL      0x00       /* Literal value                      */
#define WIN_TYPE_ANY         0x01       /* Wildcard (p0f.fp sigs only)        */
#define WIN_TYPE_MOD         0x02       /* Modulo check (p0f.fp sigs only)    */
#define WIN_TYPE_MSS         0x03       /* Window size MSS multiplier         */
#define WIN_TYPE_MTU         0x04       /* Window size MTU multiplier         */

/* Record for a TCP signature read from p0f.fp: */

struct tcp_sig_record {

  uint8_t  generic;                          /* Generic entry?                     */
  int32_t class_id;                         /* OS class ID (-1 = user)            */
  int32_t name_id;                          /* OS name ID                         */
  uint8_t* flavor;                           /* Human-readable flavor string       */

  uint32_t label_id;                         /* Signature label ID                 */

  uint32_t* sys;                             /* OS class / name IDs for user apps  */
  uint32_t  sys_cnt;                         /* Length of sys                      */

  uint32_t  line_no;                         /* Line number in p0f.fp              */

  uint8_t  bad_ttl;                          /* TTL is generated randomly          */

  struct tcp_sig* sig;                  /* Actual signature data              */

};

#include "process.h"

struct packet_data;
struct packet_flow;

void tcp_register_sig(uint8_t to_srv, uint8_t generic, int32_t sig_class, uint32_t sig_name,
                      uint8_t* sig_flavor, uint32_t label_id, uint32_t* sys, uint32_t sys_cnt,
                      uint8_t* val, uint32_t line_no);

struct tcp_sig* fingerprint_tcp(uint8_t to_srv, struct packet_data* pk,
                                struct packet_flow* f);

void fingerprint_sendsyn(struct packet_data* pk);

void check_ts_tcp(uint8_t to_srv, struct packet_data* pk, struct packet_flow* f);

#endif /* _HAVE_FP_TCP_H */
