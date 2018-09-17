/*
   p0f - HTTP fingerprinting
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_HTTP_H
#define _HAVE_FP_HTTP_H

#include "types.h"

/* A structure used for looking up various headers internally in fp_http.c: */

struct http_id {
  char* name;
  uint32_t id;
};

/* Another internal structure for UA -> OS maps: */

struct ua_map_record {
  uint8_t* name;
  uint32_t id;
};

/* HTTP header field: */

struct http_hdr {
  int32_t  id;                              /* Lookup ID (-1 = none)              */
  uint8_t*  name;                            /* Text name (NULL = use lookup ID)   */
  uint8_t*  value;                           /* Value, if any                      */
  uint8_t   optional;                        /* Optional header?                   */
};

/* Request / response signature collected from the wire: */

struct http_sig {

  int8_t  http_ver;                         /* HTTP version (-1 = any)            */

  struct http_hdr hdr[HTTP_MAX_HDRS];   /* Mandatory / discovered headers     */
  uint32_t hdr_cnt;

  uint64_t hdr_bloom4;                       /* Bloom filter for headers           */

  uint32_t miss[HTTP_MAX_HDRS];              /* Missing headers                    */
  uint32_t miss_cnt;

  uint8_t* sw;                               /* Software string (U-A or Server)    */
  uint8_t* lang;                             /* Accept-Language                    */
  uint8_t* via;                              /* Via or X-Forwarded-For             */

  uint32_t date;                             /* Parsed 'Date'                      */
  uint32_t recv_date;                        /* Actual receipt date                */

  /* Information used for matching with p0f.fp: */

  struct http_sig_record* matched;      /* NULL = no match                    */
  uint8_t  dishonest;                        /* "sw" looks forged?                 */

};

/* Record for a HTTP signature read from p0f.fp: */

struct http_sig_record {

  int32_t class_id;                         /* OS class ID (-1 = user)            */
  int32_t name_id;                          /* OS name ID                         */
  uint8_t* flavor;                           /* Human-readable flavor string       */

  uint32_t label_id;                         /* Signature label ID                 */

  uint32_t* sys;                             /* OS class / name IDs for user apps  */
  uint32_t  sys_cnt;                         /* Length of sys                      */

  uint32_t  line_no;                         /* Line number in p0f.fp              */

  uint8_t generic;                           /* Generic signature?                 */

  struct http_sig* sig;                 /* Actual signature data              */

};

/* Register new HTTP signature. */

struct packet_flow;

void http_parse_ua(uint8_t* val, uint32_t line_no);

void http_register_sig(uint8_t to_srv, uint8_t generic, int32_t sig_class, uint32_t sig_name,
                       uint8_t* sig_flavor, uint32_t label_id, uint32_t* sys, uint32_t sys_cnt,
                       uint8_t* val, uint32_t line_no);

uint8_t process_http(uint8_t to_srv, struct packet_flow* f);

void free_sig_hdrs(struct http_sig* h);

void http_init(void);

#endif /* _HAVE_FP_HTTP_H */
