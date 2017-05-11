/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_API_H
#define _HAVE_API_H

#include "types.h"

#define P0F_QUERY_MAGIC      0x50304601
#define P0F_RESP_MAGIC       0x50304602

#define P0F_STATUS_BADQUERY  0x00
#define P0F_STATUS_OK        0x10
#define P0F_STATUS_NOMATCH   0x20

#define P0F_ADDR_IPV4        0x04
#define P0F_ADDR_IPV6        0x06

#define P0F_STR_MAX          31

#define P0F_MATCH_FUZZY      0x01
#define P0F_MATCH_GENERIC    0x02

/* Keep these structures aligned to avoid architecture-specific padding. */

struct p0f_api_query {

  uint32_t magic;                            /* Must be P0F_QUERY_MAGIC            */
  uint8_t  addr_type;                        /* P0F_ADDR_*                         */
  uint8_t  addr[16];                         /* IP address (big endian left align) */

} __attribute__((packed));

struct p0f_api_response {

  uint32_t magic;                            /* Must be P0F_RESP_MAGIC             */
  uint32_t status;                           /* P0F_STATUS_*                       */

  uint32_t first_seen;                       /* First seen (unix time)             */
  uint32_t last_seen;                        /* Last seen (unix time)              */
  uint32_t total_conn;                       /* Total connections seen             */

  uint32_t uptime_min;                       /* Last uptime (minutes)              */
  uint32_t up_mod_days;                      /* Uptime modulo (days)               */

  uint32_t last_nat;                         /* NAT / LB last detected (unix time) */
  uint32_t last_chg;                         /* OS chg last detected (unix time)   */

  int16_t distance;                         /* System distance                    */

  uint8_t  bad_sw;                           /* Host is lying about U-A / Server   */
  uint8_t  os_match_q;                       /* Match quality                      */

  uint8_t  os_name[P0F_STR_MAX + 1];         /* Name of detected OS                */
  uint8_t  os_flavor[P0F_STR_MAX + 1];       /* Flavor of detected OS              */

  uint8_t  http_name[P0F_STR_MAX + 1];       /* Name of detected HTTP app          */
  uint8_t  http_flavor[P0F_STR_MAX + 1];     /* Flavor of detected HTTP app        */

  uint8_t  link_type[P0F_STR_MAX + 1];       /* Link type                          */

  uint8_t  language[P0F_STR_MAX + 1];        /* Language                           */

} __attribute__((packed));

#ifdef _FROM_P0F

void handle_query(struct p0f_api_query* q, struct p0f_api_response* r);

#endif /* _FROM_API */

#endif /* !_HAVE_API_H */
