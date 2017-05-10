/*
   p0f - packet capture and overall host / flow bookkeeping
   --------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_PROCESS_H
#define _HAVE_PROCESS_H

#include <pcap.h>

#include "types.h"
#include "fp_tcp.h"
#include "fp_http.h"

/* Parsed information handed over by the pcap callback: */

struct packet_data {

  uint8_t  ip_ver;                           /* IP_VER4, IP_VER6                   */
  uint8_t  tcp_type;                         /* TCP_SYN, ACK, FIN, RST             */

  uint8_t  src[16];                          /* Source address (left-aligned)      */
  uint8_t  dst[16];                          /* Destination address (left-aligned  */

  uint16_t sport;                            /* Source port                        */
  uint16_t dport;                            /* Destination port                   */

  uint8_t  ttl;                              /* Observed TTL                       */
  uint8_t  tos;                              /* IP ToS value                       */

  uint16_t mss;                              /* Maximum segment size               */
  uint16_t win;                              /* Window size                        */
  uint8_t  wscale;                           /* Window scaling                     */
  uint16_t tot_hdr;                          /* Total headers (for MTU calc)       */

  uint8_t  opt_layout[MAX_TCP_OPT];          /* Ordering of TCP options            */
  uint8_t  opt_cnt;                          /* Count of TCP options               */
  uint8_t  opt_eol_pad;                      /* Amount of padding past EOL         */

  uint32_t ts1;                              /* Own timestamp                      */

  uint32_t quirks;                           /* QUIRK_*                            */

  uint8_t  ip_opt_len;                       /* Length of IP options               */

  uint8_t* payload;                          /* TCP payload                        */
  uint16_t pay_len;                          /* Length of TCP payload              */

  uint32_t seq;                              /* seq value seen                     */

};

/* IP-level quirks: */

#define QUIRK_ECN            0x00000001 /* ECN supported                      */
#define QUIRK_DF             0x00000002 /* DF used (probably PMTUD)           */
#define QUIRK_NZ_ID          0x00000004 /* Non-zero IDs when DF set           */
#define QUIRK_ZERO_ID        0x00000008 /* Zero IDs when DF not set           */
#define QUIRK_NZ_MBZ         0x00000010 /* IP "must be zero" field isn't      */
#define QUIRK_FLOW           0x00000020 /* IPv6 flows used                    */

/* Core TCP quirks: */

#define QUIRK_ZERO_SEQ       0x00001000 /* SEQ is zero                        */
#define QUIRK_NZ_ACK         0x00002000 /* ACK non-zero when ACK flag not set */
#define QUIRK_ZERO_ACK       0x00004000 /* ACK is zero when ACK flag set      */
#define QUIRK_NZ_URG         0x00008000 /* URG non-zero when URG flag not set */
#define QUIRK_URG            0x00010000 /* URG flag set                       */
#define QUIRK_PUSH           0x00020000 /* PUSH flag on a control packet      */

/* TCP option quirks: */

#define QUIRK_OPT_ZERO_TS1   0x01000000 /* Own timestamp set to zero          */
#define QUIRK_OPT_NZ_TS2     0x02000000 /* Peer timestamp non-zero on SYN     */
#define QUIRK_OPT_EOL_NZ     0x04000000 /* Non-zero padding past EOL          */
#define QUIRK_OPT_EXWS       0x08000000 /* Excessive window scaling           */
#define QUIRK_OPT_BAD        0x10000000 /* Problem parsing TCP options        */

/* Host record with persistent fingerprinting data: */

struct host_data {

  struct host_data *prev, *next;        /* Linked lists                       */
  struct host_data *older, *newer;
  uint32_t use_cnt;                          /* Number of packet_flows attached    */

  uint32_t first_seen;                       /* Record created (unix time)         */
  uint32_t last_seen;                        /* Host last seen (unix time)         */
  uint32_t total_conn;                       /* Total number of connections ever   */

  uint8_t ip_ver;                            /* Address type                       */
  uint8_t addr[16];                          /* Host address data                  */

  struct tcp_sig* last_syn;             /* Sig of the most recent SYN         */
  struct tcp_sig* last_synack;          /* Sig of the most recent SYN+ACK     */

  int32_t last_class_id;                    /* OS class ID (-1 = not found)       */
  int32_t last_name_id;                     /* OS name ID (-1 = not found)        */
  uint8_t* last_flavor;                      /* Last OS flavor                     */

  uint8_t  last_quality;                     /* Generic or fuzzy match?            */

  uint8_t* link_type;                        /* MTU-derived link type              */

  uint8_t  cli_scores[NAT_SCORES];           /* Scoreboard for client NAT          */
  uint8_t  srv_scores[NAT_SCORES];           /* Scoreboard for server NAT          */
  uint16_t nat_reasons;                      /* NAT complaints                     */

  uint32_t last_nat;                         /* Last NAT detection time            */
  uint32_t last_chg;                         /* Last OS change detection time      */

  uint16_t last_port;                        /* Source port on last SYN            */

  uint8_t  distance;                         /* Last measured distance             */

  int32_t last_up_min;                      /* Last computed uptime (-1 = none)   */
  uint32_t up_mod_days;                      /* Uptime modulo (days)               */

  /* HTTP business: */

  struct http_sig* http_req_os;         /* Last request, if class != -1       */
  struct http_sig* http_resp;           /* Last response                      */

  int32_t http_name_id;                     /* Client name ID (-1 = not found)    */
  uint8_t* http_flavor;                      /* Client flavor                      */

  uint8_t* language;                         /* Detected language                  */

  uint8_t  bad_sw;                           /* Used dishonest U-A or Server?      */

  uint16_t http_resp_port;                   /* Port on which response seen        */

};

/* Reasons for NAT detection: */

#define NAT_APP_SIG          0x0001     /* App signature <-> OS mismatch      */
#define NAT_OS_SIG           0x0002     /* OS detection mismatch              */
#define NAT_UNK_DIFF         0x0004     /* Current sig unknown, but different */
#define NAT_TO_UNK           0x0008     /* Sig changed from known to unknown  */
#define NAT_TS               0x0010     /* Timestamp goes back                */
#define NAT_PORT             0x0020     /* Source port goes back              */
#define NAT_TTL              0x0040     /* TTL changes unexpectedly           */
#define NAT_FUZZY            0x0080     /* Signature fuzziness changes        */
#define NAT_MSS              0x0100     /* MSS changes                        */

#define NAT_APP_LB           0x0200     /* Server signature changes           */
#define NAT_APP_VIA          0x0400     /* Via / X-Forwarded-For seen         */
#define NAT_APP_DATE         0x0800     /* Date changes in a weird way        */
#define NAT_APP_UA           0x1000     /* User-Agent OS inconsistency        */

/* TCP flow record, maintained until all fingerprinting modules are happy: */

struct packet_flow {

  struct packet_flow *prev, *next;      /* Linked lists                       */
  struct packet_flow *older, *newer;
  uint32_t bucket;                           /* Bucket this flow belongs to        */

  struct host_data* client;             /* Requesting client                  */
  struct host_data* server;             /* Target server                      */

  uint16_t cli_port;                         /* Client port                        */
  uint16_t srv_port;                         /* Server port                        */

  uint8_t  acked;                            /* SYN+ACK received?                  */
  uint8_t  sendsyn;                          /* Created by p0f-sendsyn?            */

  int16_t srv_tps;                          /* Computed TS divisor (-1 = bad)     */ 
  int16_t cli_tps;

  uint8_t* request;                          /* Client-originating data            */
  uint32_t req_len;                          /* Captured data length               */
  uint32_t next_cli_seq;                     /* Next seq on cli -> srv packet      */

  uint8_t* response;                         /* Server-originating data            */
  uint32_t resp_len;                         /* Captured data length               */
  uint32_t next_srv_seq;                     /* Next seq on srv -> cli packet      */
  uint16_t syn_mss;                          /* MSS on SYN packet                  */

  uint32_t created;                          /* Flow creation date (unix time)     */

  /* Application-level fingerprinting: */

  int8_t  in_http;                          /* 0 = tbd, 1 = yes, -1 = no          */

  uint8_t  http_req_done;                    /* Done collecting req headers?       */
  uint32_t http_pos;                         /* Current parsing offset             */
  uint8_t  http_gotresp1;                    /* Got initial line of a response?    */

  struct http_sig http_tmp;             /* Temporary signature                */

};

extern uint64_t packet_cnt;

void parse_packet(void* junk, const struct pcap_pkthdr* hdr, const uint8_t* data);

uint8_t* addr_to_str(uint8_t* data, uint8_t ip_ver);

uint64_t get_unix_time_ms(void);
uint32_t get_unix_time(void);

void add_nat_score(uint8_t to_srv, struct packet_flow* f, uint16_t reason, uint8_t score);
void verify_tool_class(uint8_t to_srv, struct packet_flow* f, uint32_t* sys, uint32_t sys_cnt);

struct host_data* lookup_host(uint8_t* addr, uint8_t ip_ver);

void destroy_all_hosts(void);

#endif /* !_HAVE_PROCESS_H */
