/*
   p0f - main entry point and all the pcap / unix socket innards
   -------------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _GNU_SOURCE
#define _FROM_P0F

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <locale.h>


#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "readfp.h"
#include "api.h"
#include "tcp.h"
#include "fp_http.h"
#include "p0f.h"

uint8_t *log_file;                    /* Binary log file name               */

uint8_t* read_file;                          /* File to read pcap data from        */

uint32_t
  max_conn        = MAX_CONN,           /* Connection entry count limit       */
  max_hosts       = MAX_HOSTS,          /* Host cache entry count limit       */
  conn_max_age    = CONN_MAX_AGE,       /* Maximum age of a connection entry  */
  host_idle_limit = HOST_IDLE_LIMIT;    /* Host cache idle timeout            */

FILE* lf;                        /* Log file stream                    */



uint8_t daemon_mode;                         /* Running in daemon mode?            */

int32_t link_type;                          /* PCAP link type                     */

uint32_t hash_seed;                          /* Hash seed                          */

static uint8_t obs_fields;                   /* No of pending observation fields   */

/* Memory allocator data: */

#ifdef DEBUG_BUILD
struct TRK_obj* TRK[ALLOC_BUCKETS];
uint32_t TRK_cnt[ALLOC_BUCKETS];
#endif /* DEBUG_BUILD */

#define LOGF(...) fprintf(lf, __VA_ARGS__)

/* Open log entry. */

void start_observation(char* keyword, uint8_t field_cnt, uint8_t to_srv,
                       struct packet_flow* f) {

  if (obs_fields) FATAL("Premature end of observation.");

  if (!daemon_mode) {

    SAYF(".-[ %s/%u -> ", addr_to_str(f->client->addr, f->client->ip_ver),
         f->cli_port);
    SAYF("%s/%u (%s) ]-\n|\n", addr_to_str(f->server->addr, f->client->ip_ver),
         f->srv_port, keyword);

    SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server", 
         addr_to_str(to_srv ? f->client->addr :
         f->server->addr, f->client->ip_ver),
         to_srv ? f->cli_port : f->srv_port);

  }

  if (log_file) {

    uint8_t tmp[64];

    time_t ut = get_unix_time();
    struct tm* lt = localtime(&ut);

    strftime((char*)tmp, 64, "%Y/%m/%d %H:%M:%S", lt);

    LOGF("[%s] mod=%s|cli=%s/%u|",tmp, keyword, addr_to_str(f->client->addr,
         f->client->ip_ver), f->cli_port);

    LOGF("srv=%s/%u|subj=%s", addr_to_str(f->server->addr, f->server->ip_ver),
         f->srv_port, to_srv ? "cli" : "srv");

  }

  obs_fields = field_cnt;

}


/* Add log item. */

void add_observation_field(char* key, uint8_t* value) {

  if (!obs_fields) FATAL("Unexpected observation field ('%s').", key);

  if (!daemon_mode)
    SAYF("| %-8s = %s\n", key, value ? value : (uint8_t*)"???");

  if (log_file) LOGF("|%s=%s", key, value ? value : (uint8_t*)"???");

  obs_fields--;

  if (!obs_fields) {

    if (!daemon_mode) SAYF("|\n`----\n\n");

    if (log_file) LOGF("\n");

  }

}



