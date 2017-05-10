/*
   p0f - type definitions and minor macros
   ---------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

#include <stdint.h>

#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

/* Macros for non-aligned memory access. */

#ifdef ALIGN_ACCESS
#  include <string.h>
#  define RD16(_val)  ({ uint16_t _ret; memcpy(&_ret, &(_val), 2); _ret; })
#  define RD32(_val)  ({ uint32_t _ret; memcpy(&_ret, &(_val), 4); _ret; })
#  define RD16p(_ptr) ({ uint16_t _ret; memcpy(&_ret, _ptr, 2); _ret; })
#  define RD32p(_ptr) ({ uint32_t _ret; memcpy(&_ret, _ptr, 4); _ret; })
#else
#  define RD16(_val)  ((uint16_t)_val)
#  define RD32(_val)  ((uint32_t)_val)
#  define RD16p(_ptr) (*((uint16_t*)(_ptr)))
#  define RD32p(_ptr) (*((uint32_t*)(_ptr)))
#endif /* ^ALIGN_ACCESS */

#endif /* ! _HAVE_TYPES_H */
