/* ieee1275.h - Access the Open Firmware client interface.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_IEEE1275_MACHINE_HEADER
#define GRUB_IEEE1275_MACHINE_HEADER	1

#include <grub/types.h>

#define GRUB_IEEE1275_CELL_SIZEOF 4
typedef grub_uint32_t grub_ieee1275_cell_t;

#define PRIxGRUB_IEEE1275_CELL_T	PRIxGRUB_UINT32_T
#define PRIuGRUB_IEEE1275_CELL_T	PRIuGRUB_UINT32_T

#ifdef __powerpc__

extern grub_int32_t
grub_ieee1275_test (const grub_uint8_t *name, grub_ieee1275_cell_t *missing);

extern grub_int32_t
grub_ieee1275_pks_max_object_size (grub_ieee1275_cell_t *result);

extern grub_int32_t
grub_ieee1275_pks_read_object (const grub_uint8_t consumer, const grub_uint8_t *label,
                               const grub_size_t label_len, const grub_size_t buffer_len,
                               grub_uint8_t *buffer, grub_uint32_t *data_len,
                               grub_uint32_t *policies);

extern grub_int32_t
grub_ieee1275_pks_read_sbvar (const grub_uint8_t sbvar_flags, const grub_uint8_t sbvar_type,
                              const grub_uint32_t buffer_len, grub_uint8_t *buffer,
                              grub_size_t *data_len);
#endif

#endif /* ! GRUB_IEEE1275_MACHINE_HEADER */
