/* ieee1275.c - Access the Open Firmware client interface.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007,2008,2009  Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2021, 2022, 2023, 2024, 2025 IBM Corporation
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
#include <grub/ieee1275/ieee1275.h>
#include <grub/powerpc/ieee1275/ieee1275.h>
#include <grub/misc.h>

grub_int32_t
grub_ieee1275_test (const grub_uint8_t *name, grub_ieee1275_cell_t *missing)
{
  struct test_args
  {
    struct grub_ieee1275_common_hdr common;/* The header information like interface name, number of inputs and outputs. */
    grub_ieee1275_cell_t name;             /* The interface name. */
    grub_ieee1275_cell_t missing;
  } args;

  INIT_IEEE1275_COMMON (&args.common, "test", 1, 1);
  args.name = (grub_ieee1275_cell_t) name;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.missing == IEEE1275_CELL_INVALID)
    return -1;

  *missing = args.missing;

  return 0;
}

grub_int32_t
grub_ieee1275_pks_max_object_size (grub_ieee1275_cell_t *result)
{
  struct mos_args
  {
    struct grub_ieee1275_common_hdr common;/* The header information like interface name, number of inputs and outputs. */
    grub_ieee1275_cell_t size;             /* The maximum object size for a PKS object. */
  } args;

  INIT_IEEE1275_COMMON (&args.common, "pks-max-object-size", 0, 1);

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.size == IEEE1275_CELL_INVALID)
    return -1;

  *result = args.size;

  return 0;
}

grub_int32_t
grub_ieee1275_pks_read_object (const grub_uint8_t consumer, const grub_uint8_t *label,
                               const grub_size_t label_len, const grub_size_t buffer_len,
                               grub_uint8_t *buffer, grub_uint32_t *data_len,
                               grub_uint32_t *policies)
{
  struct pks_read_args
  {
    struct grub_ieee1275_common_hdr common; /* The header information like interface name, number of inputs and outputs. */
    grub_ieee1275_cell_t consumer;          /* The object belonging to consumer with the label. */
    grub_ieee1275_cell_t label;             /* Object label buffer logical real address. */
    grub_ieee1275_cell_t label_len;         /* The byte length of the object label. */
    grub_ieee1275_cell_t buffer;            /* Output buffer logical real address. */
    grub_ieee1275_cell_t buffer_len;        /* Length of the output buffer. */
    grub_ieee1275_cell_t data_len;          /* The number of bytes copied to the output buffer. */
    grub_ieee1275_cell_t policies;          /* The object policies. */
    grub_int32_t rc;                        /* The return code. */
  } args;

  INIT_IEEE1275_COMMON (&args.common, "pks-read-object", 5, 3);
  args.consumer = (grub_ieee1275_cell_t) consumer;
  args.label = (grub_ieee1275_cell_t) label;
  args.label_len = (grub_ieee1275_cell_t) label_len;
  args.buffer = (grub_ieee1275_cell_t) buffer;
  args.buffer_len = (grub_ieee1275_cell_t) buffer_len;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.data_len == IEEE1275_CELL_INVALID)
    return -1;

  *data_len = args.data_len;
  *policies = args.policies;

  return args.rc;
}

grub_int32_t
grub_ieee1275_pks_read_sbvar (const grub_uint8_t sbvar_flags, const grub_uint8_t sbvar_type,
                              const grub_size_t buffer_len, grub_uint8_t *buffer,
                              grub_size_t *data_len)
{
  struct pks_read_sbvar_args
  {
    struct grub_ieee1275_common_hdr common; /* The header information like interface name, number of inputs and outputs. */
    grub_ieee1275_cell_t sbvar_flags;       /* The sbvar operation flags. */
    grub_ieee1275_cell_t sbvar_type;        /* The sbvar being requested. */
    grub_ieee1275_cell_t buffer;            /* Output buffer logical real address. */
    grub_ieee1275_cell_t buffer_len;        /* Length of the Output buffer. */
    grub_ieee1275_cell_t data_len;          /* The number of bytes copied to the output buffer. */
    grub_int32_t rc;                        /* The return code. */
  } args;

  INIT_IEEE1275_COMMON (&args.common, "pks-read-sbvar", 4, 2);
  args.sbvar_flags = (grub_ieee1275_cell_t) sbvar_flags;
  args.sbvar_type = (grub_ieee1275_cell_t) sbvar_type;
  args.buffer = (grub_ieee1275_cell_t) buffer;
  args.buffer_len = (grub_ieee1275_cell_t) buffer_len;

  if (IEEE1275_CALL_ENTRY_FN (&args) == -1)
    return -1;

  if (args.data_len == IEEE1275_CELL_INVALID)
    return -1;

  *data_len = args.data_len;

  return args.rc;
}
