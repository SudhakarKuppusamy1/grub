/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2022, 2025 IBM Corporation
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

#ifndef PKCS7_H
#define PKCS7_H

#include <grub/crypto.h>
#include "x509.h"

struct sig_algo
{
  const char *name;
  const char *aliases;
  const char *oid;
  const grub_int32_t oid_len;
};
typedef struct sig_algo grub_sigalgo_t;

struct md_algo
{
  const char *name;
  const char *oid;
  const grub_int32_t oid_len;
  const gcry_md_spec_t *hash;
};
typedef struct md_algo grub_mdalgo_t;

/* A PKCS#7 signed data signer info. */
struct pkcs7_signerInfo
{
  grub_mdalgo_t digest_algo;
  grub_sigalgo_t sig_algo;
  gcry_mpi_t signature;
  struct pkcs7_signerInfo *next;
};
typedef struct pkcs7_signerInfo grub_pkcs7_signer_t;

/* A PKCS#7 signed data. */
struct pkcs7_signedData
{
  grub_int32_t version;
  grub_mdalgo_t digest_algo;
  grub_int32_t no_of_signers;
  grub_pkcs7_signer_t *signers;
};
typedef struct pkcs7_signedData grub_pkcs7_signed_data_t;

/* Type for the pkcs7_signed_data_parse_der function.  */
typedef grub_err_t (*grub_pkcs7_parse_t) (const void *der_data, grub_int32_t der_data_len,
                                          grub_pkcs7_signed_data_t *pkcs7_signed_data);

/* Type for the pkcs7_signed_data_release function.  */
typedef void (*grub_pkcs7_release_t) (grub_pkcs7_signed_data_t *pkcs7_signed_data);

/* Type for the pkcs7_signed_data_free function.  */
typedef void (*grub_pkcs7_free_t) (grub_pkcs7_signed_data_t *pkcs7_signed_data);

typedef struct pkcs7_spec
{
  const char *name;
  grub_pkcs7_parse_t parse_der;
  grub_pkcs7_release_t release;
  grub_pkcs7_free_t free;
} grub_pkcs7_spec_t;

extern grub_pkcs7_spec_t *grub_pkcs7_spec;

#endif /* PKCS7_H */
