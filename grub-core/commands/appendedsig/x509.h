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

#ifndef X509_H
#define X509_H

#include <grub/crypto.h>
#include <libtasn1.h>

#define GRUB_MAX_OID_LEN         32

/* RSA public key. */
#define GRUB_MAX_MPI             2
#define GRUB_RSA_PK_MODULUS      0
#define GRUB_RSA_PK_EXPONENT     1

/* Certificate fingerprint. */
#define GRUB_MAX_FINGERPRINT     3
#define GRUB_FINGERPRINT_SHA256  0
#define GRUB_FINGERPRINT_SHA384  1
#define GRUB_FINGERPRINT_SHA512  2

/* Max size of hash data. */
#define GRUB_MAX_HASH_LEN        64

/* Public Key Algorithm. */
struct pk_algo
{
  const char *name;
  const char *oid;
  const grub_int32_t oid_len;
};
typedef struct pk_algo grub_pkalgo_t;

/* Subject Public Key Info. */
struct spk_info
{
  grub_pkalgo_t pk_algo;
  gcry_mpi_t pk[GRUB_MAX_MPI];
  grub_int32_t pk_len;
};
typedef struct spk_info grub_spki_t;

/*
 * One or more x509 certificates. We do limited parsing:
 * extracting only the version, serial, issuer, subject, RSA public key
 * and key size.
 * Also, hold the sha256, sha384, and sha512 fingerprint of the certificate.
 */
struct x509_cert
{
  grub_uint8_t version;
  grub_uint8_t *serial;
  grub_size_t serial_len;
  char *issuer;
  grub_size_t issuer_len;
  char *subject;
  grub_size_t subject_len;
  grub_spki_t spki;
  grub_uint8_t fingerprint[GRUB_MAX_FINGERPRINT][GRUB_MAX_HASH_LEN];
  struct x509_cert *next;
};
typedef struct x509_cert grub_x509_cert_t;

/*
 * Import a DER-encoded certificate at 'data', of size 'size'. Place the results
 * into 'results', which must be already allocated.
 */
extern grub_err_t
grub_x509_cert_parse_der (const void *der_data, grub_int32_t der_data_len, grub_x509_cert_t *cert);

/*
 * Release all the storage associated with the x509 certificate. If the caller
 * dynamically allocated the certificate, it must free it. The caller is also
 * responsible for maintenance of the linked list.
 */
extern void
grub_x509_cert_release (grub_x509_cert_t *cert);

/* Release the allocated memory. */
extern void
grub_x509_cert_free (grub_x509_cert_t *cert);

#endif /* X509_H */
