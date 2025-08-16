/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020, 2021, 2022 Free Software Foundation, Inc.
 *  Copyright (C) 2020, 2021, 2022, 2025 IBM Corporation
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

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/command.h>
#include <grub/crypto.h>
#include <grub/i18n.h>
#include <grub/gcrypt/gcrypt.h>
#include <grub/kernel.h>
#include <grub/extcmd.h>
#include <grub/verify.h>
#include <libtasn1.h>
#include <grub/env.h>
#include <grub/lockdown.h>
#include <grub/efi/pks.h>
#include <grub/powerpc/ieee1275/platform_keystore.h>
#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Public key type. */
#define GRUB_PKEY_ID_PKCS7 2

/* Appended signature magic string. */
static const char magic[] = "~Module signature appended~\n";

/*
 * This structure is extracted from scripts/sign-file.c in the linux kernel
 * source. It was licensed as LGPLv2.1+, which is GPLv3+ compatible.
 */
struct module_signature
{
  grub_uint8_t algo;       /* Public-key crypto algorithm [0]. */
  grub_uint8_t hash;       /* Digest algorithm [0]. */
  grub_uint8_t id_type;    /* Key identifier type [GRUB_PKEY_ID_PKCS7]. */
  grub_uint8_t signer_len; /* Length of signer's name [0]. */
  grub_uint8_t key_id_len; /* Length of key identifier [0]. */
  grub_uint8_t __pad[3];
  grub_uint32_t sig_len;   /* Length of signature data. */
} GRUB_PACKED;

/* This represents an entire, parsed, appended signature. */
struct grub_appended_signature
{
  grub_size_t signature_len;            /* Length of PKCS#7 data + metadata + magic. */
  struct module_signature sig_metadata; /* Module signature metadata. */
  struct pkcs7_signedData pkcs7;        /* Parsed PKCS#7 data. */
};

/* This represents a trusted certificates. */
struct grub_database
{
  struct x509_certificate *certs; /* Certificates. */
  grub_uint32_t cert_entries;     /* Number of certificates. */
  grub_uint8_t **signatures;      /* Certificate/binary hashes. */
  grub_size_t *signature_size;    /* Size of certificate/binary hashes. */
  grub_uint32_t signature_entries;/* Number of certificate/binary hashes. */
};

/* The db list is used to validate appended signatures. */
struct grub_database db = {.certs = NULL, .cert_entries = 0, .signatures = NULL,
                           .signature_size = NULL, .signature_entries = 0};

/*
 * The dbx list is used to ensure that the distrusted certificates/kernel binaries are
 * rejected during appended signatures/hashes validation.
 */
struct grub_database dbx = {.certs = NULL, .cert_entries = 0, .signatures = NULL,
                            .signature_size = NULL, .signature_entries = 0};

/* Appended signature size. */
static grub_size_t append_sig_len = 0;

/*
 * Signature verification flag (check_sigs).
 * check_sigs: false
 *  - No signature verification. This is the default.
 * check_sigs: true
 *  - Enforce signature verification, and if signature verification fails,
 *    post the errors and stop the boot.
 */
static bool check_sigs = false;

static void
register_appended_signatures_cmd (void);
static void
unregister_appended_signatures_cmd (void);
static void
free_db_list (void);
static void
build_static_db_list (void);
static void
build_pks_keystore (void);

static const char *
grub_env_read_sec (struct grub_env_var *var __attribute__ ((unused)),
                   const char *val __attribute__ ((unused)))
{
  if (check_sigs == true)
    return "enforce";

  return "no";
}

static char *
grub_env_write_sec (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /*
   * Do not allow the value to be changed If signature verification is
   * (check_sigs is set to enforce) enabled and GRUB is locked down.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    {
      ret = grub_strdup ("enforce");
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string enforce");

      return ret;
    }

  if ((*val == '1') || (*val == 'e'))
    check_sigs = true;
  else if ((*val == '0') || (*val == 'n'))
    check_sigs = false;

  ret = grub_strdup (grub_env_read_sec (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not duplicate a string %s",
                grub_env_read_sec (NULL, NULL));

  return ret;
}

static const char *
grub_env_read_key_mgmt (struct grub_env_var *var __attribute__ ((unused)),
                        const char *val __attribute__ ((unused)))
{
  if (grub_pks_use_keystore == true)
    return "dynamic";

  return "static";
}

static char *
grub_env_write_key_mgmt (struct grub_env_var *var __attribute__ ((unused)), const char *val)
{
  char *ret;

  /*
   * Do not allow the value to be changed if check_sigs is set to enforce and
   * GRUB is locked down.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    {
      ret = grub_strdup (grub_env_read_key_mgmt (NULL, NULL));
      if (ret == NULL)
        grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

      return ret;
    }

  if ((*val == '1') || (*val == 'd'))
    {
      /*
       * If dynamic key management is disabled and PKS support is available,
       * load the PKS.
       */
      if (grub_pks_is_support_pks == true && grub_pks_use_keystore == false)
        build_pks_keystore ();

      grub_pks_use_keystore = true;
    }
  else if ((*val == '0') || (*val == 's'))
    grub_pks_use_keystore = false;

  ret = grub_strdup (grub_env_read_key_mgmt (NULL, NULL));
  if (ret == NULL)
    grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  return ret;
}

/*
 * GUID can be used to determine the hashing function and
 * generate the hash using determined hashing function.
 */
static grub_err_t
get_hash (const grub_packed_guid_t *guid, const grub_uint8_t *data, const grub_size_t data_size,
          grub_uint8_t *hash, grub_size_t *hash_size)
{
  gcry_md_spec_t *hash_func = NULL;

  if (guid == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "GUID is not available");

  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha256;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha384;
  else if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
           grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    hash_func = &_gcry_digest_spec_sha512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "unsupported GUID hash");

  grub_memset (hash, 0, GRUB_MAX_HASH_SIZE);
  grub_crypto_hash (hash_func, hash, data, data_size);
  *hash_size =  hash_func->mdlen;

  return GRUB_ERR_NONE;
}

/* Add the certificate/binary hash into the db/dbx list. */
static grub_err_t
add_hash (grub_uint8_t *const data, const grub_size_t data_size,
          grub_uint8_t ***signature_list, grub_size_t **signature_size_list,
          grub_uint32_t *signature_list_entries)
{
  grub_uint8_t **signatures;
  grub_size_t *signature_size;
  grub_uint32_t signature_entries = *signature_list_entries;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate/binary-hash data or size is not available");

  signatures = grub_realloc (*signature_list, sizeof (grub_uint8_t *) * (signature_entries + 1));
  if (signatures == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  signature_size = grub_realloc (*signature_size_list,
                                 sizeof (grub_size_t) * (signature_entries + 1));
  if (signature_size == NULL)
    {
      /*
       * Allocated memory will be freed by
       * free_db_list/free_dbx_list.
       */
      signatures[signature_entries + 1] = NULL;
      *signature_list = signatures;
      *signature_list_entries = signature_entries + 1;

      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
    }

  signatures[signature_entries] = grub_malloc (data_size);
  if (signatures[signature_entries] != NULL)
    grub_memcpy (signatures[signature_entries], data, data_size);

  signature_size[signature_entries] = data_size;
  signature_entries++;

  if (signatures[signature_entries] == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  *signature_list = signatures;
  *signature_size_list = signature_size;
  *signature_list_entries = signature_entries;

  return GRUB_ERR_NONE;
}

static bool
is_x509 (const grub_packed_guid_t *guid)
{
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  return false;
}

static bool
is_cert_match (const struct x509_certificate *distrusted_cert,
               const struct x509_certificate *db_cert)
{
  if (grub_memcmp (distrusted_cert->subject, db_cert->subject, db_cert->subject_len) == 0
      && grub_memcmp (distrusted_cert->issuer, db_cert->issuer, db_cert->issuer_len) == 0
      && grub_memcmp (distrusted_cert->serial, db_cert->serial, db_cert->serial_len) == 0
      && grub_memcmp (distrusted_cert->mpis[0], db_cert->mpis[0], sizeof (db_cert->mpis[0])) == 0
      && grub_memcmp (distrusted_cert->mpis[1], db_cert->mpis[1], sizeof (db_cert->mpis[1])) == 0)
    return true;

  return false;
}

/* Check the certificate presence in the Platform Keystore dbx list. */
static grub_err_t
is_dbx_cert (const struct x509_certificate *db_cert)
{
  grub_err_t rc;
  grub_uint32_t i;
  struct x509_certificate *distrusted_cert;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL)
        continue;

      if (is_x509 (&grub_pks_keystore.dbx[i].guid) == true)
        {
          distrusted_cert = grub_zalloc (sizeof (struct x509_certificate));
          if (distrusted_cert == NULL)
            return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

          rc = parse_x509_certificate (grub_pks_keystore.dbx[i].data,
                                       grub_pks_keystore.dbx[i].data_size, distrusted_cert);
          if (rc != GRUB_ERR_NONE)
            {
              grub_free (distrusted_cert);
              continue;
            }

          if (is_cert_match (distrusted_cert, db_cert) == true)
            {
              grub_dprintf ("appendedsig", "a certificate CN='%s' is ignored "
                            "because it is on the dbx list\n", db_cert->subject);
              return GRUB_ERR_ACCESS_DENIED;
            }

          certificate_release (distrusted_cert);
          grub_free (distrusted_cert);
        }
    }

  return GRUB_ERR_NONE;
}

/* Add the certificate into the db/dbx list */
static grub_err_t
add_certificate (const grub_uint8_t *data, const grub_size_t data_size,
                 struct grub_database *database, const bool is_db)
{
  struct x509_certificate *cert;
  grub_err_t rc;
  grub_uint32_t cert_entries = database->cert_entries;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = parse_x509_certificate (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot add a certificate CN='%s' to %s\n",
                    cert->subject, ((is_db == true) ? "db" : "dbx"));
      grub_free (cert);
      return rc;
    }

  if (is_db == true)
    {
      rc = is_dbx_cert (cert);
      if (rc != GRUB_ERR_NONE)
        {
          certificate_release (cert);
          grub_free (cert);
          return rc;
        }
    }

  grub_dprintf ("appendedsig", "add a certificate CN='%s' to %s", cert->subject,
                ((is_db == true) ? "db" : "dbx"));

  cert_entries++;
  cert->next = database->certs;
  database->certs = cert;
  database->cert_entries = cert_entries;

  return rc;
}

static grub_err_t
file_read_whole (grub_file_t file, grub_uint8_t **buf, grub_size_t *len)
{
  grub_off_t full_file_size;
  grub_size_t file_size, total_read_size = 0;
  grub_ssize_t read_size;

  full_file_size = grub_file_size (file);
  if (full_file_size == GRUB_FILE_SIZE_UNKNOWN)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "cannot read a file of unknown size into a buffer");

  if (full_file_size > GRUB_SIZE_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "file is too large to read: %" PRIuGRUB_UINT64_T " bytes",
                       full_file_size);

  file_size = (grub_size_t) full_file_size;
  *buf = grub_malloc (file_size);
  if (*buf == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate file data buffer size %" PRIuGRUB_SIZE,
                       file_size);

  while (total_read_size < file_size)
    {
      read_size = grub_file_read (file, *buf + total_read_size, file_size - total_read_size);
      if (read_size < 0)
        {
          grub_free (*buf);
          return grub_errno;
        }
      else if (read_size == 0)
        {
          grub_free (*buf);
          return grub_error (GRUB_ERR_IO,
                             "could not read full file size "
                             "(%" PRIuGRUB_SIZE "), only %" PRIuGRUB_SIZE " bytes read",
                             file_size, total_read_size);
        }

      total_read_size += read_size;
    }

  *len = file_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
extract_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize,
                            struct grub_appended_signature *sig)
{
  grub_size_t pkcs7_size;
  grub_size_t remaining_len;
  const grub_uint8_t *appsigdata = buf + bufsize - grub_strlen (magic);

  if (bufsize < grub_strlen (magic))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature magic");

  if (grub_strncmp ((const char *) appsigdata, magic, sizeof (magic) - 1))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "missing or invalid signature magic");

  remaining_len = bufsize - grub_strlen (magic);

  if (remaining_len < sizeof (struct module_signature))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature metadata");

  appsigdata -= sizeof (struct module_signature);
  /* Extract the metadata. */
  grub_memcpy (&(sig->sig_metadata), appsigdata, sizeof (struct module_signature));
  remaining_len -= sizeof (struct module_signature);

  if (sig->sig_metadata.id_type != GRUB_PKEY_ID_PKCS7)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "wrong signature type");

  pkcs7_size = grub_be_to_cpu32 (sig->sig_metadata.sig_len);

  if (pkcs7_size > remaining_len)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for PKCS#7 message");

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", pkcs7_size);

  sig->signature_len = grub_strlen (magic) + sizeof (struct module_signature) + pkcs7_size;
  /* Rewind pointer and parse pkcs7 data. */
  appsigdata -= pkcs7_size;

  return parse_pkcs7_signedData (appsigdata, pkcs7_size, &sig->pkcs7);
}

/*
 * Given a hash value 'hval', of hash specification 'hash', prepare
 * the S-expressions (sexp) and perform the signature verification.
 */
static grub_err_t
verify_signature (const gcry_mpi_t *pkmpi, const gcry_mpi_t hmpi,
                  const gcry_md_spec_t *hash, const grub_uint8_t *hval)
{
  gcry_sexp_t hsexp, pubkey, sig;
  grub_size_t errof;

  if (_gcry_sexp_build(&hsexp, &errof, "(data (flags %s) (hash %s %b))", "pkcs1",
                       hash->name, hash->mdlen, hval) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  if (_gcry_sexp_build(&pubkey, &errof, "(public-key (dsa (n %M) (e %M)))",
                       pkmpi[0], pkmpi[1]) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  if (_gcry_sexp_build(&sig, &errof, "(sig-val (rsa (s %M)))", hmpi) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  _gcry_sexp_dump(sig);
  _gcry_sexp_dump(hsexp);
  _gcry_sexp_dump(pubkey);

  if (grub_crypto_pk_rsa->verify (sig, hsexp, pubkey) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_verify_appended_signature (const grub_uint8_t *buf, grub_size_t bufsize)
{
  grub_err_t err;
  grub_size_t datasize;
  void *context;
  unsigned char *hash;
  struct x509_certificate *pk;
  struct grub_appended_signature sig;
  struct pkcs7_signerInfo *si;
  grub_uint32_t i;

  if (!db.cert_entries)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "no trusted keys to verify against");

  err = extract_appended_signature (buf, bufsize, &sig);
  if (err != GRUB_ERR_NONE)
    return err;

  append_sig_len = sig.signature_len;
  datasize = bufsize - sig.signature_len;

  /* Verify signature using trusted keys from db list. */
  for (i = 0; i < sig.pkcs7.signerInfo_count; i++)
    {
      /*
       * This could be optimised in a couple of ways:
       * - we could only compute hashes once per hash type.
       * - we could track signer information and only verify where IDs match.
       * For now we do the naive O(trusted keys * pkcs7 signers) approach.
       */
      si = &sig.pkcs7.signerInfos[i];
      context = grub_zalloc (si->hash->contextsize);
      if (context == NULL)
        return grub_errno;

      si->hash->init (context, 0);
      si->hash->write (context, buf, datasize);
      si->hash->final (context);
      hash = si->hash->read (context);

      grub_dprintf ("appendedsig", "data size %" PRIuGRUB_SIZE ", signer %d hash %02x%02x%02x%02x...\n",
                    datasize, i, hash[0], hash[1], hash[2], hash[3]);

      for (pk = db.certs; pk != NULL; pk = pk->next)
        {
          err = verify_signature (pk->mpis, si->sig_mpi, si->hash, hash);
          if (err == GRUB_ERR_NONE)
            {
              grub_dprintf ("appendedsig", "verify signer %d with key '%s' succeeded\n",
                            i, pk->subject);
              break;
            }

          grub_dprintf ("appendedsig", "verify signer %d with key '%s' failed\n",
                        i, pk->subject);
        }

      grub_free (context);
      if (err == GRUB_ERR_NONE)
        break;
    }

  pkcs7_signedData_release (&sig.pkcs7);

  if (err != GRUB_ERR_NONE)
    return grub_error (err, "failed to verify signature against a trusted key");

  return err;
}

static grub_err_t
read_cert_from_file (grub_file_t cert_file, struct x509_certificate **cert)
{
  grub_err_t err;
  grub_uint8_t *buf = NULL;
  grub_size_t buf_size = 0;

  *cert = grub_zalloc (sizeof (struct x509_certificate));
  if (*cert == NULL)
      return grub_error (GRUB_ERR_OUT_OF_MEMORY, "could not allocate memory for certificate");

  err = file_read_whole (cert_file, &buf, &buf_size);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * If signature verification is enabled and GRUB is locked down,
   * obtain the actual certificate size by subtracting the appended
   * signature size from the certificate size because
   * the certificate has an appended signature, and this actual certificate size is
   * used to get the X.509 certificate.
   */
  if (check_sigs == true && grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    buf_size -= append_sig_len;

  err = parse_x509_certificate (buf, buf_size, *cert);
  grub_free (buf);

  return err;
}

static bool
is_cert_present_in_db (const struct x509_certificate *cert_in)
{
  struct x509_certificate *cert;

  for (cert = db.certs; cert != NULL; cert = cert->next)
    if (is_cert_match (cert, cert_in) == true)
      return true;

  return false;
}

static void
remove_cert_from_db (const struct x509_certificate *cert)
{
  grub_uint32_t i = 1;
  struct x509_certificate *curr_cert, *prev_cert;

  for (curr_cert = prev_cert = db.certs; curr_cert != NULL; curr_cert = curr_cert->next, i++)
    {
      if (is_cert_match (curr_cert, cert) == true)
        {
          if (i == 1) /* Match with first certificate in the db list. */
            db.certs = curr_cert->next;
          else
            prev_cert->next = curr_cert->next;

          grub_dprintf ("appendedsig",
                        "removed distrusted certificate with CN: %s from the db list\n", curr_cert->subject);
          curr_cert->next = NULL;
          certificate_release (curr_cert);
          grub_free (curr_cert);
          break;
	}
      else
        prev_cert = curr_cert;
    }
}

static grub_err_t
grub_cmd_verify_signature (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t signed_file;
  grub_err_t err;
  grub_uint8_t *signed_data = NULL;
  grub_size_t signed_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a signed file is expected\nExample:\n\tappend_verify <SIGNED FILE>\n");

  if (*args == NULL)
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing signed file");

  grub_dprintf ("appendedsig", "verifying %s\n", args[0]);

  signed_file = grub_file_open (args[0], GRUB_FILE_TYPE_VERIFY_SIGNATURE);
  if (signed_file == NULL)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND, "could not open %s file", args[0]);

  err = file_read_whole (signed_file, &signed_data, &signed_data_size);
  if (err == GRUB_ERR_NONE)
    err = grub_verify_appended_signature (signed_data, signed_data_size);

  grub_file_close (signed_file);
  grub_free (signed_data);

  return err;
}

/*
 * Add the trusted certificate to the db list if it is not already present.
 * Note:- When signature verification is enabled, this command only accepts the
 * trusted certificate that is signed with an appended signature.
 * The signature is verified by the appendedsig module. If verification succeeds,
 * the certificate is added to the db list. Otherwise, an error is posted and
 * the certificate is not added.
 * When signature verification is disabled, it accepts the trusted certificate without
 * an appended signature and add it to the db list.
 *
 * Also, note that the adding of the trusted certificate using this command does
 * not persist across reboots.
 */
static grub_err_t
grub_cmd_db_cert (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_err_t err;
  grub_file_t cert_file;
  struct x509_certificate *cert = NULL;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a trusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_add_db_cert <X509_CERTIFICATE>\n");

  if (*args == NULL)
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing trusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = read_cert_from_file (cert_file, &cert);
  grub_file_close (cert_file);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (cert);
      return err;
    }

  if (is_cert_present_in_db (cert) == true)
    {
      certificate_release (cert);
      grub_free (cert);
      return grub_error (GRUB_ERR_EXISTS,
                         "could not add the certificate, as it is present in the db list");
    }

  grub_dprintf ("appendedsig", "added certificate with CN: %s\n", cert->subject);

  cert->next = db.certs;
  db.certs = cert;
  db.cert_entries++;

  return GRUB_ERR_NONE;
}

/*
 * Remove the distrusted certificate from the db list if it is already present.
 * Note:- When signature verification is enabled, this command only accepts the
 * distrusted certificate that is signed with an appended signature.
 * The signature is verified by the appended sig module. If verification succeeds,
 * the certificate is removed from the db list. Otherwise, an error is posted and
 * the certificate is not removed.
 * When signature verification is disabled, it accepts the distrusted certificate
 * without an appended signature and removes it from the db list.
 *
 * Also, note that the removal of the distrusted certificate using this command
 * does not persist across reboots.
 */
static grub_err_t
grub_cmd_dbx_cert (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_err_t err;
  grub_file_t cert_file;
  struct x509_certificate *cert = NULL;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a distrusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_rm_dbx_cert <X509_CERTIFICATE>\n");

  if (*args == NULL)
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing distrusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = read_cert_from_file (cert_file, &cert);
  grub_file_close (cert_file);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (cert);
      return err;
    }

  /* Remove distrusted certificate from the db list if present. */
  remove_cert_from_db (cert);
  certificate_release (cert);
  grub_free (cert);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_list_db (grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)),
                  char **args __attribute__ ((unused)))
{
  struct x509_certificate *cert;
  grub_uint32_t i, cert_num = 1;

  for (cert = db.certs; cert != NULL; cert = cert->next, cert_num++)
    {
      grub_printf ("Certificate %u:\n", cert_num);
      grub_printf ("\tSerial: ");

      for (i = 0; i < cert->serial_len - 1; i++)
        grub_printf ("%02x:", cert->serial[i]);

      grub_printf ("%02x\n", cert->serial[cert->serial_len - 1]);
      grub_printf ("\tissuer: %s\n", cert->issuer);
      grub_printf ("\tCN: %s\n\n", cert->subject);
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
appendedsig_init (grub_file_t io __attribute__ ((unused)), enum grub_file_type type,
                  void **context __attribute__ ((unused)), enum grub_verify_flags *flags)
{
  if (check_sigs == false)
    {
      *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
      return GRUB_ERR_NONE;
    }

  switch (type & GRUB_FILE_TYPE_MASK)
    {
      case GRUB_FILE_TYPE_CERTIFICATE_TRUST:
        /*
         * This is a certificate to add to trusted keychain.
         *
         * This needs to be verified or blocked. Ideally we'd write an x509
         * verifier, but we lack the hubris required to take this on. Instead,
         * require that it have an appended signature.
         */
      case GRUB_FILE_TYPE_LINUX_KERNEL:
      case GRUB_FILE_TYPE_GRUB_MODULE:
        /*
         * Appended signatures are only defined for ELF binaries.
         * Out of an abundance of caution, we only verify Linux kernels
         * and GRUB modules at this point.
         */
        *flags = GRUB_VERIFY_FLAGS_SINGLE_CHUNK;
        return GRUB_ERR_NONE;

      case GRUB_FILE_TYPE_ACPI_TABLE:
      case GRUB_FILE_TYPE_DEVICE_TREE_IMAGE:
        /*
         * It is possible to use appended signature verification without
         * lockdown - like the PGP verifier. When combined with an embedded
         * config file in a signed GRUB binary, this could still be a meaningful
         * secure-boot chain - so long as it isn't subverted by something like a
         * rouge ACPI table or DT image. Defer them explicitly.
         */
        *flags = GRUB_VERIFY_FLAGS_DEFER_AUTH;
        return GRUB_ERR_NONE;

      default:
        *flags = GRUB_VERIFY_FLAGS_SKIP_VERIFICATION;
        return GRUB_ERR_NONE;
    }
}

static grub_err_t
appendedsig_write (void *ctxt __attribute__ ((unused)), void *buf, grub_size_t size)
{
  return grub_verify_appended_signature (buf, size);
}

struct grub_file_verifier grub_appendedsig_verifier = {
  .name = "appendedsig",
  .init = appendedsig_init,
  .write = appendedsig_write,
};

static grub_ssize_t
pseudo_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_memcpy (buf, (grub_uint8_t *) file->data + file->offset, len);
  return len;
}

/* Filesystem descriptor. */
static struct grub_fs pseudo_fs = {
  .name = "pseudo",
  .fs_read = pseudo_read
};

static grub_command_t cmd_verify, cmd_list_db, cmd_dbx_cert, cmd_db_cert;

/* Check the certificate hash presence in the PKS dbx list. */
static bool
is_dbx_cert_hash (grub_uint8_t *const data, const grub_size_t data_size)
{
  grub_err_t rc;
  grub_uint32_t i;
  grub_size_t cert_hash_size = 0;
  grub_uint8_t cert_hash[GRUB_MAX_HASH_SIZE] = { 0 };

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL ||
          grub_pks_keystore.dbx[i].data_size == 0)
        continue;

      rc = get_hash (&grub_pks_keystore.dbx[i].guid, data, data_size,
                     cert_hash, &cert_hash_size);
      if (rc != GRUB_ERR_NONE)
        continue;

      if (cert_hash_size == grub_pks_keystore.dbx[i].data_size &&
          grub_memcmp (grub_pks_keystore.dbx[i].data, cert_hash, cert_hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "a certificate (%02x%02x%02x%02x) is ignored "
                        "because this certificate hash is on the dbx list\n",
                        cert_hash[0], cert_hash[1], cert_hash[2], cert_hash[3]);
          return true;
        }
    }

  return false;
}

/* Check the binary hash presence in the PKS dbx list. */
static bool
is_dbx_binary_hash (grub_uint8_t *const binary_hash, const grub_size_t binary_hash_size)
{
  grub_uint32_t i;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (grub_pks_keystore.dbx[i].data == NULL ||
          grub_pks_keystore.dbx[i].data_size == 0)
        continue;

      if (binary_hash_size == grub_pks_keystore.dbx[i].data_size &&
          grub_memcmp (grub_pks_keystore.dbx[i].data, binary_hash, binary_hash_size) == 0)
        {
          grub_dprintf ("appendedsig", "a binary hash (%02x%02x%02x%02x) is ignored"
                        " because it is on the dbx list\n", binary_hash[0], binary_hash[1],
                        binary_hash[2], binary_hash[3]);
          return true;
        }
    }

  return false;
}

/* Add the binary hash to the db list if it does not exist in the PKS dbx list. */
static grub_err_t
add_db_binary_hash (grub_uint8_t *const data, const grub_size_t data_size)
{
  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "binary hash data or size is not available");

  if (is_dbx_binary_hash (data, data_size) == false)
    return add_hash (data, data_size, &db.signatures, &db.signature_size,
                     &db.signature_entries);

  return GRUB_ERR_BAD_SIGNATURE;
}

static bool
is_hash (const grub_packed_guid_t *guid)
{
  /* GUID type of the binary hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  /* GUID type of the certificate hash. */
  if (grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA256_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA384_GUID, GRUB_PACKED_GUID_SIZE) == 0 ||
      grub_memcmp (guid, &GRUB_PKS_CERT_X509_SHA512_GUID, GRUB_PACKED_GUID_SIZE) == 0)
    return true;

  return false;
}

/* Add the X.509 certificates/binary hash to the db list from PKS. */
static grub_err_t
create_db_list (void)
{
  grub_err_t rc;
  grub_uint32_t i;

  for (i = 0; i < grub_pks_keystore.db_entries; i++)
    {
      if (is_hash (&grub_pks_keystore.db[i].guid) == true)
        {
          rc = add_db_binary_hash (grub_pks_keystore.db[i].data,
                                   grub_pks_keystore.db[i].data_size);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_x509 (&grub_pks_keystore.db[i].guid) == true)
        {
          if (is_dbx_cert_hash (grub_pks_keystore.db[i].data,
                                grub_pks_keystore.db[i].data_size) == true)
            continue;

          rc = add_certificate (grub_pks_keystore.db[i].data,
                                grub_pks_keystore.db[i].data_size, &db, true);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%u)\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/* Add the certificates and certificate/binary hash to the dbx list from PKS. */
static grub_err_t
create_dbx_list (void)
{
  grub_err_t rc;
  grub_uint32_t i;

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    {
      if (is_x509 (&grub_pks_keystore.dbx[i].guid) == true)
        {
          rc = add_certificate (grub_pks_keystore.dbx[i].data,
                                grub_pks_keystore.dbx[i].data_size, &dbx, false);
          if (rc == GRUB_ERR_OUT_OF_MEMORY)
            return rc;
        }
      else if (is_hash (&grub_pks_keystore.dbx[i].guid) == true)
        {
          rc = add_hash (grub_pks_keystore.dbx[i].data,
                         grub_pks_keystore.dbx[i].data_size, &dbx.signatures,
                         &dbx.signature_size, &dbx.signature_entries);
          if (rc != GRUB_ERR_NONE)
            return rc;
        }
      else
        grub_dprintf ("appendedsig", "unsupported signature data type and "
                      "skipped (%u)\n", i + 1);
    }

  return GRUB_ERR_NONE;
}

/* Free db list memory */
static void
free_db_list (void)
{
  struct x509_certificate *cert;
  grub_uint32_t i;

  while (db.certs != NULL)
    {
      cert = db.certs;
      db.certs = db.certs->next;
      certificate_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < db.signature_entries; i++)
    grub_free (db.signatures[i]);

  grub_free (db.signatures);
  grub_free (db.signature_size);
  grub_memset (&db, 0, sizeof (struct grub_database));
}

/* Free dbx list memory */
static void
free_dbx_list (void)
{
  struct x509_certificate *cert;
  grub_uint32_t i;

  while (dbx.certs != NULL)
    {
      cert = dbx.certs;
      dbx.certs = dbx.certs->next;
      certificate_release (cert);
      grub_free (cert);
    }

  for (i = 0; i < dbx.signature_entries; i++)
    grub_free (dbx.signatures[i]);

  grub_free (dbx.signatures);
  grub_free (dbx.signature_size);
  grub_memset (&dbx, 0, sizeof (struct grub_database));
}

/*
 * Extract the X.509 certificates from the ELF Note header,
 * parse it, and add it to the db list.
 */
static void
build_static_db_list (void)
{
  grub_err_t err;
  struct grub_module_header *header;
  struct grub_file pseudo_file;
  struct x509_certificate *cert;

  FOR_MODULES (header)
    {
      /* Not an X.509 certificate, skip. */
      if (header->type != OBJ_TYPE_X509_PUBKEY)
        continue;

      grub_memset (&pseudo_file, 0, sizeof (pseudo_file));
      pseudo_file.fs = &pseudo_fs;
      pseudo_file.size = header->size - sizeof (struct grub_module_header);
      pseudo_file.data = (char *) header + sizeof (struct grub_module_header);

      grub_dprintf ("appendedsig", "found an X.509 certificate, size=%" PRIuGRUB_UINT64_T "\n",
                    pseudo_file.size);

      err = read_cert_from_file (&pseudo_file, &cert);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
      else if (err != GRUB_ERR_NONE)
        {
          grub_dprintf ("appendedsig",
                        "warning: cannot add a certificate %u to the db list\n",
                        db.cert_entries + 1);
          continue;
        }

      grub_dprintf ("appendedsig", "add a certificate CN='%s' to db\n", cert->subject);

      cert->next = db.certs;
      db.certs = cert;
      db.cert_entries++;
    }
}

/*
 * Extract trusted and distrusted keys from PKS and store them in
 * the db and dbx list.
 */
static void
build_pks_keystore (void)
{
  grub_err_t err;

  err = create_db_list ();
  if (err != GRUB_ERR_NONE)
    grub_printf ("warning: db list might not be fully populated\n");

  err = create_dbx_list ();
  if (err != GRUB_ERR_NONE)
    grub_printf ("warning: dbx list might not be fully populated\n");

  grub_pks_free_keystore ();
  grub_dprintf ("appendedsig", "the db list now has %u keys\n"
                "the dbx list now has %u keys\n",
                db.signature_entries + db.cert_entries,
                dbx.signature_entries + dbx.cert_entries);
}

/* It registers the appended signatures GRUB commands. */
static void
register_appended_signatures_cmd (void)
{
  cmd_verify = grub_register_command ("append_verify", grub_cmd_verify_signature, N_("SIGNED_FILE"),
                                      N_("Verify SIGNED_FILE against the trusted X.509 certificates in the db list"));
  cmd_list_db = grub_register_command ("append_list_db", grub_cmd_list_db, 0,
                                       N_("Show the list of trusted X.509 certificates from the db list"));
  cmd_db_cert = grub_register_command ("append_add_db_cert", grub_cmd_db_cert, N_("X509_CERTIFICATE"),
                                       N_("Add trusted X509_CERTIFICATE to the db list"));
  cmd_dbx_cert = grub_register_command ("append_rm_dbx_cert", grub_cmd_dbx_cert, N_("X509_CERTIFICATE"),
                                        N_("Remove distrusted X509_CERTIFICATE from the db list"));
}

/* It unregisters the appended signatures GRUB commands. */
static void
unregister_appended_signatures_cmd (void)
{
  grub_unregister_command (cmd_verify);
  grub_unregister_command (cmd_list_db);
  grub_unregister_command (cmd_db_cert);
  grub_unregister_command (cmd_dbx_cert);
}

GRUB_MOD_INIT (appendedsig)
{
  grub_int32_t rc;

  /*
   * If secure boot is enabled with enforced mode and GRUB is locked down,
   * enable signature verification.
   */
  if (grub_is_lockdown () == GRUB_LOCKDOWN_ENABLED)
    check_sigs = true;

  /*
   * This is appended signature verification environment variable.
   * It is automatically set to "no" or "enforce" based on the
   * ’ibm,secure-boot’ device tree property.
   *
   * "no": No signature verification. This is the default.
   *
   * "enforce": Enforce signature verification. When GRUB is locked down,
   *            user cannot change the value by setting the check_appended_signatures
   *            variable back to ‘no’
   */
  grub_register_variable_hook ("check_appended_signatures", grub_env_read_sec, grub_env_write_sec);
  grub_env_export ("check_appended_signatures");
  /*
   * This is appended signature key management environment variable.
   * It is automatically set to "static" or "dynamic" based on the
   * ’ibm,secure-boot’ device tree property and Platform KeyStore
   * (grub_pks_use_keystore).
   *
   * "static": Enforce static key management signature verification.
   *           This is the default. When the GRUB is locked down,
   *           user cannot change the value by setting the
   *           appendedsig_key_mgmt variable back to "dynamic".
   *
   * "dynamic": Enforce dynamic key management signature verification.
   *            When the GRUB is locked down, user cannot change the value
   *            by setting the appendedsig_key_mgmt variable back to "static".
   */
  grub_register_variable_hook ("appendedsig_key_mgmt", grub_env_read_key_mgmt,
                               grub_env_write_key_mgmt);
  grub_env_export ("appendedsig_key_mgmt");

  rc = asn1_init ();
  if (rc != ASN1_SUCCESS)
    grub_fatal ("error initing ASN.1 data structures: %d: %s\n", rc, asn1_strerror (rc));

  /*
   * If signature verification is enabled with the static key management,
   * extract trusted keys from ELF Note and store them in the db list.
   */
  if (grub_pks_use_keystore == false)
    {
      build_static_db_list ();
      grub_dprintf ("appendedsig", "the db list now has %u static keys\n",
                    db.cert_entries);
    }
  /*
   * If signature verification is enabled with the dynamic key management,
   * load the Platform KeyStore(PKS).
   */
  else if (grub_pks_use_keystore == true)
    build_pks_keystore ();

  register_appended_signatures_cmd ();
  grub_verifier_register (&grub_appendedsig_verifier);
  grub_dl_set_persistent (mod);
}

GRUB_MOD_FINI (appendedsig)
{
  /*
   * grub_dl_set_persistent should prevent this from actually running, but
   * it does still run under emu.
   */

  free_db_list ();
  free_dbx_list ();
  grub_register_variable_hook ("check_appended_signatures", NULL, NULL);
  grub_env_unset ("check_appended_signatures");
  grub_register_variable_hook ("appendedsig_key_mgmt", NULL, NULL);
  grub_env_unset ("appendedsig_key_mgmt");
  grub_verifier_unregister (&grub_appendedsig_verifier);
  unregister_appended_signatures_cmd ();
}
