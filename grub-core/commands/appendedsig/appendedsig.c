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

#include "appendedsig.h"

GRUB_MOD_LICENSE ("GPLv3+");

/* Max size of hash data. */
#define MAX_HASH_SIZE      64

/* Public key type. */
#define PKEY_ID_PKCS7      2

/* Appended signature magic string and size. */
#define SIG_MAGIC          "~Module signature appended~\n"
#define SIG_MAGIC_SIZE     ((sizeof(SIG_MAGIC) - 1))

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

#define SIG_METADATA_SIZE  (sizeof (struct module_signature))
#define APPENDED_SIG_SIZE(pkcs7_data_size) \
                           (pkcs7_data_size + SIG_MAGIC_SIZE + SIG_METADATA_SIZE)

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
};

/* The db list is used to validate appended signatures. */
struct grub_database db = {.certs = NULL, .cert_entries = 0};

/*
 * Signature verification flag (check_sigs).
 * check_sigs: false
 *  - No signature verification. This is the default.
 * check_sigs: true
 *  - Enforce signature verification, and if signature verification fails,
 *    post the errors and stop the boot.
 */
static bool check_sigs = false;

/* Appended signature size. */
static grub_size_t append_sig_len = 0;

static void
register_appended_signatures_cmd (void);
static void
unregister_appended_signatures_cmd (void);

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

/*
 * We cannot use hexdump() to display hash data because it is typically
 * displayed in hexadecimal format, along with an ASCII representation of
 * the same data.
 * Example: sha256 hash data
 * 00000000  52 b5 90 49 64 de 22 d7  4e 5f 4f b4 1b 51 9c 34  |R..Id.".N_O..Q.4|
 * 00000010  b1 96 21 7c 91 78 a5 0d  20 8c e9 5c 22 54 53 f7  |..!|.x.. ..\"TS.|
 *
 * An appended signature only required to display the hexadecimal of the hash data
 * by separating each byte with ":". So, we introduced a new method dump_data_to_hex
 * to display it.
 * Example: Sha256 hash data
 *  52:b5:90:49:64:de:22:d7:4e:5f:4f:b4:1b:51:9c:34:
 *  b1:96:21:7c:91:78:a5:0d:20:8c:e9:5c:22:54:53:f7
 */
static void
dump_data_to_hex (const grub_uint8_t *data, const grub_size_t length)
{
  grub_size_t i, count = 0;

  for (i = 0; i < length - 1; i++)
    {
      grub_printf ("%02x:", data[i]);
      count++;
      if (count == 16)
        {
          grub_printf ("\n         ");
          count = 0;
        }
    }

  grub_printf ("%02x\n", data[i]);
}

static void
print_certificate (const struct x509_certificate *cert, const grub_uint32_t cert_num)
{
  grub_uint32_t i;

  grub_printf ("\nCertificate: %u\n", cert_num);
  grub_printf ("    Data:\n");
  grub_printf ("        Version: %u (0x%u)\n", cert->version + 1, cert->version);
  grub_printf ("        Serial Number:\n             ");

  for (i = 0; i < cert->serial_len - 1; i++)
    grub_printf ("%02x:", cert->serial[i]);

  grub_printf ("%02x\n", cert->serial[cert->serial_len - 1]);
  grub_printf ("        Issuer: %s\n", cert->issuer);
  grub_printf ("        Subject: %s\n", cert->subject);
  grub_printf ("        Subject Public Key Info:\n");
  grub_printf ("            Public Key Algorithm: rsaEncryption\n");
  grub_printf ("                RSA Public-Key: (%d bit)\n", cert->modulus_size);
  grub_printf ("    Fingerprint: sha256\n         ");
  dump_data_to_hex ((grub_uint8_t *) &cert->fingerprint[0], grub_strlen (cert->fingerprint[0]));
}

static void
add_cert_fingerprint (const grub_uint8_t *data, const grub_size_t data_size,
                      struct x509_certificate *const cert)
{
  gcry_md_spec_t *hash_func = NULL;

  /* Add SHA256 hash of certificate. */
  hash_func = &_gcry_digest_spec_sha256;
  grub_memset (&cert->fingerprint[0], 0, MAX_HASH_SIZE);
  grub_crypto_hash (hash_func, &cert->fingerprint[0], data, data_size);
}

static bool
is_cert_match (const struct x509_certificate *cert1, const struct x509_certificate *cert2)
{
  if (grub_memcmp (cert1->subject, cert2->subject, cert2->subject_len) == 0
      && grub_memcmp (cert1->issuer, cert2->issuer, cert2->issuer_len) == 0
      && grub_memcmp (cert1->serial, cert2->serial, cert2->serial_len) == 0
      && grub_memcmp (cert1->mpis[0], cert2->mpis[0], sizeof (cert2->mpis[0])) == 0
      && grub_memcmp (cert1->mpis[1], cert2->mpis[1], sizeof (cert2->mpis[1])) == 0
      && grub_memcmp (cert1->fingerprint[0], cert2->fingerprint[0], 32) == 0)
    return true;

  return false;
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

/* Add the certificate into the db list */
static grub_err_t
add_certificate (const grub_uint8_t *data, const grub_size_t data_size,
                 struct grub_database *database)
{
  grub_err_t rc;
  struct x509_certificate *cert;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = parse_x509_certificate (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot add a certificate CN='%s' to the db list\n",
                    cert->subject);
      grub_free (cert);
      return rc;
    }

  add_cert_fingerprint (data, data_size, cert);

  if (is_cert_present_in_db (cert) == true)
    {
      grub_dprintf ("appendedsig",
                    "cannot add a certificate CN='%s', as it is present in the db list",
                    cert->subject);
      certificate_release (cert);
      grub_free (cert);

      return GRUB_ERR_EXISTS;
    }

  grub_dprintf ("appendedsig", "added a certificate CN='%s' to the db list\n",
                cert->subject);

  cert->next = database->certs;
  database->certs = cert;
  database->cert_entries++;

  return rc;
}

static void
_remove_cert_from_db (const struct x509_certificate *cert)
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
                        "removed distrusted certificate with CN: %s from the db list\n",
                        curr_cert->subject);
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
remove_cert_from_db (const grub_uint8_t *data, const grub_size_t data_size)
{
  grub_err_t rc;
  struct x509_certificate *cert;

  if (data == NULL || data_size == 0)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "certificate data or size is not available");

  cert = grub_zalloc (sizeof (struct x509_certificate));
  if (cert == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = parse_x509_certificate (data, data_size, cert);
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("appendedsig", "cannot remove a certificate from the db list\n");
      grub_free (cert);
      return rc;
    }

  add_cert_fingerprint (data, data_size, cert);

  /* Remove certificate from the db list. */
  _remove_cert_from_db (cert);

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
                       "file is too large to read: %" PRIuGRUB_OFFSET " bytes",
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
  grub_size_t appendedsig_pkcs7_size;
  grub_size_t signed_data_size = bufsize;
  const grub_uint8_t *signed_data = buf;

  if (signed_data_size < SIG_MAGIC_SIZE)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature magic");

  /* Fast-forwarding pointer and get signature magic string. */
  signed_data += signed_data_size - SIG_MAGIC_SIZE;
  if (grub_strncmp ((const char *) signed_data, SIG_MAGIC, SIG_MAGIC_SIZE))
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "missing or invalid signature magic");

  signed_data_size -= SIG_MAGIC_SIZE;
  if (signed_data_size < SIG_METADATA_SIZE)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for signature metadata");

  /* Rewind pointer and extract signature metadata. */
  signed_data -= SIG_METADATA_SIZE;
  grub_memcpy (&(sig->sig_metadata), signed_data, SIG_METADATA_SIZE);

  if (sig->sig_metadata.id_type != PKEY_ID_PKCS7)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "wrong signature type");

  appendedsig_pkcs7_size = grub_be_to_cpu32 (sig->sig_metadata.sig_len);

  signed_data_size -= SIG_METADATA_SIZE;
  if (appendedsig_pkcs7_size > signed_data_size)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "file too short for PKCS#7 message");

  grub_dprintf ("appendedsig", "sig len %" PRIuGRUB_SIZE "\n", appendedsig_pkcs7_size);

  /* Appended signature size. */
  sig->signature_len = APPENDED_SIG_SIZE (appendedsig_pkcs7_size);
  /* Rewind pointer and parse appended pkcs7 data. */
  signed_data -= appendedsig_pkcs7_size;

  return parse_pkcs7_signedData (signed_data, appendedsig_pkcs7_size, &sig->pkcs7);
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

  if (_gcry_sexp_build (&hsexp, &errof, "(data (flags %s) (hash %s %b))", "pkcs1",
                        hash->name, hash->mdlen, hval) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  if (_gcry_sexp_build (&pubkey, &errof, "(public-key (dsa (n %M) (e %M)))",
                        pkmpi[0], pkmpi[1]) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  if (_gcry_sexp_build (&sig, &errof, "(sig-val (rsa (s %M)))", hmpi) != GPG_ERR_NO_ERROR)
    return GRUB_ERR_BAD_SIGNATURE;

  _gcry_sexp_dump (sig);
  _gcry_sexp_dump (hsexp);
  _gcry_sexp_dump (pubkey);

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
grub_cmd_verify_signature (grub_command_t cmd __attribute__ ((unused)), int argc, char **args)
{
  grub_file_t signed_file;
  grub_err_t err;
  grub_uint8_t *signed_data = NULL;
  grub_size_t signed_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a signed file is expected\nExample:\n\tappend_verify <SIGNED FILE>\n");

  if (!grub_strlen (args[0]))
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
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a trusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_add_db_cert <X509_CERTIFICATE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing trusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = file_read_whole (cert_file, &cert_data, &cert_data_size);
  grub_file_close (cert_file);
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
    cert_data_size -= append_sig_len;

  err = add_certificate (cert_data, cert_data_size, &db);
  grub_free (cert_data);
  if (err != GRUB_ERR_NONE)
    return err;

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
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       "a distrusted X.509 certificate file is expected in DER format\n"
                       "Example:\n\tappend_rm_dbx_cert <X509_CERTIFICATE>\n");

  if (!grub_strlen (args[0]))
    return grub_error (GRUB_ERR_BAD_FILENAME, "missing distrusted X.509 certificate file");

  cert_file = grub_file_open (args[0],
                              GRUB_FILE_TYPE_CERTIFICATE_TRUST | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (cert_file == NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "could not open %s file", args[0]);

  err = file_read_whole (cert_file, &cert_data, &cert_data_size);
  grub_file_close (cert_file);
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
    cert_data_size -= append_sig_len;

  /* Remove distrusted certificate from the db list if present. */
  err = remove_cert_from_db (cert_data, cert_data_size);
  grub_free (cert_data);
  if (err != GRUB_ERR_NONE)
    return err;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_list_db (grub_command_t cmd __attribute__ ((unused)), int argc __attribute__ ((unused)),
                  char **args __attribute__ ((unused)))
{
  struct x509_certificate *cert;
  grub_uint32_t i, cert_num = 1;

  for (cert = db.certs; cert != NULL; cert = cert->next, cert_num++)
    print_certificate (cert, cert_num);

  return GRUB_ERR_NONE;
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
  grub_uint8_t *cert_data = NULL;
  grub_size_t cert_data_size = 0;

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

      err = file_read_whole (&pseudo_file, &cert_data, &cert_data_size);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
      else if (err != GRUB_ERR_NONE)
        continue;

      err = add_certificate (cert_data, cert_data_size, &db);
      grub_free (cert_data);
      if (err == GRUB_ERR_OUT_OF_MEMORY)
        return;
    }
}

/* Free db list memory */
static void
free_db_list (void)
{
  struct x509_certificate *cert;

  while (db.certs != NULL)
    {
      cert = db.certs;
      db.certs = db.certs->next;
      certificate_release (cert);
      grub_free (cert);
    }

  grub_memset (&db, 0, sizeof (struct grub_database));
}

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

static grub_command_t cmd_verify, cmd_list_db, cmd_dbx_cert, cmd_db_cert;

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

  rc = asn1_init ();
  if (rc != ASN1_SUCCESS)
    grub_fatal ("error initing ASN.1 data structures: %d: %s\n", rc, asn1_strerror (rc));

  /* Extract trusted keys from ELF Note and store them in the db. */
  build_static_db_list ();
  grub_dprintf ("appendedsig", "the db list now has %u static keys\n",
                db.cert_entries);

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
  grub_register_variable_hook ("check_appended_signatures", NULL, NULL);
  grub_env_unset ("check_appended_signatures");
  grub_verifier_unregister (&grub_appendedsig_verifier);
  unregister_appended_signatures_cmd ();
}
