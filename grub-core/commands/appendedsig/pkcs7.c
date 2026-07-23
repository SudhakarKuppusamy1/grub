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

#include <grub/misc.h>
#include <sys/types.h>
#include <grub/gcrypt/gcrypt.h>

#include "asn1_util.h"
#include "pkcs7.h"

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

/* RFC 5652 s 5.1. */
static const char *signed_data_oid = "1.2.840.113549.1.7.2";

/* RFC 4055 s 2.1. */
static const grub_mdalgo_t md_algos [] =
{
  {"sha256", "2.16.840.1.101.3.4.2.1", 22, &_gcry_digest_spec_sha256},
  {"sha512", "2.16.840.1.101.3.4.2.3", 22, &_gcry_digest_spec_sha512}
};

static void
pkcs7_free_signers (grub_pkcs7_signer_t *signers);

static grub_err_t
pkcs7_get_version (asn1_node pkcs7_asn1, grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_int32_t version_size;
  char version;

  rc = asn1_read_value (pkcs7_asn1, "version", &version, &version_size);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error reading signedData version: %s",
                       asn1_strerror (rc));

  /* Signature version must be 1 because appended signature only support v1. */
  if (version != 1)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
                       "unexpected signature version v%d, only v1 supported", version);

  pkcs7_signed_data->version = 1;

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_digest_algo (asn1_node pkcs7_asn1, grub_int32_t algo_index,
                       grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc, i;
  char *digest_path;
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_oid_size = sizeof (algo_oid);

  digest_path = grub_xasprintf ("digestAlgorithms.?%d.algorithm", algo_index + 1);
  if (digest_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for digest algorithm parsing path");

  rc = asn1_read_value (pkcs7_asn1, digest_path, algo_oid, &algo_oid_size);
  if (rc != ASN1_SUCCESS)
    {
      grub_free (digest_path);
      return grub_error (GRUB_ERR_BAD_SIGNATURE, "error reading digest algorithm: %s",
                         asn1_strerror (rc));
    }

  grub_free (digest_path);

  for (i = 0; i < sizeof (md_algos)/sizeof(md_algos[0]); i++)
    {
      if (grub_strncmp (algo_oid, md_algos[i].oid, md_algos[i].oid_len) == 0 &&
		        md_algos[i].oid_len == algo_oid_size - 1)
        {
          grub_memcpy (&pkcs7_signed_data->digest_algo, &md_algos[i], sizeof (md_algos[i]));
          return GRUB_ERR_NONE;
        }
    }

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     "only SHA-256 and SHA-512 hashes are supported, found OID %s",
                     algo_oid);
}

static grub_err_t
pkcs7_get_digest_algorithms (asn1_node pkcs7_asn1, grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_err_t ret;
  grub_int32_t algo_count;

  rc = asn1_number_of_elements (pkcs7_asn1, "digestAlgorithms", &algo_count);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error counting number of digest algorithms: %s",
                       asn1_strerror (rc));

  if (algo_count <= 0 || algo_count > 1)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
                       "only one digest algorithm is required");

  ret = pkcs7_get_digest_algo (pkcs7_asn1, 0, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    return ret;

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_signerinfo_digalgo (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                              grub_pkcs7_signer_t *signer)
{
  grub_int32_t rc, i;
  char *digest_algo_path;
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_oid_size = sizeof (algo_oid);

  digest_algo_path = grub_xasprintf ("signerInfos.?%d.digestAlgorithm.algorithm",
                                     signer_index + 1);
  if (digest_algo_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's digest algorithm parsing path",
                       signer_index);

  rc = asn1_read_value (pkcs7_asn1, digest_algo_path, algo_oid, &algo_oid_size);
  if (rc != ASN1_SUCCESS)
    {
      grub_free (digest_algo_path);
      return grub_error (GRUB_ERR_BAD_SIGNATURE,
                         "error reading signer %d's digest algorithm: %s", signer_index,
		         asn1_strerror (rc));
    }

  grub_free (digest_algo_path);

  for (i = 0; i < sizeof (md_algos)/sizeof(md_algos[0]); i++)
    {
      if (grub_strncmp (algo_oid, md_algos[i].oid, md_algos[i].oid_len) == 0 &&
		        md_algos[i].oid_len == algo_oid_size - 1)
        {
          grub_memcpy (&signer->digest_algo, &md_algos[i], sizeof (md_algos[i]));
          return GRUB_ERR_NONE;
        }
    }

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     "only SHA-256 and SHA-512 hashes are supported, found OID %s",
                     algo_oid);
}

static grub_err_t
pkcs7_get_signerinfo_signature (asn1_node pkcs7_asn1, grub_int32_t signer_index,
                                grub_pkcs7_signer_t *signer)
{
  gcry_error_t gcry_err;
  grub_uint8_t *signature;
  grub_int32_t signature_len = 0;
  char *sig_path;

  sig_path = grub_xasprintf ("signerInfos.?%d.signature", signer_index + 1);
  if (sig_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate path for signer %d's signature parsing path",
		       signer_index);

  signature = grub_asn1_allocate_and_read (pkcs7_asn1, sig_path, "signature data",
                                           &signature_len);
  grub_free (sig_path);
  if (signature == NULL)
    return grub_errno;

  gcry_err = _gcry_mpi_scan (&signer->signature, GCRYMPI_FMT_USG, signature,
                             signature_len, NULL);
  grub_free (signature);
  if (gcry_err != GPG_ERR_NO_ERROR)
    return grub_error (GRUB_ERR_BAD_SIGNATURE,
                       "error loading signature %d into MPI structure: %d",
                       signer_index, gcry_err);

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_get_signerinfos (asn1_node pkcs7_asn1, grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_err_t ret = GRUB_ERR_NONE;
  grub_int32_t rc, i;
  grub_int32_t signer_count;
  grub_pkcs7_signer_t *signer, *signers = pkcs7_signed_data->signers;

  rc = asn1_number_of_elements (pkcs7_asn1, "signerInfos", &signer_count);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "error counting number of signers: %s",
                       asn1_strerror (rc));

  if (signer_count <= 0)
    return grub_error (GRUB_ERR_BAD_SIGNATURE, "a minimum of 1 signer is required");

  pkcs7_signed_data->no_of_signers = 0;

  for (i = 0; i < signer_count; i++)
    {
      signer = grub_zalloc (sizeof (grub_pkcs7_signer_t));
      if (signer == NULL)
        return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                           "could not allocate space for signers");

      ret = pkcs7_get_signerinfo_digalgo (pkcs7_asn1, i, signer);
      if (ret == GRUB_ERR_NONE)
        {
          ret = pkcs7_get_signerinfo_signature (pkcs7_asn1, i, signer);
          if (ret == GRUB_ERR_NONE)
            {
              signer->next = (signers != NULL ? signers : NULL);
              signers = signer;
              pkcs7_signed_data->no_of_signers++;
            }
        }

      if (ret != GRUB_ERR_NONE)
        pkcs7_free_signers (signer);
    }

  pkcs7_signed_data->signers = signers;

  return GRUB_ERR_NONE;
}

static grub_err_t
pkcs7_parse_signed_data (grub_uint8_t *signed_data, grub_int32_t signed_data_len,
                         grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_err_t ret;
  grub_int32_t rc;
  asn1_node pkcs7_asn1;

  /*
   * SignedData ::= SEQUENCE {
   *     version CMSVersion,
   *     digestAlgorithms DigestAlgorithmIdentifiers,
   *     encapContentInfo EncapsulatedContentInfo,
   *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
   *     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
   *     signerInfos SignerInfos }
   */
  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.pkcs-7-SignedData", &pkcs7_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for PKCS#7 signed part");

  rc = asn1_der_decoding2 (&pkcs7_asn1, signed_data, &signed_data_len,
                           ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_SIGNATURE,
                        "error reading PKCS#7 signed data: %s", asn1_error);
      goto exit;
    }

  /* version CMSVersion */
  ret = pkcs7_get_version (pkcs7_asn1, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * digestAlgorithms DigestAlgorithmIdentifiers
   *
   * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
   * DigestAlgorithmIdentifer is an X.509 AlgorithmIdentifier (10.1.1)
   *
   * RFC 4055 s 2.1:
   * sha256Identifier  AlgorithmIdentifier  ::=  { id-sha256, NULL }
   * sha512Identifier  AlgorithmIdentifier  ::=  { id-sha512, NULL }
   *
   * We only support 1 element in the set, and we do not check parameters atm.
   */
  ret = pkcs7_get_digest_algorithms (pkcs7_asn1, pkcs7_signed_data);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /* Read the signerInfos */
  ret = pkcs7_get_signerinfos (pkcs7_asn1, pkcs7_signed_data);

 exit:
  asn1_delete_structure (&pkcs7_asn1);

  return ret;
}

/* Parse a single DER formatted PKCS#7 detached signature. */
grub_err_t
grub_pkcs7_signed_data_parse_der (const void *der_data, grub_int32_t der_data_len,
                                  grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_int32_t rc;
  grub_err_t ret = GRUB_ERR_NONE;
  asn1_node cms_content_asn1;
  char content_type_oid[GRUB_MAX_OID_LEN];
  grub_uint8_t *cms_content;
  grub_int32_t cms_content_len;
  grub_int32_t content_type_oid_size = sizeof (content_type_oid);

  if (der_data == NULL || der_data_len == 0 || pkcs7_signed_data == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  if (der_data_len > GRUB_UINT_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "cannot parse a PKCS#7 message where data size > GRUB_UINT_MAX");

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.pkcs-7-ContentInfo", &cms_content_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for PKCS#7 data: %s",
                       asn1_strerror (rc));

  rc = asn1_der_decoding2 (&cms_content_asn1, der_data, &der_data_len,
                           ASN1_DECODE_FLAG_STRICT_DER | ASN1_DECODE_FLAG_ALLOW_PADDING,
                           asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error decoding PKCS#7 message DER: %s", asn1_error);
      goto exit;
    }

  /*
   * ContentInfo ::= SEQUENCE {
   *     contentType ContentType,
   *     content [0] EXPLICIT ANY DEFINED BY contentType }
   *
   * ContentType ::= OBJECT IDENTIFIER
   */
  rc = asn1_read_value (cms_content_asn1, "contentType", content_type_oid, &content_type_oid_size);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_READ_ERROR, "error reading PKCS#7 content type: %s",
                        asn1_strerror (rc));
      goto exit;
    }

  /* OID for SignedData defined in 5.1. */
  if (grub_strncmp (signed_data_oid, content_type_oid, content_type_oid_size) != 0)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "unexpected content type in PKCS#7 message: OID %s", content_type_oid);
      goto exit;
    }

  cms_content = grub_asn1_allocate_and_read (cms_content_asn1, "content", "PKCS#7 message content", &cms_content_len);
  if (cms_content == NULL)
    {
      ret = grub_errno;
      goto exit;
    }

  grub_memset (pkcs7_signed_data, 0x00, sizeof (grub_pkcs7_signed_data_t));
  ret = pkcs7_parse_signed_data (cms_content, cms_content_len, pkcs7_signed_data);
  grub_free (cms_content);

 exit:
  asn1_delete_structure (&cms_content_asn1);

  return ret;
}

static void
pkcs7_free_signers (grub_pkcs7_signer_t *signers)
{
  grub_pkcs7_signer_t *prev_signer;

  while (signers != NULL)
    {
      grub_memset (&signers->digest_algo, 0x00, sizeof (grub_mdalgo_t));
      _gcry_mpi_release (signers->signature);
      prev_signer = signers;
      signers = signers->next;
      grub_free (prev_signer);
    }
}

/*
 * Release all the storage associated with the PKCS#7 message. If the caller
 * dynamically allocated the message, it must free it.
 */
void
grub_pkcs7_signed_data_release (grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  if (pkcs7_signed_data == NULL)
    return;

  pkcs7_signed_data->version = 0;
  grub_memset (&pkcs7_signed_data->digest_algo, 0x00, sizeof (grub_mdalgo_t));
  pkcs7_free_signers (pkcs7_signed_data->signers);
  grub_memset (pkcs7_signed_data, 0x00, sizeof (grub_pkcs7_signed_data_t));
}

/* Release the alloacted memory. */
void
grub_pkcs7_signed_data_free (grub_pkcs7_signed_data_t *pkcs7_signed_data)
{
  grub_free (pkcs7_signed_data);
}
