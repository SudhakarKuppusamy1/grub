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

#include <libtasn1.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/crypto.h>
#include <grub/misc.h>
#include <grub/gcrypt/gcrypt.h>

#include "asn1_util.h"
#include "x509.h"

static char asn1_error[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

/* RFC 5280 Appendix A. */
static const char *commonName_oid = "2.5.4.3";

/* RFC 5280 4.2.1.3 Key Usage. */
static const char *keyUsage_oid = "2.5.29.15";

static const grub_uint8_t digitalSignatureUsage = 0x80;

/* RFC 5280 4.2.1.9 Basic Constraints. */
static const char *basicConstraints_oid = "2.5.29.19";

/* RFC 5280 4.2.1.12 Extended Key Usage. */
static const char *extendedKeyUsage_oid = "2.5.29.37";
static const char *codeSigningUsage_oid = "1.3.6.1.5.5.7.3.3";

/* RFC 3279 2.3.1  RSA Keys. */
static const grub_pkalgo_t pk_algo = {"rsaEncryption", "1.2.840.113549.1.1.1", 20};

/*
 * RFC 3279 2.3.1
 *
 *  The RSA public key MUST be encoded using the ASN.1 type RSAPublicKey:
 *
 *     RSAPublicKey ::= SEQUENCE {
 *        modulus            INTEGER,    -- n
 *        publicExponent     INTEGER  }  -- e
 *
 *  where modulus is the modulus n, and publicExponent is the public exponent e.
 */
static grub_err_t
x509_get_rsa_pubkey (grub_uint8_t *der_data, grub_int32_t der_data_size, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  asn1_node rsa_pk_asn1 = NULL;
  grub_uint8_t *m_data, *e_data;
  grub_int32_t m_size, e_size;
  grub_err_t err = GRUB_ERR_NONE;
  gcry_error_t gcry_err;

  rc = asn1_create_element (grub_gnutls_gnutls_asn, "GNUTLS.RSAPublicKey", &rsa_pk_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "cannot create storage for public key ASN.1 data");

  rc = asn1_der_decoding2 (&rsa_pk_asn1, der_data, &der_data_size, ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "cannot decode certificate public key DER: %s", asn1_error);
      goto cleanup;
    }

  m_data = grub_asn1_allocate_and_read (rsa_pk_asn1, "modulus", "RSA modulus", &m_size);
  if (m_data == NULL)
    {
      err = grub_errno;
      goto cleanup;
    }

  e_data = grub_asn1_allocate_and_read (rsa_pk_asn1, "publicExponent", "RSA public exponent", &e_size);
  if (e_data == NULL)
    {
      err = grub_errno;
      goto cleanup_m_data;
    }

  /*
   * Convert m, e to mpi
   *
   * nscanned is not set for FMT_USG, it's only set for FMT_PGP, so we can't
   * verify it.
   */
  gcry_err = _gcry_mpi_scan (&cert->spki.pk[0], GCRYMPI_FMT_USG, m_data, m_size, NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error loading RSA modulus into MPI structure: %d", gcry_err);
      goto cleanup_e_data;
    }

  gcry_err = _gcry_mpi_scan (&cert->spki.pk[1], GCRYMPI_FMT_USG, e_data, e_size, NULL);
  if (gcry_err != GPG_ERR_NO_ERROR)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error loading RSA exponent into MPI structure: %d", gcry_err);
      goto cleanup_m_mpi;
    }

  /* RSA key size in bits. */
  cert->spki.pk_len = (m_size * 8) - 8;

  grub_free (e_data);
  grub_free (m_data);
  asn1_delete_structure (&rsa_pk_asn1);

  return GRUB_ERR_NONE;

 cleanup_m_mpi:
  _gcry_mpi_release (cert->spki.pk[0]);
 cleanup_e_data:
  grub_free (e_data);
 cleanup_m_data:
  grub_free (m_data);
 cleanup:
  asn1_delete_structure (&rsa_pk_asn1);

  return err;
}

/* Decode a string as defined in Appendix A. */
static grub_err_t
x509_decode_string (char *der, grub_int32_t der_size, char **string, grub_size_t *string_size)
{
  asn1_node strasn;
  grub_int32_t rc;
  char *choice;
  grub_int32_t choice_size = 0;
  grub_int32_t tmp_size = 0;
  grub_err_t err = GRUB_ERR_NONE;

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.DirectoryString", &strasn);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for certificate: %s",
                       asn1_strerror (rc));

  rc = asn1_der_decoding2 (&strasn, der, &der_size, ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "could not parse DER for DirectoryString: %s", asn1_error);
      goto cleanup;
    }

  choice = grub_asn1_allocate_and_read (strasn, "", "DirectoryString choice", &choice_size);
  if (choice == NULL)
    {
      err = grub_errno;
      goto cleanup;
    }

  if (grub_strncmp ("utf8String", choice, choice_size) == 0)
    {
      rc = asn1_read_value (strasn, "utf8String", NULL, &tmp_size);
      if (rc != ASN1_MEM_ERROR)
        {
          err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of UTF-8 string: %s",
                            asn1_strerror (rc));
          goto cleanup_choice;
        }
    }
  else if (grub_strncmp ("printableString", choice, choice_size) == 0)
    {
      rc = asn1_read_value (strasn, "printableString", NULL, &tmp_size);
      if (rc != ASN1_MEM_ERROR)
        {
          err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of printableString: %s",
                            asn1_strerror (rc));
          goto cleanup_choice;
        }
    }
  else
    {
      err = grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                        "only UTF-8 and printable DirectoryStrings are supported, got %s",
                        choice);
      goto cleanup_choice;
    }

  /* Read size does not include trailing NUL. */
  tmp_size++;

  *string = grub_malloc (tmp_size);
  if (*string == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                        "cannot allocate memory for DirectoryString contents");
      goto cleanup_choice;
    }

  rc = asn1_read_value (strasn, choice, *string, &tmp_size);
  if (rc != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading out %s in DirectoryString: %s",
                        choice, asn1_strerror (rc));
      grub_free (*string);
      *string = NULL;
      goto cleanup_choice;
    }

  *string_size = tmp_size + 1;
  (*string)[tmp_size] = '\0';

 cleanup_choice:
  grub_free (choice);
 cleanup:
  asn1_delete_structure (&strasn);

  return err;
}

/* we extract only the CN and issuer. */
static grub_err_t
x509_read_name (asn1_node cert_asn1, const char *name_path, char **name, grub_size_t *name_size)
{
  grub_int32_t seq_components, set_components;
  grub_int32_t rc;
  grub_int32_t i, j;
  char *top_path, *set_path, *type_path, *val_path;
  char type[GRUB_MAX_OID_LEN];
  grub_int32_t type_len = sizeof (type);
  grub_int32_t string_size = 0;
  char *string_der;
  grub_err_t ret;

  *name = NULL;

  top_path = grub_xasprintf ("%s.rdnSequence", name_path);
  if (top_path == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not allocate memory for %s name parsing path", name_path);

  rc = asn1_number_of_elements (cert_asn1, top_path, &seq_components);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error counting name components: %s",
                        asn1_strerror (rc));
      goto cleanup;
    }

  for (i = 1; i <= seq_components; i++)
    {
      set_path = grub_xasprintf ("%s.?%d", top_path, i);
      if (set_path == NULL)
        {
          ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                            "could not allocate memory for %s name set parsing path",
                            name_path);
          goto cleanup_set;
        }
      /* This brings us, hopefully, to a set. */
      rc = asn1_number_of_elements (cert_asn1, set_path, &set_components);
      if (rc != ASN1_SUCCESS)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                            "error counting name sub-components components (element %d): %s",
                            i, asn1_strerror (rc));
          goto cleanup_set;
        }
      for (j = 1; j <= set_components; j++)
        {
          type_path = grub_xasprintf ("%s.?%d.?%d.type", top_path, i, j);
          if (type_path == NULL)
            {
              ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                                "could not allocate memory for %s name component type path",
                                name_path);
              goto cleanup_set;
            }
          type_len = sizeof (type);
          rc = asn1_read_value (cert_asn1, type_path, type, &type_len);
          if (rc != ASN1_SUCCESS)
            {
              ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading %s name component type: %s",
                                name_path, asn1_strerror (rc));
              goto cleanup_type;
            }

          if (grub_strncmp (type, commonName_oid, type_len) != 0)
            {
              grub_free (type_path);
              continue;
            }

          val_path = grub_xasprintf ("%s.?%d.?%d.value", top_path, i, j);
          if (val_path == NULL)
            {
              ret = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                                "could not allocate memory for %s name component value path",
                                name_path);
              goto cleanup_type;
            }

          string_der = grub_asn1_allocate_and_read (cert_asn1, val_path, name_path, &string_size);
          if (string_der == NULL)
            {
              ret = grub_errno;
              goto cleanup_val_path;
            }

          ret = x509_decode_string (string_der, string_size, name, name_size);
          if (ret)
            goto cleanup_string;

          grub_free (string_der);
          grub_free (type_path);
          grub_free (val_path);
          break;
        }

      grub_free (set_path);
      if (*name)
        break;
    }

  grub_free (top_path);

  return GRUB_ERR_NONE;

 cleanup_string:
  grub_free (string_der);
 cleanup_val_path:
  grub_free (val_path);
 cleanup_type:
  grub_free (type_path);
 cleanup_set:
  grub_free (set_path);
 cleanup:
  grub_free (top_path);

  return ret;
}

/* Verify the Key Usage extension. We require the Digital Signature usage. */
static grub_err_t
x509_verify_key_usage (grub_uint8_t *value, grub_int32_t value_size)
{
  asn1_node usageasn;
  grub_int32_t result;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t usage = 0xff;
  grub_int32_t usage_size = sizeof (usage_size);

  result = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.KeyUsage", &usageasn);
  if (result != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for key usage");

  result = asn1_der_decoding2 (&usageasn, value, &value_size,
                               ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error parsing DER for Key Usage: %s", asn1_error);
      goto cleanup;
    }

  result = asn1_read_value (usageasn, "", &usage, &usage_size);
  if (result != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading Key Usage value: %s",
                        asn1_strerror (result));
      goto cleanup;
    }

  if (!(usage & digitalSignatureUsage))
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "key usage (0x%x) missing Digital Signature usage", usage);
      goto cleanup;
    }

 cleanup:
  asn1_delete_structure (&usageasn);

  return err;
}

/*
 * BasicConstraints ::= SEQUENCE {
 *       cA                      BOOLEAN DEFAULT FALSE,
 *       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
static grub_err_t
x509_verify_basic_constraints (grub_uint8_t *value, grub_int32_t value_size)
{
  asn1_node basicasn;
  grub_int32_t result;
  grub_err_t err = GRUB_ERR_NONE;
  char cA[6]; /* FALSE or TRUE. */
  grub_int32_t cA_size = sizeof (cA);

  result = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.BasicConstraints", &basicasn);
  if (result != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for Basic Constraints");

  result = asn1_der_decoding2 (&basicasn, value, &value_size,
                               ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error parsing DER for Basic Constraints: %s", asn1_error);
      goto cleanup;
    }

  result = asn1_read_value (basicasn, "cA", cA, &cA_size);
  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      /* Not present, default is False, so this is OK. */
      err = GRUB_ERR_NONE;
      goto cleanup;
    }
  else if (result != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading Basic Constraints cA value: %s",
                        asn1_strerror (result));
      goto cleanup;
    }

  /* The certificate must not be a CA certificate. */
  if (grub_strncmp ("FALSE", cA, cA_size) != 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "unexpected CA value: %s", cA);
      goto cleanup;
    }

 cleanup:
  asn1_delete_structure (&basicasn);

  return err;
}

/*
 * Verify the Extended Key Usage extension. We require the Code Signing usage.
 *
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static grub_err_t
x509_verify_extended_key_usage (grub_uint8_t *value, grub_int32_t value_size)
{
  asn1_node extendedasn;
  grub_int32_t result, count, i = 0;
  grub_err_t err = GRUB_ERR_NONE;
  char usage[GRUB_MAX_OID_LEN], name[3];
  grub_int32_t usage_size = sizeof (usage);

  result = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.ExtKeyUsageSyntax", &extendedasn);
  if (result != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for Extended Key Usage");

  result = asn1_der_decoding2 (&extendedasn, value, &value_size,
                               ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (result != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "error parsing DER for Extended Key Usage: %s", asn1_error);
      goto cleanup;
    }

  /* If EKUs are present, it checks the presents of Code Signing usage. */
  result = asn1_number_of_elements (extendedasn, "", &count);
  if (result != ASN1_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error counting number of Extended Key Usages: %s",
                        asn1_strerror (result));
      goto cleanup;
    }

  for (i = 1; i < count + 1; i++)
    {
      grub_memset (name, 0, sizeof (name));
      grub_snprintf (name, sizeof (name), "?%d", i);
      result = asn1_read_value (extendedasn, name, usage, &usage_size);
      if (result != ASN1_SUCCESS)
        {
          err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading Extended Key Usage: %s",
                            asn1_strerror (result));
          goto cleanup;
        }

      if (grub_strncmp (codeSigningUsage_oid, usage, usage_size) == 0)
        goto cleanup;
    }

  err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "extended key usage missing Code Signing usage");

 cleanup:
  asn1_delete_structure (&extendedasn);

  return err;
}

/*
 * TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  EXPLICIT Version DEFAULT v1,
 * ...
 *
 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static grub_err_t
x509_get_version (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  const char *name = "tbsCertificate.version";
  grub_uint8_t version;
  grub_int32_t version_len = sizeof (version);

  rc = asn1_read_value (cert_asn1, name, &version, &version_len);
  /* Require version 3. */
  if (rc != ASN1_SUCCESS || version_len != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading certificate version");

  if (version != 0x02)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "invalid x509 certificate version, expected v3 (0x02), got 0x%02x.",
                       version);

  cert->version = version;

  return GRUB_ERR_NONE;
}

static grub_err_t
x509_get_serial (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t serial_size;

  cert->serial = grub_asn1_allocate_and_read (cert_asn1, "tbsCertificate.serialNumber",
                                              "certificate serial number", &serial_size);
  if (cert->serial == NULL)
    return grub_errno;
  /*
   * It's safe to cast the signed int to an unsigned here, we know
   * length is non-negative.
   */
  cert->serial_len = serial_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
x509_get_issuer_and_subject (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_err_t ret;

  ret = x509_read_name (cert_asn1, "tbsCertificate.issuer", &cert->issuer, &cert->issuer_len);
  if (ret != GRUB_ERR_NONE)
    {
      grub_free (cert->serial);
      return ret;
    }

  ret = x509_read_name (cert_asn1, "tbsCertificate.subject", &cert->subject, &cert->subject_len);
  if (ret != GRUB_ERR_NONE)
    {
      grub_free (cert->serial);
      grub_free (cert->issuer);
      return ret;
    }

  return GRUB_ERR_NONE;
}

/*
 * RFC 5280:
 *   SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING  }
 *
 * AlgorithmIdentifiers come from RFC 3279, we are not strictly compilant as we
 * only support RSA Encryption.
 */
static grub_err_t
x509_get_subject_public_key (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  grub_err_t ret;
  const char *algo_name = "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm";
  const char *params_name = "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters";
  const char *pk_name = "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey";
  char algo_oid[GRUB_MAX_OID_LEN];
  grub_int32_t algo_size = sizeof (algo_oid);
  char params_value[2];
  grub_int32_t params_size = sizeof (params_value);
  grub_uint8_t *key_data = NULL;
  grub_int32_t key_size = 0;
  grub_uint32_t key_type;

  /* Algorithm: see notes for rsaEncryption_oid. */
  rc = asn1_read_value (cert_asn1, algo_name, algo_oid, &algo_size);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading x509 public key algorithm: %s",
                       asn1_strerror (rc));

  if (grub_strncmp (algo_oid, pk_algo.oid, sizeof (pk_algo.oid)) != 0)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                       "unsupported x509 public key algorithm: %s", algo_oid);

  grub_memcpy (&cert->spki.pk_algo, &pk_algo, sizeof (pk_algo));

  /*
   * RFC 3279 2.3.1 : The rsaEncryption OID is intended to be used in the
   * algorithm field of a value of type AlgorithmIdentifier. The parameters
   * field MUST have ASN.1 type NULL for this algorithm identifier.
   */
  rc = asn1_read_value (cert_asn1, params_name, params_value, &params_size);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading x509 public key parameters: %s",
                       asn1_strerror (rc));

  if (params_value[0] != ASN1_TAG_NULL)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "invalid x509 public key parameters: expected NULL");

  /*
   * RFC 3279 2.3.1:  The DER encoded RSAPublicKey is the value of the BIT
   * STRING subjectPublicKey.
   */
  rc = asn1_read_value_type (cert_asn1, pk_name, NULL, &key_size, &key_type);
  if (rc != ASN1_MEM_ERROR)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading size of x509 public key: %s",
                       asn1_strerror (rc));
  if (key_type != ASN1_ETYPE_BIT_STRING)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "unexpected ASN.1 type when reading x509 public key: %x",
                       key_type);

  /* Length is in bits. */
  key_size = (key_size + 7) / 8;

  key_data = grub_malloc (key_size);
  if (key_data == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory for x509 public key");

  rc = asn1_read_value (cert_asn1, pk_name, key_data, &key_size);
  if (rc != ASN1_SUCCESS)
    {
      grub_free (key_data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading public key data");
    }

  key_size = (key_size + 7) / 8;
  ret = x509_get_rsa_pubkey (key_data, key_size, cert);
  grub_free (key_data);

  return ret;
}

/*
 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension  ::=  SEQUENCE  {
 *      extnID      OBJECT IDENTIFIER,
 *      critical    BOOLEAN DEFAULT FALSE,
 *      extnValue   OCTET STRING
 *                  -- contains the DER encoding of an ASN.1 value
 *                  -- corresponding to the extension type identified
 *                  -- by extnID
 * }
 *
 * A certificate must:
 *  - contain the Digital Signature usage
 *  - not be a CA
 *  - contain no extended usages, or contain the Code Signing extended usage
 *  - not contain any other critical extensions (RFC 5280 s 4.2)
 */
static grub_err_t
x509_get_extensions (asn1_node cert_asn1, grub_x509_cert_t *cert)
{
  grub_int32_t rc;
  grub_int32_t ext, num_extensions = 0;
  grub_int32_t usage_present = 0, constraints_present = 0, extended_usage_present = 0;
  char *oid_path, *critical_path, *value_path;
  char extnID[GRUB_MAX_OID_LEN];
  grub_int32_t extnID_size;
  grub_err_t ret;
  char critical[6]; /* We get either "TRUE" or "FALSE". */
  grub_int32_t critical_size;
  grub_uint8_t *value;
  grub_int32_t value_size;

  (void) cert;

  rc = asn1_number_of_elements (cert_asn1, "tbsCertificate.extensions", &num_extensions);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error counting number of extensions: %s",
                       asn1_strerror (rc));

  if (num_extensions < 2)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "insufficient number of extensions for certificate, need at least 2, got %d",
                       num_extensions);

  for (ext = 1; ext <= num_extensions; ext++)
    {
      oid_path = grub_xasprintf ("tbsCertificate.extensions.?%d.extnID", ext);
      if (oid_path == NULL)
        return grub_error (GRUB_ERR_BAD_FILE_TYPE, "error extension OID path is empty");

      extnID_size = sizeof (extnID);
      rc = asn1_read_value (cert_asn1, oid_path, extnID, &extnID_size);
      if (rc != ASN1_SUCCESS)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading extension OID: %s",
                            asn1_strerror (rc));
          goto cleanup_oid_path;
        }

      critical_path = grub_xasprintf ("tbsCertificate.extensions.?%d.critical", ext);
      if (critical_path == NULL)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error critical path is empty");
          goto cleanup_oid_path;
        }

      critical_size = sizeof (critical);
      rc = asn1_read_value (cert_asn1, critical_path, critical, &critical_size);
      if (rc == ASN1_ELEMENT_NOT_FOUND)
        critical[0] = '\0';
      else if (rc != ASN1_SUCCESS)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error reading extension criticality: %s",
                            asn1_strerror (rc));
          goto cleanup_critical_path;
        }

      value_path = grub_xasprintf ("tbsCertificate.extensions.?%d.extnValue", ext);
      if (value_path == NULL)
        {
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE, "error extnValue path is empty");
          goto cleanup_critical_path;
        }

      value = grub_asn1_allocate_and_read (cert_asn1, value_path,
                                           "certificate extension value", &value_size);
      if (value == NULL)
        {
          ret = grub_errno;
          goto cleanup_value_path;
        }

      /*
       * Now we must see if we recognise the OID. If we have an unrecognised
       * critical extension we MUST bail.
       */
      if (grub_strncmp (keyUsage_oid, extnID, extnID_size) == 0)
        {
          ret = x509_verify_key_usage (value, value_size);
          if (ret != GRUB_ERR_NONE)
            goto cleanup_value;

          usage_present++;
        }
      else if (grub_strncmp (basicConstraints_oid, extnID, extnID_size) == 0)
        {
          ret = x509_verify_basic_constraints (value, value_size);
          if (ret != GRUB_ERR_NONE)
            goto cleanup_value;

          constraints_present++;
        }
      else if (grub_strncmp (extendedKeyUsage_oid, extnID, extnID_size) == 0)
        {
          ret = x509_verify_extended_key_usage (value, value_size);
          if (ret != GRUB_ERR_NONE)
            goto cleanup_value;

          extended_usage_present++;
        }
      else if (grub_strncmp ("TRUE", critical, critical_size) == 0)
        {
          /*
           * Per the RFC, we must not process a certificate with a critical
           * extension we do not understand.
           */
          ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                            "unhandled critical x509 extension with OID %s", extnID);
          goto cleanup_value;
        }

      grub_free (value);
      grub_free (value_path);
      grub_free (critical_path);
      grub_free (oid_path);
    }

  if (usage_present != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "unexpected number of Key Usage extensions - expected 1, got %d",
                       usage_present);

  if (constraints_present != 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "unexpected number of basic constraints extensions - expected 1, got %d",
                       constraints_present);

  if (extended_usage_present > 1)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE,
                       "unexpected number of Extended Key Usage extensions - expected 0 or 1, got %d",
                       extended_usage_present);

  return GRUB_ERR_NONE;

 cleanup_value:
  grub_free (value);
 cleanup_value_path:
  grub_free (value_path);
 cleanup_critical_path:
  grub_free (critical_path);
 cleanup_oid_path:
  grub_free (oid_path);

  return ret;
}

static void
x509_add_cert_fingerprint (const void *data, const grub_size_t data_size,
                           grub_x509_cert_t *const cert)
{
  /* Add SHA256 hash of certificate. */
  grub_crypto_hash ((gcry_md_spec_t *) &_gcry_digest_spec_sha256,
                    &cert->fingerprint[GRUB_FINGERPRINT_SHA256], data, data_size);
  /* Add SHA384 hash of certificate. */
  grub_crypto_hash ((gcry_md_spec_t *) &_gcry_digest_spec_sha384,
                    &cert->fingerprint[GRUB_FINGERPRINT_SHA384], data, data_size);
  /* Add SHA512 hash of certificate. */
  grub_crypto_hash ((gcry_md_spec_t *) &_gcry_digest_spec_sha512,
                    &cert->fingerprint[GRUB_FINGERPRINT_SHA512], data, data_size);
}

/*
 * Parse a certificate whose DER-encoded form is in @data, of size @data_size.
 * Return the results in @results, which must point to an allocated x509
 * certificate.
 */
grub_err_t
grub_x509_cert_parse_der (const void *der_data, grub_int32_t der_data_size, grub_x509_cert_t *cert)
{
  grub_int32_t rc = 0;
  grub_err_t ret;
  asn1_node cert_asn1;

  if (cert == NULL || der_data == NULL || der_data_size == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "bad input data");

  if (der_data_size > GRUB_UINT_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       "cannot parse a certificate where data size > GRUB_UINT_MAX");

  rc = asn1_create_element (grub_gnutls_pkix_asn, "PKIX1.Certificate", &cert_asn1);
  if (rc != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       "could not create ASN.1 structure for certificate: %s",
                       asn1_strerror (rc));

  rc = asn1_der_decoding2 (&cert_asn1, der_data, &der_data_size, ASN1_DECODE_FLAG_STRICT_DER, asn1_error);
  if (rc != ASN1_SUCCESS)
    {
      ret = grub_error (GRUB_ERR_BAD_FILE_TYPE,
                        "could not parse DER for certificate: %s", asn1_error);
      goto exit;
    }

  /*
   * TBSCertificate  ::=  SEQUENCE {
   *     version         [0]  EXPLICIT Version DEFAULT v1
   */
  ret = x509_get_version (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * serialNumber         CertificateSerialNumber,
   *
   * CertificateSerialNumber  ::=  INTEGER
   */
  ret = x509_get_serial (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * signature            AlgorithmIdentifier,
   *
   * We don't load the signature or issuer at the moment,
   * as we don't attempt x509 verification.
   */
  /*
   * validity             Validity,
   *
   * Validity ::= SEQUENCE {
   *     notBefore      Time,
   *     notAfter       Time }
   *
   * We can't validate this reasonably, we have no true time source on several
   * platforms. For now we do not parse them.
   */

  /*
   * issuer              Name,
   *
   * This is an X501 name, we parse out just the issuer.
   */
  /*
   * subject              Name,
   *
   * This is an X501 name, we parse out just the CN.
   */
  ret = x509_get_issuer_and_subject (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto exit;

  /*
   * TBSCertificate  ::=  SEQUENCE  {
   *    ...
   *    subjectPublicKeyInfo SubjectPublicKeyInfo,
   *    ...
   */
  ret = x509_get_subject_public_key (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto cleanup_exit;

  /*
   * TBSCertificate  ::=  SEQUENCE  {
   *    ...
   *    extensions      [3]  EXPLICIT Extensions OPTIONAL
   *                         -- If present, version MUST be v3
   * }
   */
  ret = x509_get_extensions (cert_asn1, cert);
  if (ret != GRUB_ERR_NONE)
    goto cleanup_pk;

  /*
   * We do not read or check the signature on the certificate:
   * as discussed we do not try to validate the certificate but trust
   * it implictly.
   */
  asn1_delete_structure (&cert_asn1);

  /* Add the fingerprint of the certificate. */
  x509_add_cert_fingerprint (der_data, der_data_size, cert);

  return GRUB_ERR_NONE;

 cleanup_pk:
  _gcry_mpi_release (cert->spki.pk[GRUB_RSA_PK_MODULUS]);
  _gcry_mpi_release (cert->spki.pk[GRUB_RSA_PK_EXPONENT]);
 cleanup_exit:
  grub_free (cert->serial);
  grub_free (cert->issuer);
  grub_free (cert->subject);
 exit:
  asn1_delete_structure (&cert_asn1);

  return ret;
}

/*
 * Release all the storage associated with the x509 certificate. If the caller
 * dynamically allocated the certificate, it must free it. The caller is also
 * responsible for maintenance of the linked list.
 */
void
grub_x509_cert_release (grub_x509_cert_t *cert)
{
  if (cert == NULL)
    return;

  grub_free (cert->issuer);
  grub_free (cert->subject);
  grub_free (cert->serial);
  _gcry_mpi_release (cert->spki.pk[GRUB_RSA_PK_MODULUS]);
  _gcry_mpi_release (cert->spki.pk[GRUB_RSA_PK_EXPONENT]);
  grub_memset (cert, 0x00, sizeof (grub_x509_cert_t));
}

/* Release the allocated memory. */
void
grub_x509_cert_free (grub_x509_cert_t *cert)
{
  grub_free (cert);
}
