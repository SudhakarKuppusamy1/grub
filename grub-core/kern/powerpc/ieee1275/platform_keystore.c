/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024  Free Software Foundation, Inc.
 *  Copyright (C) 2022, 2023, 2024, 2025 IBM Corporation
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

#include <grub/mm.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/lockdown.h>
#include <grub/ieee1275/ieee1275.h>
#include <grub/powerpc/ieee1275/ieee1275.h>
#include <grub/powerpc/ieee1275/platform_keystore.h>

#if __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

/* PKS consumer type for firmware. */
#define PKS_CONSUMER_FW      ((grub_uint8_t) 1)

/* The maximum object size interface name for a PKS object. */
#define PKS_MAX_OBJ_SIZE     ((grub_uint8_t *) "pks-max-object-size")

/* PKS read object lable for secure boot version. */
#define SB_VERSION_KEY_NAME  ((grub_uint8_t *) "SB_VERSION")
#define SB_VERSION_KEY_LEN   ((grub_size_t) 10)

/* PKS read secure boot variable request type for db and dbx. */
#define DB                   ((grub_uint8_t) 1)
#define DBX                  ((grub_uint8_t) 2)

static grub_size_t pks_max_object_size;

/*
 * Platform KeyStore db and dbx, pks_supported flag to indicate the availability
 * of PSK support and use_keystore flag to indicate the key management.
 *
 * pks_supported:
 * False: No PKS support. This is default.
 * True: PKS support available.
 *
 * use_keystore:
 * False: Static key management (use built-in Keys). This is default.
 * True: Dynamic key management (use Platform KeySotre).
 */
grub_pks_t grub_pks_keystore = { .db = NULL, .dbx = NULL, .db_entries = 0, .dbx_entries = 0,
                                 .use_keystore = false, .pks_supported = false};

/*
 * Import the Globally Unique Identifier (GUID), EFI Signature Database (ESD),
 * and its size into the PKS Signature Database (SD) (i.e pks_sd buffer) and pks_sd entries
 * from the EFI Signature List (ESL).
 */
static grub_err_t
_esl_to_esd (const grub_uint8_t *esl_data, grub_size_t esl_size,
             const grub_size_t signature_size, const grub_packed_guid_t *guid,
             grub_pks_sd_t **pks_sd, grub_uint32_t *pks_sd_entries)
{
  grub_esd_t *esd;
  grub_pks_sd_t *signature = *pks_sd;
  grub_uint32_t entries = *pks_sd_entries;
  grub_size_t data_size, offset = 0;

  /* Reads the ESD from ESL. */
  while (esl_size > 0)
    {
      esd = (grub_esd_t *) (esl_data + offset);
      data_size = signature_size - sizeof (grub_esd_t);

      signature = grub_realloc (signature, (entries + 1) * sizeof (grub_pks_sd_t));
      if (signature == NULL)
        return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

      signature[entries].data = grub_malloc (data_size * sizeof (grub_uint8_t));
      if (signature[entries].data == NULL)
        {
          /*
           * Allocated memory will be freed by
           * grub_free_platform_keystore.
           */
          *pks_sd = signature;
          *pks_sd_entries = entries + 1;
          return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
        }

      grub_memcpy (signature[entries].data, esd->signature_data, data_size);
      signature[entries].data_size = data_size;
      signature[entries].guid = *guid;
      entries++;
      esl_size -= signature_size;
      offset += signature_size;
    }

  *pks_sd = signature;
  *pks_sd_entries = entries;

  return GRUB_ERR_NONE;
}

/* Extract the ESD after removing the ESL header from ESL. */
static grub_err_t
esl_to_esd (const grub_uint8_t *esl_data, grub_size_t *next_esl,
            grub_pks_sd_t **pks_sd, grub_uint32_t *pks_sd_entries)
{
  grub_packed_guid_t guid;
  grub_esl_t *esl;
  grub_size_t offset, esl_size, signature_size, signature_header_size;

  /* Convert the ESL data into the ESL. */
  esl = (grub_esl_t *) esl_data;
  if (*next_esl < sizeof (grub_esl_t) || esl == NULL)
    return grub_error (GRUB_ERR_BUG, "invalid ESL");

  esl_size = grub_le_to_cpu32 (esl->signature_list_size);
  signature_header_size = grub_le_to_cpu32 (esl->signature_header_size);
  signature_size = grub_le_to_cpu32 (esl->signature_size);
  grub_memcpy (&guid, &esl->signature_type, sizeof (grub_packed_guid_t));

  if (esl_size < sizeof (grub_esl_t) || esl_size > *next_esl)
    return grub_error (GRUB_ERR_BUG, "invalid ESL size (%u)\n", esl_size);

  *next_esl = esl_size;
  offset = sizeof (grub_esl_t) + signature_header_size;
  esl_size = esl_size - offset;

  return _esl_to_esd (esl_data + offset, esl_size, signature_size, &guid,
                      pks_sd, pks_sd_entries);
}

/*
 * Import the EFI Signature Database (ESD) and the number of ESD from the ESL
 * into the pks_sd buffer and pks_sd entries.
 */
static grub_err_t
pks_sd_from_esl (const grub_uint8_t *esl_data, grub_size_t esl_size,
                 grub_pks_sd_t **pks_sd, grub_uint32_t *pks_sd_entries)
{
  grub_err_t rc;
  grub_size_t next_esl = esl_size;

  do
    {
      rc = esl_to_esd (esl_data, &next_esl, pks_sd, pks_sd_entries);
      if (rc != GRUB_ERR_NONE)
        break;

      esl_data += next_esl;
      esl_size -= next_esl;
      next_esl = esl_size;
    }
  while (esl_size > 0);

  return rc;
}

/*
 * Read the secure boot version from PKS as an object.
 * Caller must free result.
 */
static grub_err_t
read_sbversion_from_pks (grub_uint8_t **out, grub_uint32_t *outlen, grub_uint32_t *policy)
{
  grub_int32_t rc;

  *out = grub_malloc (pks_max_object_size);
  if (*out == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = grub_ieee1275_pks_read_object (PKS_CONSUMER_FW, SB_VERSION_KEY_NAME,
                                      SB_VERSION_KEY_LEN, pks_max_object_size, *out,
                                      outlen, policy);
  if (rc < 0)
    return grub_error (GRUB_ERR_READ_ERROR, "SB version read failed (%d)\n", rc);

  return GRUB_ERR_NONE;
}

/*
 * Reads the secure boot variable from PKS, unpacks it, read the ESD
 * from ESL, and store the information in the pks_sd buffer.
 */
static grub_err_t
read_sbvar_from_pks (const grub_uint8_t sbvarflags, const grub_uint8_t sbvartype,
                     grub_pks_sd_t **pks_sd, grub_uint32_t *pks_sd_entries)
{
  grub_int32_t rc;
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint8_t *esl_data = NULL;
  grub_size_t esl_data_size = 0;

  esl_data = grub_malloc (pks_max_object_size);
  if (esl_data == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");

  rc = grub_ieee1275_pks_read_sbvar (sbvarflags, sbvartype, pks_max_object_size,
                                     esl_data, &esl_data_size);
  if (rc == IEEE1275_CELL_NOT_FOUND)
    {
      err =  grub_error (GRUB_ERR_UNKNOWN_COMMAND, "secure boot variable %s not found (%d)",
                         ((sbvartype == DB) ? "db" : "dbx"), rc);
      goto clean;
    }
  else if (rc < 0)
    {
      err = grub_error (GRUB_ERR_READ_ERROR, "secure boot variable %s reading (%d)",
                        ((sbvartype == DB) ? "db" : "dbx"), rc);
      goto clean;
    }

  if (esl_data_size != 0)
    err = pks_sd_from_esl (esl_data, esl_data_size, pks_sd, pks_sd_entries);

 clean:
  grub_free (esl_data);

  return err;
}

/*
 * Test the availability of PKS support. If PKS support is avaialble and
 * objects present, it reads the secure boot version (SB_VERSION) from PKS.
 *
 * SB_VERSION: Key Management Mode
 * 1 - Enable dynamic key management mode. Read the db and dbx variables from PKS,
       and use them for signature verification.
 * 0 - Enable static key management mode. Read keys from the GRUB ELF Note and
 *     use it for signature verification.
 */
static grub_err_t
is_pks_present (void)
{
  grub_err_t err;
  grub_int32_t rc;
  grub_ieee1275_cell_t missing = 0;
  grub_uint8_t *data = NULL;
  grub_uint32_t len = 0, policy = 0;

  rc = grub_ieee1275_test (PKS_MAX_OBJ_SIZE, &missing);
  if (rc < 0 || missing == IEEE1275_CELL_INVALID)
    return  grub_error (GRUB_ERR_BAD_FIRMWARE, "firmware doesn't have PKS support\n");
  else
    {
      rc = grub_ieee1275_pks_max_object_size (&pks_max_object_size);
      if (rc < 0)
        return  grub_error (GRUB_ERR_BAD_NUMBER, "PKS support is there but it has zero objects\n");
    }

  grub_pks_keystore.pks_supported = true;

  err = read_sbversion_from_pks (&data, &len, &policy);
  if (err == GRUB_ERR_NONE && (len != 1 || (*data >= 2)))
    {
      grub_free (data);
      return grub_error (GRUB_ERR_BAD_NUMBER, "found unexpected SB version (%d)\n", *data);
    }
  else if (*data)
    grub_pks_keystore.use_keystore = true;

  grub_free (data);

  return err;
}

/* Free allocated memory. */
void
grub_pks_free_keystore (void)
{
  grub_size_t i;

  for (i = 0; i < grub_pks_keystore.db_entries; i++)
    grub_free (grub_pks_keystore.db[i].data);

  for (i = 0; i < grub_pks_keystore.dbx_entries; i++)
    grub_free (grub_pks_keystore.dbx[i].data);

  grub_free (grub_pks_keystore.db);
  grub_free (grub_pks_keystore.dbx);
  grub_memset (&grub_pks_keystore, 0, sizeof (grub_pks_t));
}

/* Initialization of the Platform KeyStore. */
grub_err_t
grub_pks_keystore_init (void)
{
  grub_err_t rc;

  grub_dprintf ("ieee1275", "trying to load Platform KeyStore\n");

  rc = is_pks_present ();
  if (rc != GRUB_ERR_NONE)
    {
      grub_dprintf ("ieee1275", "switch to static key\n");
      return rc;
    }

  if (grub_pks_keystore.pks_supported == true)
    {
      grub_memset (&grub_pks_keystore, 0, sizeof (grub_pks_t));
      /* Read db from PKS. */
      rc = read_sbvar_from_pks (0, DB, &grub_pks_keystore.db, &grub_pks_keystore.db_entries);
      if (rc == GRUB_ERR_NONE)
        {
          /* Read dbx from PKS. */
          rc = read_sbvar_from_pks (0, DBX, &grub_pks_keystore.dbx, &grub_pks_keystore.dbx_entries);
          if (rc == GRUB_ERR_UNKNOWN_COMMAND)
          rc = GRUB_ERR_NONE;
        }

      if (rc != GRUB_ERR_NONE)
        grub_pks_free_keystore ();
    }

  return rc;
}
