#ifndef __PLATFORM_KEYSTORE_H__
#define __PLATFORM_KEYSTORE_H__

#include <grub/symbol.h>
#include <grub/mm.h>
#include <grub/types.h>

#if __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

#define GRUB_UUID_SIZE 16
#define GRUB_MAX_HASH_SIZE 64

typedef struct grub_uuid grub_uuid_t;
typedef struct grub_esd grub_esd_t;
typedef struct grub_esl grub_esl_t;

/* The structure of a UUID.*/
struct grub_uuid
{
  grub_uint8_t b[GRUB_UUID_SIZE];
};

/* The structure of an EFI signature database (ESD).*/
struct grub_esd
{
  /*
   * An identifier which identifies the agent which added
   * the signature to the list.
   */
  grub_uuid_t signatureowner;
  /* The format of the signature is defined by the SignatureType.*/
  grub_uint8_t signaturedata[];
} GRUB_PACKED;

/* The structure of an EFI signature list (ESL).*/
struct grub_esl
{
  /* Type of the signature. GUID signature types are defined in below.*/
  grub_uuid_t signaturetype;
  /* Total size of the signature list, including this header.*/
  grub_uint32_t signaturelistsize;
  /*
   * Size of the signature header which precedes
   * the array of signatures.
   */
  grub_uint32_t signatureheadersize;
  /* Size of each signature.*/
  grub_uint32_t signaturesize;
} GRUB_PACKED;

/*
 * The GRUB_PKS_CERT_* is derived from the following files referred from edk2-staging[1] repo
 * of tianocore
 *
 * MdePkg/Include/Guid/ImageAuthentication.h
 *
 * [1] https://github.com/tianocore/edk2-staging
 */

#define GRUB_PKS_CERT_X509_GUID            \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94,  \
      0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15,  \
      0x5c, 0x2b, 0xf0, 0x72               \
    }                                      \
  }

#define GRUB_PKS_CERT_SHA1_GUID            \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x12, 0xa5, 0x6c, 0x82, 0x10, 0xcf,  \
      0xc9, 0x4a, 0xb1, 0x87, 0xbe, 0x1,   \
      0x49, 0x66, 0x31, 0xbd               \
    }                                      \
  }

#define GRUB_PKS_CERT_SHA224_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x33, 0x52, 0x6e, 0xb, 0x5c, 0xa6,   \
      0xc9, 0x44, 0x94, 0x7, 0xd9, 0xab,   \
      0x83, 0xbf, 0xc8, 0xbd               \
    }                                      \
  }

#define GRUB_PKS_CERT_SHA256_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50,  \
      0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9,  \
      0x36, 0x93, 0x43, 0x28               \
    }                                      \
  }

#define GRUB_PKS_CERT_SHA384_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x07, 0x53, 0x3e, 0xff, 0xd0, 0x9f,  \
      0xc9, 0x48, 0x85, 0xf1, 0x8a, 0xd5,  \
      0x6c, 0x70, 0x1e, 0x1                \
    }                                      \
  }

#define GRUB_PKS_CERT_SHA512_GUID          \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0xae, 0x0f, 0x3e, 0x09, 0xc4, 0xa6,  \
      0x50, 0x4f, 0x9f, 0x1b, 0xd4, 0x1e,  \
      0x2b, 0x89, 0xc1, 0x9a               \
    }                                      \
  }

#define GRUB_PKS_CERT_X509_SHA256_GUID     \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x92, 0xa4, 0xd2, 0x3b, 0xc0, 0x96,  \
      0x79, 0x40, 0xb4, 0x20, 0xfc, 0xf9,  \
      0x8e, 0xf1, 0x03, 0xed               \
    }                                      \
  }

#define GRUB_PKS_CERT_X509_SHA384_GUID     \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x6e, 0x87, 0x76, 0x70, 0xc2, 0x80,  \
      0xe6, 0x4e, 0xaa, 0xd2, 0x28, 0xb3,  \
      0x49, 0xa6, 0x86, 0x5b               \
    }                                      \
  }

#define GRUB_PKS_CERT_X509_SHA512_GUID     \
  (grub_uuid_t)                            \
  {                                        \
    {                                      \
      0x63, 0xbf, 0x6d, 0x44, 0x02, 0x25,  \
      0xda, 0x4c, 0xbc, 0xfa, 0x24, 0x65,  \
      0xd2, 0xb0, 0xfe, 0x9d               \
    }                                      \
  }

typedef struct grub_pks_sd grub_pks_sd_t;
typedef struct grub_pks grub_pks_t;

/* The structure of a PKS signature data.*/
struct grub_pks_sd
{
  grub_uuid_t guid;      /* signature type */
  grub_uint8_t *data;    /* signature data */
  grub_size_t data_size; /* size of signature data */
} GRUB_PACKED;

/* The structure of a PKS.*/
struct grub_pks
{
  grub_uint8_t use_static_keys;
  grub_pks_sd_t *db;        /* signature database */
  grub_pks_sd_t *dbx;       /* forbidden signature database */
  grub_size_t db_entries;   /* size of signature database */
  grub_size_t dbx_entries;  /* size of forbidden signature database */
} GRUB_PACKED;

#ifdef __powerpc__

/* initialization of the Platform Keystore */
grub_err_t grub_platform_keystore_init (void);
/* releasing allocated memory */
void EXPORT_FUNC(grub_release_platform_keystore) (void);
extern grub_uint8_t EXPORT_VAR(grub_use_platform_keystore);
extern grub_pks_t EXPORT_VAR(grub_platform_keystore);

#else

#define grub_use_platform_keystore	0
grub_pks_t grub_platform_keystore = {0, NULL, NULL, 0, 0};
void grub_release_platform_keystore (void);

#endif

#endif
