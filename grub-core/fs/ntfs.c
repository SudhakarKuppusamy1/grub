/* ntfs.c - NTFS filesystem */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2007,2008,2009 Free Software Foundation, Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define grub_fshelp_node grub_ntfs_file

#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/fshelp.h>
#include <grub/ntfs.h>
#include <grub/charset.h>
#include <grub/lockdown.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_dl_t my_mod;

#define grub_fshelp_node grub_ntfs_file

static inline grub_uint16_t
u16at (void *ptr, grub_size_t ofs)
{
  return grub_le_to_cpu16 (grub_get_unaligned16 ((char *) ptr + ofs));
}

static inline grub_uint32_t
u32at (void *ptr, grub_size_t ofs)
{
  return grub_le_to_cpu32 (grub_get_unaligned32 ((char *) ptr + ofs));
}

static inline grub_uint64_t
u64at (void *ptr, grub_size_t ofs)
{
  return grub_le_to_cpu64 (grub_get_unaligned64 ((char *) ptr + ofs));
}

static grub_uint16_t
first_attr_off (void *mft_buf_ptr)
{
  return u16at (mft_buf_ptr, 0x14);
}

static grub_uint16_t
res_attr_data_off (void *res_attr_ptr)
{
  return u16at (res_attr_ptr, 0x14);
}

static grub_uint32_t
res_attr_data_len (void *res_attr_ptr)
{
  return u32at (res_attr_ptr, 0x10);
}

/*
 * Check if the attribute is valid and doesn't exceed the allocated region.
 * This accounts for resident and non-resident data.
 *
 * This is based off the documentation from the linux-ntfs project:
 * https://flatcap.github.io/linux-ntfs/ntfs/concepts/attribute_header.html
 */
static bool
validate_attribute (grub_uint8_t *attr, void *end)
{
  grub_size_t attr_size = 0;
  grub_size_t min_size = 0;
  grub_size_t run_size = 0;
  grub_size_t spare = (grub_uint8_t *) end - attr;
  /*
   * Just used as a temporary variable to try and deal with cases where someone
   * tries to overlap fields.
   */
  grub_size_t curr = 0;

  /* Need verify we can entirely read the attributes header. */
  if (attr + GRUB_NTFS_ATTRIBUTE_HEADER_SIZE >= (grub_uint8_t *) end)
    goto fail;

  /*
   * So, the rest of this code uses a 16bit int for the attribute length but
   * from reading the all the documentation I could find it says this field is
   * actually 32bit. But let's be consistent with the rest of the code.
   *
   * https://elixir.bootlin.com/linux/v6.10.7/source/fs/ntfs3/ntfs.h#L370
   */
  attr_size = u16at (attr, GRUB_NTFS_ATTRIBUTE_LENGTH);

  if (attr_size > spare)
    goto fail;

  /* Not an error case, just reached the end of the attributes. */
  if (attr_size == 0)
    return false;

  /*
   * Extra validation by trying to calculate a minimum possible size for this
   * attribute. +8 from the size of the resident data struct which is the
   * minimum that can be added.
   */
  min_size = GRUB_NTFS_ATTRIBUTE_HEADER_SIZE + 8;

  if (min_size > attr_size)
    goto fail;

  /* Is the data is resident (0) or not (1). */
  if (attr[GRUB_NTFS_ATTRIBUTE_RESIDENT] == 0)
    {
      /* Read the offset and size of the attribute. */
      curr = u16at (attr, GRUB_NTFS_ATTRIBUTE_RES_OFFSET);
      curr += u32at (attr, GRUB_NTFS_ATTRIBUTE_RES_LENGTH);
      if (curr > min_size)
	min_size = curr;
    }
  else
    {
      /*
       * If the data is non-resident, the minimum size is 64 which is where
       * the data runs start. We already have a minimum size of 24. So, just
       * adding 40 to get to the real value.
       */
      min_size += 40;
      if (min_size > attr_size)
	goto fail;
      /* If the compression unit size is > 0, +8 bytes*/
      if (u16at (attr, GRUB_NTFS_ATTRIBUTE_COMPRESSION_UNIT_SIZE) > 0)
	min_size += 8;

      /*
       * Need to consider the data runs now. Each member of the run has byte
       * that describes the size of the data length and offset. Each being
       * 4 bits in the byte.
       */
      curr = u16at (attr, GRUB_NTFS_ATTRIBUTE_DATA_RUNS);

      if (curr + 1 > min_size)
	min_size = curr + 1;

      if (min_size > attr_size)
	goto fail;

      /*
       * Each attribute can store multiple data runs which are stored
       * continuously in the attribute. They exist as one header byte
       * with up to 14 bytes following it depending on the lengths.
       * We stop when we hit a header that is just a NUL byte.
       *
       * https://flatcap.github.io/linux-ntfs/ntfs/concepts/data_runs.html
       */
      while (attr[curr] != 0)
	{
	  /*
	   * We stop when we hit a header that is just a NUL byte. The data
	   * run header is stored as a single byte where the top 4 bits refer
	   * to the number of bytes used to store the total length of the
	   * data run, and the number of bytes used to store the offset.
	   * These directly follow the header byte, so we use them to update
	   * the minimum size. Increment by one more than run size to move on
	   * to the next run size header byte. An example is a run size field
	   * value of 0x32, 3 + 2 = 5 bytes follow the run size. Increment
	   * by 5 to get to the end of this data run then one more to get to
	   * the start of the next run size byte.
	   */
	  run_size = (attr[curr] & 0x7) + ((attr[curr] >> 4) & 0x7);
	  curr += (run_size + 1);
	  min_size += (run_size + 1);
	  if (min_size > attr_size)
	    goto fail;
	}
    }

  /* Name offset, doing this after data residence checks. */
  if (u16at (attr, GRUB_NTFS_ATTRIBUTE_NAME_OFFSET) != 0)
    {
      curr = u16at (attr, GRUB_NTFS_ATTRIBUTE_NAME_OFFSET);
      /*
       * Multiple the name length by 2 as its UTF-16. Can be zero if this in an
       * unamed attribute.
       */
      curr += attr[GRUB_NTFS_ATTRIBUTE_NAME_LENGTH] * 2;
      if (curr > min_size)
	min_size = curr;
    }

  /* Padded to 8 bytes. */
  if (min_size % 8 != 0)
    min_size += 8 - (min_size % 8);

  /*
   * At this point min_size should be exactly attr_size but being flexible
   * here to avoid any issues.
   */
  if (min_size > attr_size)
    goto fail;

  return true;

 fail:
  grub_dprintf ("ntfs", "spare=%" PRIuGRUB_SIZE " min_size=%" PRIuGRUB_SIZE " attr_size=%" PRIuGRUB_SIZE "\n",
		spare, min_size, attr_size);
  return false;
}

/* Return the next attribute if it exists, otherwise return NULL. */
static grub_uint8_t *
next_attribute (grub_uint8_t *curr_attribute, void *end, bool validate)
{
  grub_uint8_t *next = curr_attribute;

  /*
   * Need to verify we aren't exceeding the end of the buffer by reading the
   * header for the current attribute
   */
  if (curr_attribute + GRUB_NTFS_ATTRIBUTE_HEADER_SIZE >= (grub_uint8_t *) end)
    return NULL;

  next += u16at (curr_attribute, 4);
  if (validate && validate_attribute (next, end) == false)
    return NULL;

  return next;
}


grub_ntfscomp_func_t grub_ntfscomp_func;

static grub_err_t
fixup (grub_uint8_t *buf, grub_size_t len, const grub_uint8_t *magic)
{
  grub_uint16_t ss;
  grub_uint8_t *pu;
  grub_uint16_t us;
  grub_uint16_t pu_offset;

  COMPILE_TIME_ASSERT ((1 << GRUB_NTFS_BLK_SHR) == GRUB_DISK_SECTOR_SIZE);

  if (grub_memcmp (buf, magic, 4))
    return grub_error (GRUB_ERR_BAD_FS, "%s label not found", magic);

  ss = u16at (buf, 6) - 1;
  if (ss != len)
    return grub_error (GRUB_ERR_BAD_FS, "size not match");
  pu_offset = u16at (buf, 4);
  if (pu_offset >= (len * GRUB_DISK_SECTOR_SIZE - (2 * ss)))
    return grub_error (GRUB_ERR_BAD_FS, "pu offset size incorrect");
  pu = buf + pu_offset;
  us = u16at (pu, 0);
  buf -= 2;
  while (ss > 0)
    {
      buf += GRUB_DISK_SECTOR_SIZE;
      pu += 2;
      if (u16at (buf, 0) != us)
	return grub_error (GRUB_ERR_BAD_FS, "fixup signature not match");
      buf[0] = pu[0];
      buf[1] = pu[1];
      ss--;
    }

  return 0;
}

static grub_err_t read_mft (struct grub_ntfs_data *data, grub_uint8_t *buf,
			    grub_uint64_t mftno);
static grub_err_t read_attr (struct grub_ntfs_attr *at, grub_uint8_t *dest,
			     grub_disk_addr_t ofs, grub_size_t len,
			     int cached,
			     grub_disk_read_hook_t read_hook,
			     void *read_hook_data);

static grub_err_t read_data (struct grub_ntfs_attr *at, grub_uint8_t *pa,
			     grub_uint8_t *dest,
			     grub_disk_addr_t ofs, grub_size_t len,
			     int cached,
			     grub_disk_read_hook_t read_hook,
			     void *read_hook_data);

static grub_err_t
init_attr (struct grub_ntfs_attr *at, struct grub_ntfs_file *mft)
{
  at->mft = mft;
  at->flags = (mft == &mft->data->mmft) ? GRUB_NTFS_AF_MMFT : 0;
  at->attr_nxt = mft->buf + first_attr_off (mft->buf);
  at->end = mft->buf + (mft->data->mft_size << GRUB_NTFS_BLK_SHR);

  if (at->attr_nxt > at->end)
    return grub_error (GRUB_ERR_BAD_FS, "attributes start outside the MFT");

  at->attr_end = at->emft_buf = at->edat_buf = at->sbuf = NULL;

  return GRUB_ERR_NONE;
}

static void
free_attr (struct grub_ntfs_attr *at)
{
  grub_free (at->emft_buf);
  grub_free (at->edat_buf);
  grub_free (at->sbuf);
}

static grub_uint8_t *
find_attr (struct grub_ntfs_attr *at, grub_uint8_t attr)
{
  grub_uint8_t *mft_end;
  grub_uint16_t nsize;
  grub_uint16_t nxt_offset;
  grub_uint32_t edat_offset;

  /* GRUB_NTFS_AF_ALST indicates the attribute list type */
  if (at->flags & GRUB_NTFS_AF_ALST)
    {
    retry:
      while (at->attr_nxt)
	{
	  at->attr_cur = at->attr_nxt;
	  /*
	   * Go to the next attribute in the list but do not validate
	   * because this is the attribute list type.
	   */
	  at->attr_nxt = next_attribute (at->attr_cur, at->attr_end, false);
	  if ((*at->attr_cur == attr) || (attr == 0))
	    {
	      grub_uint8_t *new_pos, *end;

	      if (at->flags & GRUB_NTFS_AF_MMFT)
		{
		  if ((grub_disk_read
		       (at->mft->data->disk, u32at (at->attr_cur, 0x10), 0,
			512, at->emft_buf))
		      ||
		      (grub_disk_read
		       (at->mft->data->disk, u32at (at->attr_cur, 0x14), 0,
			512, at->emft_buf + 512)))
		    return NULL;

		  if (fixup (at->emft_buf, at->mft->data->mft_size,
			     (const grub_uint8_t *) "FILE"))
		    return NULL;
		}
	      else
		{
		  if (read_mft (at->mft->data, at->emft_buf,
				u32at (at->attr_cur, 0x10)))
		    return NULL;
		}

	      /*
	       * Only time emft_bufs is defined is in this function, with this
	       * size.
	       */
	      grub_size_t emft_buf_size =
	        at->mft->data->mft_size << GRUB_NTFS_BLK_SHR;

	      /*
	       * Needs to be enough space for the successful case to even
	       * bother.
	       */
	      if (first_attr_off (at->emft_buf) >= (emft_buf_size - 0x18 - 2))
		{
		  grub_error (GRUB_ERR_BAD_FS,
			      "can\'t find 0x%X in attribute list",
			      (unsigned char) *at->attr_cur);
		  return NULL;
		}

	      new_pos = &at->emft_buf[first_attr_off (at->emft_buf)];
	      end = &at->emft_buf[emft_buf_size];
	      at->end = end;

	      while (new_pos && *new_pos != 0xFF)
		{
		  if ((*new_pos == *at->attr_cur)
		      && (u16at (new_pos, 0xE) == u16at (at->attr_cur, 0x18)))
		    {
		      return new_pos;
		    }
		    /*
		     * Go to the next attribute in the list but do not validate
		     * because this is the attribute list type.
		     */
		    new_pos = next_attribute (new_pos, end, false);
		}
	      grub_error (GRUB_ERR_BAD_FS,
			  "can\'t find 0x%X in attribute list",
			  (unsigned char) *at->attr_cur);
	      return NULL;
	    }
	}
      return NULL;
    }
  at->attr_cur = at->attr_nxt;
  mft_end = at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR);
  while (at->attr_cur >= at->mft->buf && at->attr_cur < (mft_end - 4)
         && *at->attr_cur != 0xFF)
    {
      /*
       * We can't use validate_attribute here because this logic
       * seems to be used for both parsing through attributes
       * and attribute lists.
       */
      nsize = u16at (at->attr_cur, 4);
      if (at->attr_cur + grub_max (GRUB_NTFS_ATTRIBUTE_HEADER_SIZE, nsize) >= at->end)
      {
        at->attr_nxt = at->attr_cur;
        break;
      }
      else
        at->attr_nxt = at->attr_cur + nsize;

      if (*at->attr_cur == GRUB_NTFS_AT_ATTRIBUTE_LIST)
	at->attr_end = at->attr_cur;
      if ((*at->attr_cur == attr) || (attr == 0) || (nsize == 0))
	return at->attr_cur;
      at->attr_cur = at->attr_nxt;
    }
  if (at->attr_end)
    {
      grub_uint8_t *pa, *pa_end;

      at->emft_buf = grub_malloc (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR);
      if (at->emft_buf == NULL)
	return NULL;

      pa = at->attr_end;
      if (pa[8])
	{
          grub_uint32_t n;

          n = ((u32at (pa, 0x30) + GRUB_DISK_SECTOR_SIZE - 1)
               & (~(GRUB_DISK_SECTOR_SIZE - 1)));
	  at->attr_cur = at->attr_end;
	  at->edat_buf = grub_malloc (n);
	  if (!at->edat_buf)
	    return NULL;
	  if (read_data (at, pa, at->edat_buf, 0, n, 0, 0, 0))
	    {
	      grub_error (GRUB_ERR_BAD_FS,
			  "fail to read non-resident attribute list");
	      return NULL;
	    }
	  at->attr_nxt = at->edat_buf;
	  edat_offset = u32at (pa, 0x30);
	  if (edat_offset >= n)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "edat offset is out of bounds");
	      return NULL;
	    }
	  at->attr_end = at->edat_buf + edat_offset;
	  pa_end = at->edat_buf + n;
	}
      else
	{
	  at->attr_nxt = at->attr_end + res_attr_data_off (pa);
	  edat_offset = u32at (pa, 4);
	  if ((at->attr_end + edat_offset) >= (at->end))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "edat offset is out of bounds");
	      return NULL;
	    }
	  at->attr_end = at->attr_end + edat_offset;
	  pa_end = at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR);
	}
      at->flags |= GRUB_NTFS_AF_ALST;

      /* From this point on pa_end is the end of the buffer */
      at->end = pa_end;

      if (at->attr_end >= pa_end || at->attr_nxt >= pa_end)
        return NULL;

      while (at->attr_nxt)
	{
	  if ((*at->attr_nxt == attr) || (attr == 0))
	    break;

	  nxt_offset = u16at (at->attr_nxt, 4);
	  at->attr_nxt += nxt_offset;

	  /*
	   * Stop and set attr_nxt to NULL when either the next offset is zero,
	   * or when the pointer is within four bytes of the end of the buffer
	   * since we could attempt to access attr_nxt + 4 bytes offset above to
	   * get the next 16-bit 'nxt_offset' value.
	   */
	  if (nxt_offset == 0 || at->attr_nxt >= (pa_end - 4))
	    at->attr_nxt = NULL;
	}

      if ((at->attr_nxt + GRUB_NTFS_ATTRIBUTE_HEADER_SIZE) >= at->attr_end || at->attr_nxt == NULL)
	return NULL;

      if ((at->flags & GRUB_NTFS_AF_MMFT) && (attr == GRUB_NTFS_AT_DATA))
	{
	  at->flags |= GRUB_NTFS_AF_GPOS;
	  at->attr_cur = at->attr_nxt;
	  pa = at->attr_cur;

	  if ((pa >= pa_end) || (pa_end - pa < 0x18))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "can\'t parse attribute list");
	      return NULL;
	    }

	  grub_set_unaligned32 ((char *) pa + 0x10,
				grub_cpu_to_le32 (at->mft->data->mft_start));
	  grub_set_unaligned32 ((char *) pa + 0x14,
				grub_cpu_to_le32 (at->mft->data->mft_start
						  + 1));
	  pa = at->attr_nxt + u16at (pa, 4);

	  if (pa >= pa_end)
	    pa = NULL;

	  while (pa)
	    {
	      if (*pa != attr)
		break;

              if ((pa >= pa_end) || (pa_end - pa < 0x18))
                {
	          grub_error (GRUB_ERR_BAD_FS, "can\'t parse attribute list");
	          return NULL;
	        }

	      if (read_attr
		  (at, pa + 0x10,
		   u32at (pa, 0x10) * (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR),
		   at->mft->data->mft_size << GRUB_NTFS_BLK_SHR, 0, 0, 0))
		return NULL;
	      pa += u16at (pa, 4);
	      if (pa >= pa_end)
	        pa = NULL;
	    }
	  at->attr_nxt = at->attr_cur;
	  at->flags &= ~GRUB_NTFS_AF_GPOS;
	}
      goto retry;
    }
  return NULL;
}

static grub_uint8_t *
locate_attr (struct grub_ntfs_attr *at, struct grub_ntfs_file *mft,
	     grub_uint8_t attr)
{
  grub_uint8_t *pa;
  grub_uint8_t *last_pa;

  if (init_attr (at, mft) != GRUB_ERR_NONE)
    return NULL;

  pa = find_attr (at, attr);
  if (pa == NULL)
    return NULL;
  if ((at->flags & GRUB_NTFS_AF_ALST) == 0)
    {
      /* Used to make sure we're not stuck in a loop. */
      last_pa = NULL;
      while (1)
	{
	  pa = find_attr (at, attr);
	  if (pa == NULL || pa == last_pa)
	    break;
	  if (at->flags & GRUB_NTFS_AF_ALST)
	    return pa;
	  last_pa = pa;
	}
      grub_errno = GRUB_ERR_NONE;
      free_attr (at);
      if (init_attr (at, mft) != GRUB_ERR_NONE)
	return NULL;
      pa = find_attr (at, attr);
    }
  return pa;
}

static grub_disk_addr_t
read_run_data (const grub_uint8_t *run, int nn, int sig)
{
  grub_uint64_t r = 0;

  if (sig && nn && (run[nn - 1] & 0x80))
    r = -1;

  grub_memcpy (&r, run, nn);

  return grub_le_to_cpu64 (r);
}

grub_err_t
grub_ntfs_read_run_list (struct grub_ntfs_rlst * ctx)
{
  grub_uint8_t c1, c2;
  grub_disk_addr_t val;
  grub_uint8_t *run;

  run = ctx->cur_run;
retry:
  c1 = ((*run) & 0x7);
  c2 = ((*run) >> 4) & 0x7;
  run++;
  if (!c1)
    {
      if ((ctx->attr) && (ctx->attr->flags & GRUB_NTFS_AF_ALST))
	{
	  grub_disk_read_hook_t save_hook;

	  save_hook = ctx->comp.disk->read_hook;
	  ctx->comp.disk->read_hook = 0;
	  run = find_attr (ctx->attr, *ctx->attr->attr_cur);
	  ctx->comp.disk->read_hook = save_hook;
	  if (run)
	    {
	      if (run[8] == 0)
		return grub_error (GRUB_ERR_BAD_FS,
				   "$DATA should be non-resident");

	      run += u16at (run, 0x20);
	      ctx->curr_lcn = 0;
	      goto retry;
	    }
	}
      return grub_error (GRUB_ERR_BAD_FS, "run list overflow");
    }
  ctx->curr_vcn = ctx->next_vcn;
  ctx->next_vcn += read_run_data (run, c1, 0);	/* length of current VCN */
  run += c1;
  val = read_run_data (run, c2, 1);	/* offset to previous LCN */
  run += c2;
  ctx->curr_lcn += val;
  if (val == 0)
    ctx->flags |= GRUB_NTFS_RF_BLNK;
  else
    ctx->flags &= ~GRUB_NTFS_RF_BLNK;
  ctx->cur_run = run;
  return 0;
}

static grub_disk_addr_t
grub_ntfs_read_block (grub_fshelp_node_t node, grub_disk_addr_t block)
{
  struct grub_ntfs_rlst *ctx;

  ctx = (struct grub_ntfs_rlst *) node;
  if (block >= ctx->next_vcn)
    {
      if (grub_ntfs_read_run_list (ctx))
	return -1;
      return ctx->curr_lcn;
    }
  else
    return (ctx->flags & GRUB_NTFS_RF_BLNK) ? 0 : (block -
					 ctx->curr_vcn + ctx->curr_lcn);
}

static grub_err_t
read_data (struct grub_ntfs_attr *at, grub_uint8_t *pa, grub_uint8_t *dest,
	   grub_disk_addr_t ofs, grub_size_t len, int cached,
	   grub_disk_read_hook_t read_hook, void *read_hook_data)
{
  struct grub_ntfs_rlst cc, *ctx;
  grub_uint8_t *end_ptr = (pa + len);
  grub_uint16_t run_offset;

  if (len == 0)
    return 0;

  grub_memset (&cc, 0, sizeof (cc));
  ctx = &cc;
  ctx->attr = at;
  ctx->comp.log_spc = at->mft->data->log_spc;
  ctx->comp.disk = at->mft->data->disk;

  if (read_hook == grub_file_progress_hook)
    ctx->file = read_hook_data;

  if (pa[8] == 0)
    {
      if (ofs + len > res_attr_data_len (pa))
	return grub_error (GRUB_ERR_BAD_FS, "read out of range");

      if (res_attr_data_len (pa) > (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR))
	return grub_error (GRUB_ERR_BAD_FS, "resident attribute too large");

      if (pa >= at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR))
	return grub_error (GRUB_ERR_BAD_FS, "resident attribute out of range");

      if (res_attr_data_off (pa) + res_attr_data_len (pa) >
	  (grub_addr_t) at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR) - (grub_addr_t) pa)
	return grub_error (GRUB_ERR_BAD_FS, "resident attribute out of range");

      grub_memcpy (dest, pa + res_attr_data_off (pa) + ofs, len);
      return 0;
    }

  run_offset = u16at (pa, 0x20);
  if ((run_offset + pa) >= end_ptr || ((run_offset + pa) >= (at->end)))
      return grub_error (GRUB_ERR_BAD_FS, "run offset out of range");

  ctx->cur_run = pa + run_offset;

  ctx->next_vcn = u32at (pa, 0x10);
  ctx->curr_lcn = 0;

  if ((pa[0xC] & GRUB_NTFS_FLAG_COMPRESSED)
      && !(at->flags & GRUB_NTFS_AF_GPOS))
    {
      if (!cached)
	return grub_error (GRUB_ERR_BAD_FS, "attribute can\'t be compressed");

      return (grub_ntfscomp_func) ? grub_ntfscomp_func (dest, ofs, len, ctx)
	: grub_error (GRUB_ERR_BAD_FS, N_("module `%s' isn't loaded"),
		      "ntfscomp");
    }

  ctx->target_vcn = ofs >> (GRUB_NTFS_BLK_SHR + ctx->comp.log_spc);
  while (ctx->next_vcn <= ctx->target_vcn)
    {
      if (grub_ntfs_read_run_list (ctx))
	return grub_errno;
    }

  if (at->flags & GRUB_NTFS_AF_GPOS)
    {
      grub_disk_addr_t st0, st1;
      grub_uint64_t m;

      m = (ofs >> GRUB_NTFS_BLK_SHR) & ((1 << ctx->comp.log_spc) - 1);

      st0 =
	((ctx->target_vcn - ctx->curr_vcn + ctx->curr_lcn) << ctx->comp.log_spc) + m;
      st1 = st0 + 1;
      if (st1 ==
	  (ctx->next_vcn - ctx->curr_vcn + ctx->curr_lcn) << ctx->comp.log_spc)
	{
	  if (grub_ntfs_read_run_list (ctx))
	    return grub_errno;
	  st1 = ctx->curr_lcn << ctx->comp.log_spc;
	}
      grub_set_unaligned32 (dest, grub_cpu_to_le32 (st0));
      grub_set_unaligned32 (dest + 4, grub_cpu_to_le32 (st1));
      return 0;
    }

  grub_fshelp_read_file (ctx->comp.disk, (grub_fshelp_node_t) ctx,
			 read_hook, read_hook_data, ofs, len,
			 (char *) dest,
			 grub_ntfs_read_block, ofs + len,
			 ctx->comp.log_spc, 0);
  return grub_errno;
}

static grub_err_t
read_attr (struct grub_ntfs_attr *at, grub_uint8_t *dest, grub_disk_addr_t ofs,
	   grub_size_t len, int cached,
	   grub_disk_read_hook_t read_hook, void *read_hook_data)
{
  grub_uint8_t *save_cur;
  grub_uint8_t attr;
  grub_uint8_t *pp;
  grub_err_t ret;

  if (at == NULL || at->attr_cur == NULL)
    return grub_error (GRUB_ERR_BAD_FS, "attribute not found");
  save_cur = at->attr_cur;
  at->attr_nxt = at->attr_cur;
  attr = *at->attr_nxt;
  if (at->flags & GRUB_NTFS_AF_ALST)
    {
      grub_uint8_t *pa;
      grub_disk_addr_t vcn;

      /* If compression is possible make sure that we include possible
	 compressed block size.  */
      if (GRUB_NTFS_LOG_COM_SEC >= at->mft->data->log_spc)
	vcn = ((ofs >> GRUB_NTFS_COM_LOG_LEN)
	       << (GRUB_NTFS_LOG_COM_SEC - at->mft->data->log_spc)) & ~0xFULL;
      else
	vcn = ofs >> (at->mft->data->log_spc + GRUB_NTFS_BLK_SHR);
      pa = at->attr_nxt + u16at (at->attr_nxt, 4);
      if (validate_attribute (pa, at->attr_end) == false)
	pa = NULL;

      while (pa)
	{
	  if (*pa != attr)
	    break;
	  if (u32at (pa, 8) > vcn)
	    break;
	  at->attr_nxt = pa;
	  pa = next_attribute (pa, at->attr_end, true);
	}
    }
  pp = find_attr (at, attr);
  if (pp)
    ret = read_data (at, pp, dest, ofs, len, cached,
		     read_hook, read_hook_data);
  else
    ret =
      (grub_errno) ? grub_errno : grub_error (GRUB_ERR_BAD_FS,
					      "attribute not found");
  at->attr_cur = save_cur;
  return ret;
}

static grub_err_t
read_mft (struct grub_ntfs_data *data, grub_uint8_t *buf, grub_uint64_t mftno)
{
  if (read_attr
      (&data->mmft.attr, buf, mftno * ((grub_disk_addr_t) data->mft_size << GRUB_NTFS_BLK_SHR),
       data->mft_size << GRUB_NTFS_BLK_SHR, 0, 0, 0))
    return grub_error (GRUB_ERR_BAD_FS, "read MFT 0x%llx fails", (unsigned long long) mftno);
  return fixup (buf, data->mft_size, (const grub_uint8_t *) "FILE");
}

static grub_err_t
init_file (struct grub_ntfs_file *mft, grub_uint64_t mftno)
{
  unsigned short flag;

  mft->inode_read = 1;

  mft->buf = grub_malloc (mft->data->mft_size << GRUB_NTFS_BLK_SHR);
  if (mft->buf == NULL)
    return grub_errno;

  if (read_mft (mft->data, mft->buf, mftno))
    return grub_errno;

  flag = u16at (mft->buf, 0x16);
  if ((flag & 1) == 0)
    return grub_error (GRUB_ERR_BAD_FS, "MFT 0x%llx is not in use",
		       (unsigned long long) mftno);

  if ((flag & 2) == 0)
    {
      grub_uint8_t *pa;

      pa = locate_attr (&mft->attr, mft, GRUB_NTFS_AT_DATA);
      if (pa == NULL)
	return grub_error (GRUB_ERR_BAD_FS, "no $DATA in MFT 0x%llx",
			   (unsigned long long) mftno);

      if (!pa[8])
	mft->size = res_attr_data_len (pa);
      else
	mft->size = u64at (pa, 0x30);

      if ((mft->attr.flags & GRUB_NTFS_AF_ALST) == 0)
	mft->attr.attr_end = 0;	/*  Don't jump to attribute list */
    }
  else
    return init_attr (&mft->attr, mft);

  return 0;
}

static void
free_file (struct grub_ntfs_file *mft)
{
  if (mft)
  {
    free_attr (&mft->attr);
    grub_free (mft->buf);
  }
}

static char *
get_utf8 (grub_uint8_t *in, grub_size_t len)
{
  grub_uint8_t *buf;
  grub_uint16_t *tmp;
  grub_size_t i;

  buf = grub_calloc (len, GRUB_MAX_UTF8_PER_UTF16 + 1);
  tmp = grub_calloc (len, sizeof (tmp[0]));
  if (!buf || !tmp)
    {
      grub_free (buf);
      grub_free (tmp);
      return NULL;
    }
  for (i = 0; i < len; i++)
    tmp[i] = grub_le_to_cpu16 (grub_get_unaligned16 (in + 2 * i));
  *grub_utf16_to_utf8 (buf, tmp, len) = '\0';
  grub_free (tmp);
  return (char *) buf;
}

static int
list_file (struct grub_ntfs_file *diro, grub_uint8_t *pos, grub_uint8_t *end_pos,
	   grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
  grub_uint8_t *np;
  int ns;
  grub_uint16_t pos_incr;

  while (1)
    {
      grub_uint8_t namespace;
      char *ustr;

      if ((pos >= end_pos) || (end_pos - pos < 0x52))
        break;

      if (pos[0xC] & 2)		/* end signature */
	break;

      np = pos + 0x50;
      ns = *(np++);
      namespace = *(np++);

      if (2 * ns > end_pos - pos - 0x52)
        break;

      /*
       *  Ignore files in DOS namespace, as they will reappear as Win32
       *  names.
       */
      if ((ns) && (namespace != 2))
	{
	  enum grub_fshelp_filetype type;
	  struct grub_ntfs_file *fdiro;
	  grub_uint32_t attr;

	  attr = u32at (pos, 0x48);
	  if (attr & GRUB_NTFS_ATTR_REPARSE)
	    type = GRUB_FSHELP_SYMLINK;
	  else if (attr & GRUB_NTFS_ATTR_DIRECTORY)
	    type = GRUB_FSHELP_DIR;
	  else
	    type = GRUB_FSHELP_REG;

	  fdiro = grub_zalloc (sizeof (struct grub_ntfs_file));
	  if (!fdiro)
	    return 0;

	  fdiro->data = diro->data;
	  fdiro->ino = u64at (pos, 0) & 0xffffffffffffULL;
	  fdiro->mtime = u64at (pos, 0x20);

	  ustr = get_utf8 (np, ns);
	  if (ustr == NULL)
	    {
	      grub_free (fdiro);
	      return 0;
	    }
          if (namespace)
            type |= GRUB_FSHELP_CASE_INSENSITIVE;

	  if (hook (ustr, type, fdiro, hook_data))
	    {
	      grub_free (ustr);
	      return 1;
	    }

	  grub_free (ustr);
	}
	pos_incr = u16at (pos, 8);
	if (pos_incr > 0)
	  pos += pos_incr;
	else
	  return 0;

    }
  return 0;
}

struct symlink_descriptor
{
  grub_uint32_t type;
  grub_uint32_t total_len;
  grub_uint16_t off1;
  grub_uint16_t len1;
  grub_uint16_t off2;
  grub_uint16_t len2;
} GRUB_PACKED;

static char *
grub_ntfs_read_symlink (grub_fshelp_node_t node)
{
  struct grub_ntfs_file *mft;
  struct symlink_descriptor symdesc;
  grub_err_t err;
  grub_uint8_t *buf16 = NULL;
  char *buf, *end;
  grub_size_t len;
  grub_uint8_t *pa;
  grub_size_t off;

  mft = (struct grub_ntfs_file *) node;

  mft->buf = grub_malloc (mft->data->mft_size << GRUB_NTFS_BLK_SHR);
  if (mft->buf == NULL)
    return NULL;

  if (read_mft (mft->data, mft->buf, mft->ino))
    goto fail;

  pa = locate_attr (&mft->attr, mft, GRUB_NTFS_AT_SYMLINK);
  if (pa == NULL)
    {
      grub_error (GRUB_ERR_BAD_FS, "no $SYMLINK in MFT 0x%llx",
		  (unsigned long long) mft->ino);
      goto fail;
    }

  err = read_attr (&mft->attr, (grub_uint8_t *) &symdesc, 0,
		   sizeof (struct symlink_descriptor), 1, 0, 0);
  if (err)
    goto fail;

  switch (grub_cpu_to_le32 (symdesc.type))
    {
    case 0xa000000c:
      off = (sizeof (struct symlink_descriptor) + 4
	     + grub_cpu_to_le32 (symdesc.off1));
      len = grub_cpu_to_le32 (symdesc.len1);
      break;
    case 0xa0000003:
      off = (sizeof (struct symlink_descriptor)
	     + grub_cpu_to_le32 (symdesc.off1));
      len = grub_cpu_to_le32 (symdesc.len1);
      break;
    default:
      grub_error (GRUB_ERR_BAD_FS, "symlink type invalid (%x)",
		  grub_cpu_to_le32 (symdesc.type));
      goto fail;
    }

  buf16 = grub_malloc (len);
  if (!buf16)
    goto fail;

  err = read_attr (&mft->attr, buf16, off, len, 1, 0, 0);
  if (err)
    goto fail;

  buf = get_utf8 (buf16, len / 2);
  if (!buf)
    goto fail;

  grub_free (mft->buf);
  grub_free (buf16);

  for (end = buf; *end; end++)
    if (*end == '\\')
      *end = '/';

  /* Split the sequence to avoid GCC thinking that this is a trigraph.  */
  if (grub_memcmp (buf, "/?" "?/", 4) == 0 && buf[5] == ':' && buf[6] == '/'
      && grub_isalpha (buf[4]))
    {
      grub_memmove (buf, buf + 6, end - buf + 1 - 6);
      end -= 6;
    }
  return buf;

 fail:
  grub_free (mft->buf);
  grub_free (buf16);
  return NULL;
}

static int
grub_ntfs_iterate_dir (grub_fshelp_node_t dir,
		       grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
  grub_uint8_t *bitmap;
  struct grub_ntfs_attr attr, *at;
  grub_uint8_t *cur_pos, *indx, *bmp;
  int ret = 0;
  grub_size_t bitmap_len;
  struct grub_ntfs_file *mft;
  /* Used to make sure we're not stuck in a loop. */
  grub_uint8_t *last_pos = NULL;
  grub_uint32_t tmp_len;

  mft = (struct grub_ntfs_file *) dir;

  if (!mft->inode_read)
    {
      if (init_file (mft, mft->ino))
	return 0;
    }

  indx = NULL;
  bmp = NULL;

  at = &attr;
  if (init_attr (at, mft) != GRUB_ERR_NONE)
    return 0;

  while (1)
    {
      cur_pos = find_attr (at, GRUB_NTFS_AT_INDEX_ROOT);
      if (cur_pos == NULL || cur_pos == last_pos)
	{
	  grub_error (GRUB_ERR_BAD_FS, "no $INDEX_ROOT");
	  goto done;
	}
      last_pos = cur_pos;

      /* Resident, Namelen=4, Offset=0x18, Flags=0x00, Name="$I30" */
      if ((u32at (cur_pos, 8) != 0x180400) ||
	  (u32at (cur_pos, 0x18) != 0x490024) ||
	  (u32at (cur_pos, 0x1C) != 0x300033))
	continue;
      cur_pos += res_attr_data_off (cur_pos);
      if(cur_pos >= at->end)
        continue;
      if (*cur_pos != 0x30)	/* Not filename index */
	continue;
      break;
    }

  cur_pos += 0x10;		/* Skip index root */
  ret = list_file (mft, cur_pos + u16at (cur_pos, 0),
                   at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR),
                   hook, hook_data);
  if (ret)
    goto done;

  bitmap = NULL;
  bitmap_len = 0;
  free_attr (at);
  /* No need to check errors here, as it will already be fine */
  init_attr (at, mft);

  last_pos = NULL;
  while ((cur_pos = find_attr (at, GRUB_NTFS_AT_BITMAP)) != NULL)
    {
      int ofs;

      if (cur_pos == last_pos)
      {
        grub_error (GRUB_ERR_BAD_FS, "bitmap attribute loop");
        goto done;
      }
      last_pos = cur_pos;

      ofs = cur_pos[0xA];
      /* Namelen=4, Name="$I30" */
      if ((cur_pos[9] == 4) &&
	  (u32at (cur_pos, ofs) == 0x490024) &&
	  (u32at (cur_pos, ofs + 4) == 0x300033))
	{
          int is_resident = (cur_pos[8] == 0);

          bitmap_len = ((is_resident) ? res_attr_data_len (cur_pos) :
                        u32at (cur_pos, 0x28));

          bmp = grub_malloc (bitmap_len);
          if (bmp == NULL)
            goto done;

	  if (is_resident)
	    {
              if (bitmap_len > (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR))
		{
		  grub_error (GRUB_ERR_BAD_FS, "resident bitmap too large");
		  goto done;
		}

              if (cur_pos >= at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR))
		{
		  grub_error (GRUB_ERR_BAD_FS, "resident bitmap out of range");
		  goto done;
		}

              if (res_attr_data_off (cur_pos) + res_attr_data_len (cur_pos) >
		  (grub_addr_t) at->mft->buf + (at->mft->data->mft_size << GRUB_NTFS_BLK_SHR) - (grub_addr_t) cur_pos)
		{
		  grub_error (GRUB_ERR_BAD_FS, "resident bitmap out of range");
		  goto done;
		}

              grub_memcpy (bmp, cur_pos + res_attr_data_off (cur_pos),
                           bitmap_len);
	    }
          else
            {
              if (read_data (at, cur_pos, bmp, 0, bitmap_len, 0, 0, 0))
                {
                  grub_error (GRUB_ERR_BAD_FS,
                              "fails to read non-resident $BITMAP");
                  goto done;
                }
                tmp_len = u32at (cur_pos, 0x30);
                if (tmp_len <= bitmap_len)
                  bitmap_len = tmp_len;
                else
                {
                  grub_error (GRUB_ERR_BAD_FS,
                    "bitmap len too large for non-resident $BITMAP");
                  goto done;
                }
            }

          bitmap = bmp;
	  break;
	}
    }

  free_attr (at);
  last_pos = NULL;
  cur_pos = locate_attr (at, mft, GRUB_NTFS_AT_INDEX_ALLOCATION);
  while (cur_pos != NULL)
    {
      /* Non-resident, Namelen=4, Offset=0x40, Flags=0, Name="$I30" */
      if ((u32at (cur_pos, 8) == 0x400401) &&
	  (u32at (cur_pos, 0x40) == 0x490024) &&
	  (u32at (cur_pos, 0x44) == 0x300033))
	break;
      cur_pos = find_attr (at, GRUB_NTFS_AT_INDEX_ALLOCATION);
      if (cur_pos == last_pos)
        break;
      last_pos = cur_pos;
    }

  if ((!cur_pos) && (bitmap))
    {
      grub_error (GRUB_ERR_BAD_FS, "$BITMAP without $INDEX_ALLOCATION");
      goto done;
    }

  if (bitmap)
    {
      grub_disk_addr_t i;
      grub_uint8_t v;

      indx = grub_malloc (mft->data->idx_size << GRUB_NTFS_BLK_SHR);
      if (indx == NULL)
	goto done;

      v = 1;
      for (i = 0; i < (grub_disk_addr_t)bitmap_len * 8; i++)
	{
	  if (*bitmap & v)
	    {
	      if ((read_attr
		   (at, indx, i * (mft->data->idx_size << GRUB_NTFS_BLK_SHR),
		    (mft->data->idx_size << GRUB_NTFS_BLK_SHR), 0, 0, 0))
		  || (fixup (indx, mft->data->idx_size,
			     (const grub_uint8_t *) "INDX")))
		goto done;
	      ret = list_file (mft, &indx[0x18 + u16at (indx, 0x18)],
			       indx + (mft->data->idx_size << GRUB_NTFS_BLK_SHR),
			       hook, hook_data);
	      if (ret)
		goto done;
	    }
	  v <<= 1;
	  if (!v)
	    {
	      v = 1;
	      bitmap++;
	    }
	}
    }

done:
  free_attr (at);
  grub_free (indx);
  grub_free (bmp);

  return ret;
}

static struct grub_ntfs_data *
grub_ntfs_mount (grub_disk_t disk)
{
  struct grub_ntfs_bpb bpb;
  struct grub_ntfs_data *data = 0;
  grub_uint32_t spc;

  if (!disk)
    goto fail;

  data = (struct grub_ntfs_data *) grub_zalloc (sizeof (*data));
  if (!data)
    goto fail;

  data->disk = disk;

  /* Read the BPB.  */
  if (grub_disk_read (disk, 0, 0, sizeof (bpb), &bpb))
    goto fail;

  if (grub_memcmp ((char *) &bpb.oem_name, "NTFS", 4) != 0
      || bpb.sectors_per_cluster == 0
      || (bpb.sectors_per_cluster & (bpb.sectors_per_cluster - 1)) != 0
      || bpb.bytes_per_sector == 0
      || (bpb.bytes_per_sector & (bpb.bytes_per_sector - 1)) != 0)
    goto fail;

  spc = (((grub_uint32_t) bpb.sectors_per_cluster
	  * (grub_uint32_t) grub_le_to_cpu16 (bpb.bytes_per_sector))
	 >> GRUB_NTFS_BLK_SHR);
  if (spc == 0)
    goto fail;

  for (data->log_spc = 0; (1U << data->log_spc) < spc; data->log_spc++);

  if (bpb.clusters_per_mft > 0)
    data->mft_size = ((grub_disk_addr_t) bpb.clusters_per_mft) << data->log_spc;
  else if (-bpb.clusters_per_mft < GRUB_NTFS_BLK_SHR || -bpb.clusters_per_mft >= 31)
    goto fail;
  else
    data->mft_size = 1ULL << (-bpb.clusters_per_mft - GRUB_NTFS_BLK_SHR);

  if (bpb.clusters_per_index > 0)
    data->idx_size = (((grub_disk_addr_t) bpb.clusters_per_index)
		      << data->log_spc);
  else if (-bpb.clusters_per_index < GRUB_NTFS_BLK_SHR || -bpb.clusters_per_index >= 31)
    goto fail;
  else
    data->idx_size = 1ULL << (-bpb.clusters_per_index - GRUB_NTFS_BLK_SHR);

  data->mft_start = grub_le_to_cpu64 (bpb.mft_lcn) << data->log_spc;

  if ((data->mft_size > GRUB_NTFS_MAX_MFT) || (data->idx_size > GRUB_NTFS_MAX_IDX))
    goto fail;

  data->mmft.data = data;
  data->cmft.data = data;

  data->mmft.buf = grub_malloc (data->mft_size << GRUB_NTFS_BLK_SHR);
  if (!data->mmft.buf)
    goto fail;

  if (grub_disk_read
      (disk, data->mft_start, 0, data->mft_size << GRUB_NTFS_BLK_SHR, data->mmft.buf))
    goto fail;

  data->uuid = grub_le_to_cpu64 (bpb.num_serial);

  if (fixup (data->mmft.buf, data->mft_size, (const grub_uint8_t *) "FILE"))
    goto fail;

  if (!locate_attr (&data->mmft.attr, &data->mmft, GRUB_NTFS_AT_DATA))
    goto fail;

  if (init_file (&data->cmft, GRUB_NTFS_FILE_ROOT))
    goto fail;

  return data;

fail:
  grub_error (GRUB_ERR_BAD_FS, "not an ntfs filesystem");

  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }
  return 0;
}

/* Context for grub_ntfs_dir.  */
struct grub_ntfs_dir_ctx
{
  grub_fs_dir_hook_t hook;
  void *hook_data;
};

/* Helper for grub_ntfs_dir.  */
static int
grub_ntfs_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
		    grub_fshelp_node_t node, void *data)
{
  struct grub_ntfs_dir_ctx *ctx = data;
  struct grub_dirhook_info info;

  grub_memset (&info, 0, sizeof (info));
  info.dir = ((filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR);
  info.mtimeset = 1;
  info.mtime = grub_divmod64 (node->mtime, 10000000, 0)
    - 86400ULL * 365 * (1970 - 1601)
    - 86400ULL * ((1970 - 1601) / 4) + 86400ULL * ((1970 - 1601) / 100);
  grub_free (node);
  return ctx->hook (filename, &info, ctx->hook_data);
}

static grub_err_t
grub_ntfs_dir (grub_device_t device, const char *path,
	       grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_ntfs_dir_ctx ctx = { hook, hook_data };
  struct grub_ntfs_data *data = 0;
  struct grub_fshelp_node *fdiro = 0;

  grub_dl_ref (my_mod);

  data = grub_ntfs_mount (device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (path, &data->cmft, &fdiro, grub_ntfs_iterate_dir,
			 grub_ntfs_read_symlink, GRUB_FSHELP_DIR);

  if (grub_errno)
    goto fail;

  grub_ntfs_iterate_dir (fdiro, grub_ntfs_dir_iter, &ctx);

fail:
  if ((fdiro) && (fdiro != &data->cmft))
    {
      free_file (fdiro);
      grub_free (fdiro);
    }
  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ntfs_open (grub_file_t file, const char *name)
{
  struct grub_ntfs_data *data = 0;
  struct grub_fshelp_node *mft = 0;

  grub_dl_ref (my_mod);

  data = grub_ntfs_mount (file->device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file (name, &data->cmft, &mft, grub_ntfs_iterate_dir,
			 grub_ntfs_read_symlink, GRUB_FSHELP_REG);

  if (grub_errno)
    goto fail;

  if (mft != &data->cmft)
    {
      free_file (&data->cmft);
      grub_memcpy (&data->cmft, mft, sizeof (*mft));
      grub_free (mft);
      if (!data->cmft.inode_read)
	{
	  if (init_file (&data->cmft, data->cmft.ino))
	    goto fail;
	}
    }

  file->size = data->cmft.size;
  file->data = data;
  file->offset = 0;

  return 0;

fail:
  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_ssize_t
grub_ntfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_ntfs_file *mft;

  mft = &((struct grub_ntfs_data *) file->data)->cmft;
  if (file->read_hook)
    mft->attr.save_pos = 1;

  read_attr (&mft->attr, (grub_uint8_t *) buf, file->offset, len, 1,
	     file->read_hook, file->read_hook_data);
  return (grub_errno) ? -1 : (grub_ssize_t) len;
}

static grub_err_t
grub_ntfs_close (grub_file_t file)
{
  struct grub_ntfs_data *data;

  data = file->data;

  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ntfs_label (grub_device_t device, char **label)
{
  struct grub_ntfs_data *data = 0;
  struct grub_fshelp_node *mft = 0;
  grub_uint8_t *pa;
  grub_err_t err;

  grub_dl_ref (my_mod);

  *label = 0;

  data = grub_ntfs_mount (device->disk);
  if (!data)
    goto fail;

  grub_fshelp_find_file ("/$Volume", &data->cmft, &mft, grub_ntfs_iterate_dir,
			 0, GRUB_FSHELP_REG);

  if (grub_errno)
    goto fail;

  if (!mft->inode_read)
    {
      mft->buf = grub_malloc (mft->data->mft_size << GRUB_NTFS_BLK_SHR);
      if (mft->buf == NULL)
	goto fail;

      if (read_mft (mft->data, mft->buf, mft->ino))
	goto fail;
    }

  err = init_attr (&mft->attr, mft);
  if (err != GRUB_ERR_NONE)
    return err;

  pa = find_attr (&mft->attr, GRUB_NTFS_AT_VOLUME_NAME);

  if (pa == NULL || pa >= mft->buf + (mft->data->mft_size << GRUB_NTFS_BLK_SHR))
    {
      grub_error (GRUB_ERR_BAD_FS, "can\'t parse volume label");
      goto fail;
    }

  if (mft->buf + (mft->data->mft_size << GRUB_NTFS_BLK_SHR) - pa < 0x16)
    {
      grub_error (GRUB_ERR_BAD_FS, "can\'t parse volume label");
      goto fail;
    }

  if ((pa) && (pa[8] == 0) && (res_attr_data_len (pa)))
    {
      int len;

      len = res_attr_data_len (pa) / 2;
      pa += res_attr_data_off (pa);
      if (mft->buf + (mft->data->mft_size << GRUB_NTFS_BLK_SHR) - pa >= 2 * len &&
          pa >= mft->buf && (pa + len < (mft->buf + (mft->data->mft_size << GRUB_NTFS_BLK_SHR))))
        *label = get_utf8 (pa, len);
      else
        grub_error (GRUB_ERR_BAD_FS, "can\'t parse volume label");
    }

fail:
  if ((mft) && (mft != &data->cmft))
    {
      free_file (mft);
      grub_free (mft);
    }
  if (data)
    {
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }

  grub_dl_unref (my_mod);

  return grub_errno;
}

static grub_err_t
grub_ntfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_ntfs_data *data;
  grub_disk_t disk = device->disk;

  grub_dl_ref (my_mod);

  data = grub_ntfs_mount (disk);
  if (data)
    {
      char *ptr;
      *uuid = grub_xasprintf ("%016llx", (unsigned long long) data->uuid);
      if (*uuid)
	for (ptr = *uuid; *ptr; ptr++)
	  *ptr = grub_toupper (*ptr);
      free_file (&data->mmft);
      free_file (&data->cmft);
      grub_free (data);
    }
  else
    *uuid = NULL;

  grub_dl_unref (my_mod);

  return grub_errno;
}

static struct grub_fs grub_ntfs_fs =
  {
    .name = "ntfs",
    .fs_dir = grub_ntfs_dir,
    .fs_open = grub_ntfs_open,
    .fs_read = grub_ntfs_read,
    .fs_close = grub_ntfs_close,
    .fs_label = grub_ntfs_label,
    .fs_uuid = grub_ntfs_uuid,
#ifdef GRUB_UTIL
    .reserved_first_sector = 1,
    .blocklist_install = 1,
#endif
    .next = 0
};

GRUB_MOD_INIT (ntfs)
{
  if (!grub_is_lockdown ())
    {
      grub_ntfs_fs.mod = mod;
      grub_fs_register (&grub_ntfs_fs);
    }
  my_mod = mod;
}

GRUB_MOD_FINI (ntfs)
{
  if (!grub_is_lockdown ())
    grub_fs_unregister (&grub_ntfs_fs);
}
