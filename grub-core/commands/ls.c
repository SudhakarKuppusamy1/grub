/* ls.c - command to list files and devices */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2005,2007,2008,2009  Free Software Foundation, Inc.
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
#include <grub/disk.h>
#include <grub/device.h>
#include <grub/term.h>
#include <grub/partition.h>
#include <grub/file.h>
#include <grub/normal.h>
#include <grub/extcmd.h>
#include <grub/datetime.h>
#include <grub/i18n.h>
#include <grub/net.h>

GRUB_MOD_LICENSE ("GPLv3+");

static const struct grub_arg_option options[] =
  {
    {"long", 'l', 0, N_("Show a long list with more detailed information."), 0, 0},
    {"human-readable", 'h', 0, N_("Print sizes in a human readable format."), 0, 0},
    {"all", 'a', 0, N_("List all files."), 0, 0},
    {0, 0, 0, 0, 0, 0}
  };

/* Helper for grub_ls_list_devices.  */
static int
grub_ls_print_devices (const char *name, void *data)
{
  int *longlist = data;

  if (*longlist)
    grub_normal_print_device_info (name);
  else
    grub_printf ("(%s) ", name);

  return 0;
}

static grub_err_t
grub_ls_list_devices (int longlist)
{
  grub_device_iterate (grub_ls_print_devices, &longlist);
  grub_xputs ("\n");

#if 0
  {
    grub_net_app_level_t proto;
    int first = 1;
    FOR_NET_APP_LEVEL (proto)
    {
      if (first)
	grub_puts_ (N_("Network protocols:"));
      first = 0;
      grub_printf ("%s ", proto->name);
    }
    grub_xputs ("\n");
  }
#endif

  grub_refresh ();

  return 0;
}

/* Context for grub_ls_list_files.  */
struct grub_ls_list_files_ctx
{
  char *dirname;
  char *filename;
  int all;
  int human;
  int longlist;
  int print_dirhdr;
};

/* Helper for grub_ls_list_files.  */
static int
print_file (const char *filename, const struct grub_dirhook_info *info,
		  void *data)
{
  char *pathname = NULL;
  struct grub_ls_list_files_ctx *ctx = data;

  if ((! ctx->all) && (filename[0] == '.'))
    return 0;

  if ((ctx->filename != NULL) && (grub_strcmp (filename, ctx->filename) != 0))
    return 0;

  if (ctx->print_dirhdr)
    {
      grub_printf ("%s:\n", ctx->dirname);
      ctx->print_dirhdr = 0;
    }

  if (! ctx->longlist)
    {
      if (ctx->filename != NULL)
	grub_xputs (ctx->dirname);
      grub_printf ("%s%s ", filename, info->dir ? "/" : "");
      return 0;
    }

  if (! info->dir)
    {
      grub_file_t file;

      if (ctx->dirname[grub_strlen (ctx->dirname) - 1] == '/')
	pathname = grub_xasprintf ("%s%s", ctx->dirname, filename);
      else
	pathname = grub_xasprintf ("%s/%s", ctx->dirname, filename);

      if (!pathname)
	return 1;

      /* XXX: For ext2fs symlinks are detected as files while they
	 should be reported as directories.  */
      file = grub_file_open (pathname, GRUB_FILE_TYPE_GET_SIZE
			     | GRUB_FILE_TYPE_NO_DECOMPRESS);
      if (file)
	{
	  if (! ctx->human)
	    grub_printf ("%-12llu", (unsigned long long) file->size);
	  else
	    grub_printf ("%-12s", grub_get_human_size (file->size,
						   GRUB_HUMAN_SIZE_SHORT));
	  grub_file_close (file);
	}
      else
	grub_xputs ("????????????");

      grub_errno = GRUB_ERR_NONE;
    }
  else
    grub_printf ("%-12s", _("DIR"));

  if (info->mtimeset)
    {
      struct grub_datetime datetime;
      grub_unixtime2datetime (info->mtime, &datetime);
      if (ctx->human)
	grub_printf (" %d-%02d-%02d %02d:%02d:%02d %-11s ",
		     datetime.year, datetime.month, datetime.day,
		     datetime.hour, datetime.minute,
		     datetime.second,
		     grub_get_weekday_name (&datetime));
      else
	grub_printf (" %04d%02d%02d%02d%02d%02d ",
		     datetime.year, datetime.month,
		     datetime.day, datetime.hour,
		     datetime.minute, datetime.second);
    }
  /*
   * Only print the full path when listing a file path given as an argument
   * to ls, i.e. when ctx->filename != NULL. File listings that are printed
   * due to showing the contents of a directory do not need a full path because
   * the full path to the directory will have already been printed.
   */
  grub_printf ("%s%s\n", (ctx->filename != NULL) ? pathname : filename,
			 info->dir ? "/" : "");

  grub_free (pathname);

  return 0;
}

static grub_err_t
grub_ls_list_files (char *dirname, int longlist, int all, int human, int dirhdr)
{
  char *device_name;
  grub_fs_t fs;
  const char *path;
  grub_device_t dev;

  device_name = grub_file_get_device_name (dirname);
  dev = grub_device_open (device_name);
  if (! dev)
    goto fail;

  fs = grub_fs_probe (dev);
  path = grub_strchr (dirname, ')');
  if (! path)
    path = dirname;
  else
    path++;

  if (! path && ! device_name)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid argument");
      goto fail;
    }

  if (! *path && device_name)
    {
      if (grub_errno == GRUB_ERR_UNKNOWN_FS)
	grub_errno = GRUB_ERR_NONE;

#ifdef GRUB_MACHINE_IEEE1275
      /*
       * Close device to prevent a double open in grub_normal_print_device_info().
       * Otherwise it may lead to hangs on some IEEE 1275 platforms.
       */
      grub_device_close (dev);
      dev = NULL;
#endif

      grub_normal_print_device_info (device_name);
    }
  else if (fs)
    {
      struct grub_ls_list_files_ctx ctx = {
	.dirname = dirname,
	.filename = NULL,
	.all = all,
	.human = human,
	.longlist = longlist,
	.print_dirhdr = dirhdr
      };

      (fs->fs_dir) (dev, path, print_file, &ctx);

      if (grub_errno == GRUB_ERR_BAD_FILE_TYPE
	  && path[grub_strlen (path) - 1] != '/')
	{
	  /*
	   * Reset errno as it is currently set, but will cause subsequent code
	   * to think there is an error.
	   */
	  grub_errno = GRUB_ERR_NONE;

	  /* PATH might be a regular file.  */
	  ctx.print_dirhdr = 0;
	  ctx.filename = grub_strrchr (dirname, '/');
	  if (ctx.filename == NULL)
	    goto fail;
	  ++(ctx.filename);

	  ctx.dirname = grub_strndup (dirname, ctx.filename - dirname);
	  if (ctx.dirname == NULL)
	    goto fail;

	  (fs->fs_dir) (dev, ctx.dirname + (path - dirname), print_file, &ctx);

	  grub_free (ctx.dirname);
	}

      if (grub_errno == GRUB_ERR_NONE)
	grub_xputs ("\n");

      grub_refresh ();
    }

 fail:
  if (dev)
    grub_device_close (dev);

  grub_free (device_name);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_ls (grub_extcmd_context_t ctxt, int argc, char **args)
{
  struct grub_arg_list *state = ctxt->state;
  int i;

  if (argc == 0)
    grub_ls_list_devices (state[0].set);
  else
    for (i = 0; i < argc; i++)
      grub_ls_list_files (args[i], state[0].set, state[2].set, state[1].set,
			  argc > 1);

  return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(ls)
{
  cmd = grub_register_extcmd ("ls", grub_cmd_ls, 0,
			      N_("[-l|-h|-a] [FILE ...]"),
			      N_("List devices and files."), options);
}

GRUB_MOD_FINI(ls)
{
  grub_unregister_extcmd (cmd);
}
