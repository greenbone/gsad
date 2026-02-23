/* Copyright (C) 2009-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_base.c
 * @brief Base functionality of GSA.
 */

#include "gsad_base.h"

#include "gsad_params.h"

#include <glib.h>
#include <libxml/parser.h> /* for xmlHasFeature() */
#include <string.h>        /* for strlen() */
#include <sys/param.h>
#ifndef __FreeBSD__
#include <malloc.h>
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad base"

/**
 * @brief The chroot state: 0 = no chroot, 1 = chroot used
 */
static int chroot_state = 0;

/**
 * @brief Base init.
 *
 * @return 0 success, 1 XML needs thread support.
 */
int
gsad_base_init ()
{
  if (!xmlHasFeature (XML_WITH_THREAD))
    return 1;
  /* Required by libxml for thread safety. */
  xmlInitParser ();
  return 0;
}

/**
 * @brief Base init.
 *
 * @return 0 success, -1 error.
 */
int
gsad_base_cleanup ()
{
  xmlCleanupParser ();
  return 0;
}

/**
 * @brief Sets the chroot state.
 *
 * @param[in]  state The new chroot state.
 */
void
set_chroot_state (int state)
{
  chroot_state = state;
}

/**
 * @brief Return string from ctime_r with newline replaces with terminator.
 *
 * @param[in]  time    Time.
 * @param[out] string  Time string.
 *
 * @return Return from ctime_r applied to time, with newline stripped off.
 */
char *
ctime_r_strip_newline (time_t *time, char *string)
{
  struct tm tm;

  if (localtime_r (time, &tm) == NULL
      || (strftime (string, 199, "%c %Z", &tm) == 0))
    {
      string[0] = '\0';
      return string;
    }
  return string;
}
