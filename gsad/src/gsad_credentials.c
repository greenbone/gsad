/* Greenbone Security Assistant
 *
 * Description: GSAD credentials handling
 *
 * Authors:
 * Björn Ricks <bjoern.ricks@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>

#include "gsad_credentials.h"
#include "gsad_user.h"

/**
 *  @brief Structure of credential related information.
 */
struct credentials
{
  struct timeval cmd_start; ///< Seconds since command page handler started.
  gchar *caller;            ///< Caller URL, for POST relogin.
  gchar *current_page;      ///< Current page URL, for refresh.
  gchar *language;          ///< Language for this request
  user_t *user;             ///< Current user
};

credentials_t *
credentials_new (user_t *user,
                 const gchar *language,
                 const gchar *caller)
{
  credentials_t *credentials;

  credentials = g_malloc0 (sizeof (credentials_t));
  credentials->user = user_copy (user);
  credentials->language = g_strdup (language);
  credentials->caller = g_strdup (caller);

  return credentials;
}

void
credentials_free (credentials_t *creds)
{
  if (!creds)
    return;

  g_free (creds->caller);
  g_free (creds->current_page);
  g_free (creds->language);

  user_free (creds->user);

  g_free (creds);
}

user_t *
credentials_get_user (credentials_t *cred)
{
  return cred->user;
}

const gchar *
credentials_get_caller (credentials_t *cred)
{
  return cred->caller;
}

const gchar *
credentials_get_current_page (credentials_t *cred)
{
  return cred->current_page;
}

const gchar *
credentials_get_language (credentials_t *cred)
{
  return cred->language;
}

void
credentials_start_cmd (credentials_t *creds)
{
  gettimeofday (&creds->cmd_start, NULL);
}

double
credentials_get_cmd_duration (credentials_t *cred)
{
  struct timeval tv;
  gettimeofday (&tv, NULL);
  return ((double) ((tv.tv_sec - cred->cmd_start.tv_sec) * 1000000L
                    + tv.tv_usec - cred->cmd_start.tv_usec) / 1000000.0);
}