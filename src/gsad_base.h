/* Greenbone Security Assistant
 * $Id$
 * Description: Headers/structs used generally in GSA
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

/**
 * @file gsad_base.h
 * @brief Headers/structs used generally in GSA.
 */

#ifndef _GSAD_BASE_H
#define _GSAD_BASE_H

#include <glib.h>

/** @brief Answer for invalid input. */
#define GSAD_MESSAGE_INVALID_PARAM(op)                                            \
  "<gsad_msg status_text=\"Invalid parameter\" operation=\"" op "\">"             \
  "At least one entered value contains invalid characters or exceeds"             \
  " a size limit.  You may use the Back button of your browser to adjust"         \
  " the entered values.  If in doubt, the online help of the respective section"  \
  " will lead you to the appropriate help page."                                  \
  "</gsad_msg>"

/**
 *  @brief Structure of credential related information.
 */
typedef struct
{
  char *username;  ///< Name of user.
  char *password;  ///< User's password.
  char *token;     ///< Session token.
  char *caller;    ///< Caller URL, for POST relogin.
} credentials_t;

/**
 * @brief Config preference.
 */
typedef struct
{
  gchar *name;     ///< Name of preference.
  gchar *nvt;      ///< ID of NVT.
  void *value;     ///< Value of preference.
  int value_size;  ///< Size of value.
} preference_t;

/**
 * @brief Method data parameters.
 */
struct method_data_param
{
  gchar *key;             /* Key. */
  gchar *value;           /* Binary value. */
  gsize value_size;       /* Size of value. */
};

/**
 * @brief Method data parameter type.
 */
typedef struct method_data_param method_data_param_t;

int gsad_base_init ();
char *ctime_r_strip_newline (time_t *, char *);
char * xsl_transform (const char *);
char * gsad_message (credentials_t *, const char *, const char *, int,
                     const char *, const char *);

/**
 * @brief Content types.
 */
enum content_type
{
  GSAD_CONTENT_TYPE_APP_DEB,
  GSAD_CONTENT_TYPE_APP_EXE,
  GSAD_CONTENT_TYPE_APP_HTML,
  GSAD_CONTENT_TYPE_APP_KEY,
  GSAD_CONTENT_TYPE_APP_NBE,
  GSAD_CONTENT_TYPE_APP_PDF,
  GSAD_CONTENT_TYPE_APP_RPM,
  GSAD_CONTENT_TYPE_APP_XML,
  GSAD_CONTENT_TYPE_DONE,         ///< Special marker.
  GSAD_CONTENT_TYPE_IMAGE_PNG,
  GSAD_CONTENT_TYPE_TEXT_CSS,
  GSAD_CONTENT_TYPE_TEXT_HTML,
  GSAD_CONTENT_TYPE_TEXT_PLAIN,
  GSAD_CONTENT_TYPE_OCTET_STREAM
} ;


/* Params. */

#define params_t GHashTable

/**
 * @brief Request parameter.
 */
struct param
{
  int valid;             /* Validation flag. */
  gchar *value;          /* Value. */
  int value_size;        /* Size of value, excluding trailing NULL. */
  params_t *values;      /* Multiple binary values. */
};

/**
 * @brief Request parameter.
 */
typedef struct param param_t;

params_t *params_new ();

void params_free (params_t *);

const char *params_value (params_t *, const char *);

params_t *params_values (params_t *, const char *);

param_t *params_get (params_t *, const char *);

int params_valid (params_t *, const char *);

param_t *params_add (params_t *, const char *, const char *);

param_t *params_append_bin (params_t *, const char *, const char *, int, int);

#define params_iterator_t GHashTableIter

#define params_iterator_init g_hash_table_iter_init

gboolean params_iterator_next (params_iterator_t *, char **, param_t **);

#endif /* not _GSAD_BASE_H */
