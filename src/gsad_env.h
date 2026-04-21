/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GSAD_ENV_H
#define _GSAD_ENV_H

#include <glib.h>

gboolean
gsad_env_get_boolean (const gchar *, gboolean);

gchar *
gsad_env_get_string (const gchar *, const gchar *);

gchar **
gsad_env_get_string_array (const gchar *, const gchar *, const gchar *);

int
gsad_env_get_int (const gchar *, int);

#endif /* _GSAD_ENV_H */
