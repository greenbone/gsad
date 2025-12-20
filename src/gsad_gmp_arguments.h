/* Copyright (C) 2019-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef _GSAD_GMP_ARGUMENTS_H
#define _GSAD_GMP_ARGUMENTS_H

#include <glib.h>

typedef GHashTable gmp_arguments_t;

gmp_arguments_t *
gmp_arguments_new ();

void
gmp_arguments_free (gmp_arguments_t *);

void
gmp_arguments_add (gmp_arguments_t *, const char *, const char *);

gchar *
gmp_arguments_string (gmp_arguments_t *);

gboolean
gmp_arguments_has (gmp_arguments_t *, const gchar *);

#endif
