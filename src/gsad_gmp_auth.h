/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_gmp_auth.h
 * @brief Authentication GMP
 */

#ifndef _GSAD_GMP_AUTH_H
#define _GSAD_GMP_AUTH_H

#include <glib.h> /* for gchar */

int
authenticate_gmp (const gchar *, const gchar *, gchar **, gchar **, gchar **,
                  gchar **, gchar **, gchar **);

int
logout_gmp (const gchar *username, const gchar *password);

#endif /* _GSAD_GMP_AUTH_H */
