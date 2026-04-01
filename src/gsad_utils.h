/* Copyright (C) 2018-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file utils.h
 * @brief Headers/structs for utility functions in GSAD
 */

#ifndef _GSAD_UTILS_H
#define _GSAD_UTILS_H

#include <glib.h> // for gboolean, gchar

gboolean
str_equal (const gchar *, const gchar *);

gchar *
capitalize (const char *);

gboolean
credential_username_is_valid (const gchar *);

#endif /* not _GSAD_UTILS_H */
