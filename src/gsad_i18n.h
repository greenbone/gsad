/* Copyright (C) 2015-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_i18n.h
 * @brief I18n support for Greenbone Security Assistant.
 */

#ifndef _GSAD_I18N_H
#define _GSAD_I18N_H

#include <glib.h>

/**
 * @brief Default language code, used when Accept-Language header is missing.
 */
#define DEFAULT_GSAD_LANGUAGE "en"

gchar *
accept_language_to_env_fmt (const char *);

#endif /* not _GSAD_I18N_H */
