/* Copyright (C) 2018-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_credentials.h
 * @brief GSAD credentials handling
 */

#ifndef _GSAD_CREDENTIALS_H
#define _GSAD_CREDENTIALS_H

#include "gsad_user.h"

#include <glib.h>

typedef struct credentials credentials_t;

credentials_t *
credentials_new (user_t *user, const gchar *language);

void
credentials_free (credentials_t *creds);

user_t *
credentials_get_user (credentials_t *creds);

const gchar *
credentials_get_current_page (credentials_t *creds);

const gchar *
credentials_get_language (credentials_t *creds);

void
credentials_start_cmd (credentials_t *creds);

double
credentials_get_cmd_duration (credentials_t *creds);

#endif /* _GSAD_CREDENTIALS_H */
