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

typedef struct gsad_credentials gsad_credentials_t;

gsad_credentials_t *
gsad_credentials_new (user_t *user, const gchar *language);

void
gsad_credentials_free (gsad_credentials_t *creds);

user_t *
gsad_credentials_get_user (gsad_credentials_t *creds);

const gchar *
gsad_credentials_get_language (gsad_credentials_t *creds);

void
gsad_credentials_start_cmd (gsad_credentials_t *creds);

double
gsad_credentials_get_cmd_duration (gsad_credentials_t *creds);

#endif /* _GSAD_CREDENTIALS_H */
