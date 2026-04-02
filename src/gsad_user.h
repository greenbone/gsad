/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_user.h
 * @brief GSAD user handling
 */

#ifndef _GSAD_USER_H
#define _GSAD_USER_H

#include "gsad_params.h"

#include <glib.h>

#define USER_OK 0
#define USER_BAD_TOKEN 1
#define USER_EXPIRED_TOKEN 2
#define USER_BAD_MISSING_COOKIE 3
#define USER_BAD_MISSING_TOKEN 4
#define USER_GMP_DOWN 6
#define USER_IP_ADDRESS_MISSMATCH 7

/**
 * @brief User information type, for sessions.
 */
typedef struct gsad_user gsad_user_t;

gsad_user_t *
gsad_user_new ();

gsad_user_t *
gsad_user_new_with_data (const gchar *username, const gchar *password,
                         const gchar *timezone, const gchar *capabilities,
                         const gchar *language, const gchar *address,
                         const gchar *jwt);

void
gsad_user_free (gsad_user_t *user);

gsad_user_t *
gsad_user_copy (gsad_user_t *user);

void
gsad_user_set_timezone (gsad_user_t *user, const gchar *timezone);

void
gsad_user_set_username (gsad_user_t *user, const gchar *username);

void
gsad_user_set_password (gsad_user_t *user, const gchar *password);

void
gsad_user_set_language (gsad_user_t *user, const gchar *language);

const gchar *
gsad_user_get_username (gsad_user_t *user);

const gchar *
gsad_user_get_password (gsad_user_t *user);

const gchar *
gsad_user_get_language (gsad_user_t *user);

const gchar *
gsad_user_get_cookie (gsad_user_t *user);

const gchar *
gsad_user_get_token (gsad_user_t *user);

const gchar *
gsad_user_get_timezone (gsad_user_t *user);

const gchar *
gsad_user_get_client_address (gsad_user_t *user);

const gchar *
gsad_user_get_jwt (gsad_user_t *user);

const gchar *
gsad_user_get_capabilities (gsad_user_t *user);

time_t
gsad_user_get_time (gsad_user_t *user);

#endif /* _GSAD_USER_H_ */
