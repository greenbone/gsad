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
typedef struct user user_t;

user_t *
user_new ();

user_t *
user_new_with_data (const gchar *username, const gchar *password,
                    const gchar *timezone, const gchar *capabilities,
                    const gchar *language, const gchar *address,
                    const gchar *jwt);

void
user_free (user_t *user);

user_t *
user_copy (user_t *user);

void
user_set_timezone (user_t *user, const gchar *timezone);

void
user_set_username (user_t *user, const gchar *username);

void
user_set_password (user_t *user, const gchar *password);

void
user_set_language (user_t *user, const gchar *language);

const gchar *
user_get_username (user_t *user);

const gchar *
user_get_password (user_t *user);

const gchar *
user_get_language (user_t *user);

const gchar *
user_get_cookie (user_t *user);

const gchar *
user_get_token (user_t *user);

const gchar *
user_get_timezone (user_t *user);

const gchar *
user_get_client_address (user_t *user);

const gchar *
user_get_jwt (user_t *user);

const gchar *
user_get_capabilities (user_t *user);

time_t
user_get_time (user_t *user);

#endif /* _GSAD_USER_H_ */
