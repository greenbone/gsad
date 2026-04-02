/* Copyright (C) 2016-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_user_session.h
 * @brief GSAD user session handling
 */

#ifndef _GSAD_USER_SESSION_H
#define _GSAD_USER_SESSION_H

#include "gsad_user.h"

int
user_logout (user_t *user);

int
user_find (const gchar *cookie, const gchar *token, const char *address,
           user_t **user_return);

user_t *
user_add (const gchar *username, const gchar *password, const gchar *timezone,
          const gchar *capabilities, const gchar *language, const char *address,
          const gchar *jwt);

gboolean
user_session_expired (user_t *user);

const time_t
user_get_session_timeout (user_t *user);

void
user_renew_session (user_t *user);

#endif /* _GSAD_USER_SESSION_H */
