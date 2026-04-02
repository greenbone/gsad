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

void
gsad_user_session_logout (gsad_user_t *user);

int
gsad_user_session_find (const gchar *cookie, const gchar *token,
                        const char *address, gsad_user_t **user_return);

gsad_user_t *
gsad_user_session_add (const gchar *username, const gchar *password,
                       const gchar *timezone, const gchar *capabilities,
                       const gchar *language, const char *address,
                       const gchar *jwt);

gboolean
gsad_user_session_is_expired (gsad_user_t *user);

const time_t
gsad_user_session_get_timeout (gsad_user_t *user);

void
gsad_user_session_renew_timeout (gsad_user_t *user);

#endif /* _GSAD_USER_SESSION_H */
