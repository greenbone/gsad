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
gsad_user_session_find (const gchar *cookie, const gchar *token,
                        const char *address, gsad_user_t **user_return);

int
gsad_user_session_add (gsad_user_t *user);

gboolean
gsad_user_session_is_expired (gsad_user_t *user);

const time_t
gsad_user_session_get_timeout (gsad_user_t *user);

void
gsad_user_session_renew_timeout (gsad_user_t *user);

#endif /* _GSAD_USER_SESSION_H */
