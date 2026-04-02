/* Copyright (C) 2018-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_session.h
 * @brief GSAD user session handling
 */

#ifndef _GSAD_SESSION_H
#define _GSAD_SESSION_H

#include "gsad_user.h"

#include <glib.h>

void
gsad_session_add_user (const gchar *id, gsad_user_t *user);

void
gsad_session_remove_user (const gchar *id);

gsad_user_t *
gsad_session_get_user_by_id (const gchar *id);

GList *
gsad_session_get_users_by_username (const gchar *username);

void
gsad_session_remove_other_sessions (const gchar *id, const gchar *user);

void
gsad_session_renew_user (const gchar *id);

void
gsad_session_init ();

#endif
