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
session_add_user (const gchar *id, user_t *user);

void
session_remove_user (const gchar *id);

user_t *
session_get_user_by_id (const gchar *id);

GList *
session_get_users_by_username (const gchar *username);

void
session_remove_other_sessions (const gchar *id, const gchar *user);

void
session_init ();

#endif
