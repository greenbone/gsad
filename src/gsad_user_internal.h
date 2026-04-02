/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_USER_INTERNAL_H
#define _GSAD_USER_INTERNAL_H

#include "gsad_user.h"

/**
 * @brief User information structure, for sessions.
 */
struct gsad_user
{
  gchar *cookie;       ///< Cookie token.
  gchar *token;        ///< Request session token.
  gchar *username;     ///< Login name.
  gchar *password;     ///< Password.
  gchar *timezone;     ///< Timezone.
  gchar *capabilities; ///< Capabilities.
  gchar *language;     ///< User Interface Language.
  gchar *address;      ///< Client's IP address.
  time_t time;         ///< Login time.
  gchar *jwt;          ///< JSON Web token value.
};

#endif /* _GSAD_USER_INTERNAL_H */
