/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GSAD_USER_INTERNAL_H
#define _GSAD_USER_INTERNAL_H

#include "gsad_user.h"

user_t *
user_new ();

user_t *
user_new_with_data (const gchar *username, const gchar *password,
                    const gchar *timezone, const gchar *capabilities,
                    const gchar *language, const gchar *pw_warning,
                    const gchar *address, const gchar *jwt);

#endif /* _GSAD_USER_INTERNAL_H */
