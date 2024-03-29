/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file gsad_gmp_auth.h
 * @brief Authentication GMP
 */

#ifndef _GSAD_GMP_AUTH_H
#define _GSAD_GMP_AUTH_H

#include <glib.h> /* for gchar */

int
authenticate_gmp (const gchar *, const gchar *, gchar **, gchar **, gchar **,
                  gchar **, gchar **, gchar **);

int
logout_gmp (const gchar *username, const gchar *password);

#endif /* _GSAD_GMP_AUTH_H */
