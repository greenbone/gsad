/* Copyright (C) 2018-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_credentials.c
 * @brief GSAD credentials handling
 */

#include "gsad_credentials.h"

#include "gsad_user.h"

#include <glib.h>

/**
 *  @brief Structure of credential related information.
 */
struct gsad_credentials
{
  gsad_user_t *user; ///< Current user, if available
  gchar *jwt;        ///< JWT for this credential, if applicable
};

/**
 * @brief Create a new credential
 *
 * @return A new credential instance. The caller is responsible for freeing it
 */
gsad_credentials_t *
gsad_credentials_new ()
{
  gsad_credentials_t *credentials;

  credentials = g_malloc0 (sizeof (gsad_credentials_t));
  credentials->user = NULL;
  credentials->jwt = NULL;

  return credentials;
}

/**
 * @brief Free the credential and its associated resources
 *
 * @param[in] creds Credential to free. If NULL, the function does nothing.
 */
void
gsad_credentials_free (gsad_credentials_t *creds)
{
  if (!creds)
    return;

  g_free (creds->jwt);

  gsad_user_free (creds->user);

  g_free (creds);
}

/**
 * @brief Set the user for the credential
 *
 * @param[in] creds Credential to set the user for
 * @param[in] user User to associate with the credential. The credential will
 * make a copy of the user, so the caller retains ownership of the user object
 * and is responsible for freeing it.
 */
void
gsad_credentials_set_user (gsad_credentials_t *creds, gsad_user_t *user)
{
  gsad_user_free (creds->user);
  creds->user = gsad_user_copy (user);
}

/**
 * @brief Get the user associated with the credential
 *
 * @param[in] cred Credential to get the user from
 *
 * @return The user associated with the credential. The caller should not free
 * this user, as it is owned by the credential.
 */
gsad_user_t *
gsad_credentials_get_user (gsad_credentials_t *cred)
{
  return cred->user;
}

/**
 * @brief Set the JWT for the credential
 *
 * @param[in] creds Credential to set the JWT for
 * @param[in] jwt JWT to associate with the credential. The
 * credential will make a copy of the JWT string, so the caller retains
 * ownership of the string and is responsible for freeing it.
 */
void
gsad_credentials_set_jwt (gsad_credentials_t *creds, const gchar *jwt_token)
{
  g_free (creds->jwt);
  creds->jwt = g_strdup (jwt_token);
}

/**
 * @brief Get the JWT associated with the credential
 *
 * @param[in] cred Credential to get the JWT from
 *
 * @return The JWT associated with the credential. The caller should not
 * free this string, as it is owned by the credential.
 */
const gchar *
gsad_credentials_get_jwt (gsad_credentials_t *cred)
{
  return cred->jwt;
}
