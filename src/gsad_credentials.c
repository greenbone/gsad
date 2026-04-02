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
  struct timeval cmd_start; ///< Seconds since command page handler started.
  gchar *language;          ///< Language for this request
  user_t *user;             ///< Current user
};

/**
 * @brief Create a new credential from user and language
 *
 * @param[in] user     User to set for the credential
 * @param[in] language Language to use for the credential
 *
 * @return A new credential instance. The caller is responsible for freeing it
 */
gsad_credentials_t *
gsad_credentials_new (user_t *user, const gchar *language)
{
  gsad_credentials_t *credentials;

  credentials = g_malloc0 (sizeof (gsad_credentials_t));
  credentials->user = user_copy (user);
  credentials->language = g_strdup (language);

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

  g_free (creds->language);

  user_free (creds->user);

  g_free (creds);
}

/**
 * @brief Get the user associated with the credential
 *
 * @param[in] cred Credential to get the user from
 *
 * @return The user associated with the credential. The caller should not free
 * this user, as it is owned by the credential.
 */
user_t *
gsad_credentials_get_user (gsad_credentials_t *cred)
{
  return cred->user;
}

/**
 * @brief Get the language associated with the credential
 *
 * @param[in] cred Credential to get the language from
 *
 * @return The language associated with the credential. The caller should not
 * free this string, as it is owned by the credential.
 */
const gchar *
gsad_credentials_get_language (gsad_credentials_t *cred)
{
  return cred->language;
}

/**
 * @brief Start the command timer for the credential
 *
 * @param[in] creds Credential to start the command timer for
 */
void
gsad_credentials_start_cmd (gsad_credentials_t *creds)
{
  gettimeofday (&creds->cmd_start, NULL);
}

/**
 * @brief Get the duration in seconds since the command timer was started for
 * the credential
 *
 * @param[in] cred Credential to get the command duration for
 *
 * @return The duration in seconds since the command timer was started
 */
double
gsad_credentials_get_cmd_duration (gsad_credentials_t *cred)
{
  struct timeval tv;
  gettimeofday (&tv, NULL);
  return (double) ((tv.tv_sec - cred->cmd_start.tv_sec) * 1000000L + tv.tv_usec
                   - cred->cmd_start.tv_usec)
         / 1000000.0;
}
