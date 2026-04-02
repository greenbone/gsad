/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_user.c
 * @brief GSAD user handling
 */

#include "gsad_user.h"

#include "gsad_base.h" /* for set_language_code */
#include "gsad_gmp_auth.h"
#include "gsad_session.h"
#include "gsad_settings.h"
#include "gsad_user.h"
#include "gsad_user_internal.h"
#include "gsad_utils.h"

#include <assert.h>             /* for asset */
#include <gvm/util/uuidutils.h> /* for gvm_uuid_make */
#include <string.h>             /* for strcmp */

#define BROWSER_LANGUAGE "Browser Language"

/**
 * @brief Create a new user
 *
 * @return A new user with all fields initialized to NULL
 */
user_t *
gsad_user_new ()
{
  user_t *user = g_malloc0 (sizeof (user_t));
  return user;
}

/**
 * @brief Create a new user with the given data
 *
 * Creates and initializes a user object with given parameters and generates new
 * cookie and token values.
 *
 * @param[in] username      Name of user.
 * @param[in] password      Password for user.
 * @param[in] timezone      Timezone of user.
 * @param[in] capabilities  Capabilities of user.
 * @param[in] language      User Interface Language (language code)
 * @param[in] address       Client's IP address.
 * @param[in] jwt           JWT token value
 *
 * @return A new user with the given data, cookie and token values generated,
 * and session time set to current time.
 */
user_t *
gsad_user_new_with_data (const gchar *username, const gchar *password,
                         const gchar *timezone, const gchar *capabilities,
                         const gchar *language, const gchar *address,
                         const gchar *jwt)
{
  user_t *user = gsad_user_new ();

  user->cookie = gvm_uuid_make ();
  user->token = gvm_uuid_make ();

  user->username = g_strdup (username);
  user->password = g_strdup (password);
  user->timezone = g_strdup (timezone);
  user->capabilities = g_strdup (capabilities);
  user->language = g_strdup (language);
  user->address = g_strdup (address);
  user->jwt = g_strdup (jwt);
  user->time = time (NULL);

  gsad_user_set_language (user, language);

  return user;
}

/**
 * @brief Free a user and all its associated data
 *
 * @param[in] user User to be freed. If NULL, the function does nothing.
 */
void
gsad_user_free (user_t *user)
{
  if (!user)
    {
      return;
    }

  g_free (user->cookie);
  g_free (user->token);
  g_free (user->username);
  g_free (user->password);
  g_free (user->timezone);
  g_free (user->capabilities);
  g_free (user->language);
  g_free (user->address);
  g_free (user->jwt);
  g_free (user);
}

/**
 * @brief Create a copy of a user
 *
 * @param[in] user User to be copied. If NULL, the function returns NULL.
 *
 * @return A new user which is a copy of the given user, or NULL if the input
 * user is NULL.
 */
user_t *
gsad_user_copy (user_t *user)
{
  if (!user)
    {
      return NULL;
    }

  user_t *copy = gsad_user_new ();

  copy->cookie = g_strdup (user->cookie);
  copy->token = g_strdup (user->token);
  copy->username = g_strdup (user->username);
  copy->password = g_strdup (user->password);
  copy->timezone = g_strdup (user->timezone);
  copy->capabilities = g_strdup (user->capabilities);
  copy->language = g_strdup (user->language);
  copy->address = g_strdup (user->address);
  copy->time = user->time;
  copy->jwt = g_strdup (user->jwt);

  return copy;
}

/**
 * @brief Get the username of a user
 *
 * @param[in] user User whose username is to be retrieved.
 *
 * @return The username of the user
 */
const gchar *
gsad_user_get_username (user_t *user)
{
  return user->username;
}

/**
 * @brief Get the User Interface Language of a user (language code)
 *
 * @param[in] user User whose language is to be retrieved.
 *
 * @return The language of the user
 */
const gchar *
gsad_user_get_language (user_t *user)
{
  return user->language;
}

/**
 * @brief Get the cookie token of a user
 *
 * @param[in] user User whose cookie token is to be retrieved.
 *
 * @return The cookie token of the user
 */
const gchar *
gsad_user_get_cookie (user_t *user)
{
  return user->cookie;
}

/**
 * @brief Get the session token of a user
 *
 * @param[in] user User whose session token is to be retrieved.
 *
 * @return The session token of the user
 */
const gchar *
gsad_user_get_token (user_t *user)
{
  return user->token;
}

/**
 * @brief Get the capabilities of a user
 *
 * @param[in] user User whose capabilities are to be retrieved.
 *
 * @return The capabilities of the user
 */
const gchar *
gsad_user_get_capabilities (user_t *user)
{
  return user->capabilities;
}

/**
 * @brief Get the JWT token value of a user
 *
 * @param[in] user User whose JWT token value is to be retrieved.
 *
 * @return The JWT token value of the user
 */
const gchar *
gsad_user_get_jwt (user_t *user)
{
  return user->jwt;
}

/**
 * @brief Get the timezone of a user
 *
 * @param[in] user User whose timezone is to be retrieved.
 *
 * @return The timezone of the user
 */
const gchar *
gsad_user_get_timezone (user_t *user)
{
  return user->timezone;
}

/**
 * @brief Get the client IP address of a user
 *
 * @param[in] user User whose client IP address is to be retrieved.
 *
 * @return The client IP address of the user
 */
const gchar *
gsad_user_get_client_address (user_t *user)
{
  return user->address;
}

/**
 * @brief Get the password of a user
 *
 * @param[in] user User whose password is to be retrieved.
 *
 * @return The password of the user
 */
const gchar *
gsad_user_get_password (user_t *user)
{
  return user->password;
}

/**
 * @brief Get the login time of a user.
 *
 * @param[in] user User whose login time is to be retrieved.
 *
 * @return The login time of the user as a time_t value
 */
time_t
gsad_user_get_time (user_t *user)
{
  return user->time;
}

/**
 * @brief Set timezone of user.
 *
 * @param[in]   user      User.
 * @param[in]   timezone  Timezone.
 *
 */
void
gsad_user_set_timezone (user_t *user, const gchar *timezone)
{
  g_free (user->timezone);

  user->timezone = g_strdup (timezone);
}

/**
 * @brief Set password of user.
 *
 * @param[in]   user      User.
 * @param[in]   password  Password.
 *
 */
void
gsad_user_set_password (user_t *user, const gchar *password)
{
  g_free (user->password);

  user->password = g_strdup (password);
}

/**
 * @brief Set language of user.
 *
 * @param[in]   user      User.
 * @param[in]   language  Language.
 *
 */
void
gsad_user_set_language (user_t *user, const gchar *language)
{
  g_free (user->language);

  if (language == NULL || str_equal (language, BROWSER_LANGUAGE))
    {
      user->language = NULL;
    }
  else
    {
      user->language = g_strdup (language);
    }
}

/**
 * @brief Set username of user.
 *
 * @param[in]   user      User.
 * @param[in]   username  Username.
 *
 */
void
gsad_user_set_username (user_t *user, const gchar *username)
{
  g_free (user->username);
  user->username = g_strdup (username);
}
