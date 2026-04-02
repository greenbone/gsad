/* Copyright (C) 2016-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_user_session.h"

#include "gsad_gmp_auth.h"
#include "gsad_session.h"
#include "gsad_settings.h"
#include "gsad_user_internal.h"
#include "gsad_user_session.h"
#include "gsad_utils.h"

/**
 * @brief Logout a user
 *
 * @param[in]  user  User.
 *
 * @return 0 success, -1 error.
 */
int
user_logout (user_t *user)
{
  user_t *fuser = session_get_user_by_id (user->token);

  if (fuser)
    {
      if (fuser->username && fuser->password)
        logout_gmp (fuser->username, fuser->password);
      session_remove_user (fuser->token);
      user_free (fuser);
      return 0;
    }

  return -1;
}

/**
 * @brief Check if a user's session has expired
 *
 * @param[in] user User to check for session expiration.
 *
 * @return TRUE if the user's session has expired, FALSE otherwise.
 */
gboolean
user_session_expired (user_t *user)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  return (time (NULL) - user->time)
         > (gsad_settings_get_session_timeout (gsad_global_settings) * 60);
}

/**
 * @brief Add a user to the session store.
 *
 * Creates and initializes a user object with given parameters
 *
 * It's up to the caller to free the returned user.
 *
 * @param[in]  username      Name of user.
 * @param[in]  password      Password for user.
 * @param[in]  timezone      Timezone of user.
 * @param[in]  capabilities  Capabilities of manager.
 * @param[in]  language      User Interface Language (language name or code)
 * @param[in]  address       Client's IP address.
 * @param[in]  jwt           JWT token value, NULL if not requested.
 *
 * @return Added user.
 */
user_t *
user_add (const gchar *username, const gchar *password, const gchar *timezone,
          const gchar *capabilities, const gchar *language, const char *address,
          const gchar *jwt)
{
  GList *current_user_item, *user_list;
  user_t *user;
  int session_count = 0;

  user_list = current_user_item = session_get_users_by_username (username);
  while (current_user_item)
    {
      user = current_user_item->data;
      if (user_session_expired (user))
        {
          if (user->username && user->password)
            logout_gmp (user->username, user->password);
          session_remove_user (user->token);
        }
      else
        session_count++;
      user_free (user);
      current_user_item = current_user_item->next;
    }
  g_list_free (user_list);

  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  int session_limit =
    gsad_settings_get_user_session_limit (gsad_global_settings);
  if (session_limit && (session_count >= session_limit))

    return NULL;

  user = user_new_with_data (username, password, timezone, capabilities,
                             language, address, jwt);

  session_add_user (user->token, user);

  return user;
}

/**
 * @brief Find a user, given a token and cookie.
 *
 * If a user is returned, the session of the user is renewed and it's up to the
 * caller to free the user.
 *
 * @param[in]   cookie       Token in cookie.
 * @param[in]   token        Token request parameter.
 * @param[in]   address      Client's IP address.
 * @param[out]  user_return  Copy of the User or NULL in error cases.
 *
 * @return 0 ok (user in user_return),
 *         1 bad token,
 *         2 expired token,
 *         3 bad/missing cookie,
 *         4 bad/missing token,
 *         7 IP address mismatch,
 */
int
user_find (const gchar *cookie, const gchar *token, const char *address,
           user_t **user_return)
{
  user_t *user = NULL;
  if (token == NULL)
    return USER_BAD_MISSING_TOKEN;

  user = session_get_user_by_id (token);

  if (user)
    {
      if (user_session_expired (user))
        {
          if (user->username && user->password)
            logout_gmp (user->username, user->password);
          session_remove_user (user->token);
          user_free (user);
          return USER_EXPIRED_TOKEN;
        }

      else if ((cookie == NULL) || !str_equal (user->cookie, cookie))
        {
          user_free (user);
          return USER_BAD_MISSING_COOKIE;
        }

      /* Verify that the user address matches the client's address. */
      else if (address == NULL || !str_equal (address, user->address))
        {
          user_free (user);
          return USER_IP_ADDRESS_MISSMATCH;
        }
      else
        {
          session_add_user (user->token, user);

          *user_return = user;
          return USER_OK;
        }
    }

  /* should it be really USER_EXPIRED_TOKEN?
   * No user has been found therefore the token couldn't even expire */
  return USER_EXPIRED_TOKEN;
}

/**
 * @brief Get the session timeout time of a user
 *
 * @param[in] user User whose session timeout time is to be retrieved.
 *
 * @return The session timeout time of the user, calculated as the login time
 */
const time_t
user_get_session_timeout (user_t *user)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  return user->time
         + (gsad_settings_get_session_timeout (gsad_global_settings) * 60);
}

/**
 * @brief Renew a user's session by updating the login time to the current time.
 *
 * @param[in] user User whose session is to be renewed.
 */
void
user_renew_session (user_t *user)
{
  user->time = time (NULL);
}
