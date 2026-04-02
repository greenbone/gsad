/* Copyright (C) 2016-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_user_session.h"

#include "gsad_gmp_auth.h" /* for logout_gmp */
#include "gsad_session.h"
#include "gsad_settings.h" /* for gsad_settings_get_session_timeout  */
#include "gsad_user_internal.h"
#include "gsad_utils.h" /* for str_equal */

/**
 * @brief Logout a user and remove the session of the user.
 *
 * @param[in]  user  User to logout.
 *
 * @return 0 success, -1 error.
 */
void
gsad_user_session_logout (gsad_user_t *user)
{
  gsad_user_t *fuser = gsad_session_get_user_by_id (user->token);

  if (fuser)
    {
      if (fuser->username && fuser->password)
        logout_gmp (fuser->username, fuser->password);

      gsad_session_remove_user (fuser->token);
      gsad_user_free (fuser);
    }
}

/**
 * @brief Check if a user's session has expired
 *
 * @param[in] user User to check for session expiration.
 *
 * @return TRUE if the user's session has expired, FALSE otherwise.
 */
gboolean
gsad_user_session_is_expired (gsad_user_t *user)
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
gsad_user_t *
gsad_user_session_add (const gchar *username, const gchar *password,
                       const gchar *timezone, const gchar *capabilities,
                       const gchar *language, const char *address,
                       const gchar *jwt)
{
  GList *current_user_item, *user_list;
  gsad_user_t *user;
  int session_count = 0;

  user_list = current_user_item = gsad_session_get_users_by_username (username);
  while (current_user_item)
    {
      user = current_user_item->data;
      if (gsad_user_session_is_expired (user))
        {
          if (user->username && user->password)
            logout_gmp (user->username, user->password);
          gsad_session_remove_user (user->token);
        }
      else
        session_count++;
      gsad_user_free (user);
      current_user_item = current_user_item->next;
    }
  g_list_free (user_list);

  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  int session_limit =
    gsad_settings_get_user_session_limit (gsad_global_settings);
  if (session_limit && (session_count >= session_limit))

    return NULL;

  user = gsad_user_new_with_data (username, password, timezone, capabilities,
                                  language, address, jwt);

  gsad_session_add_user (user->token, user);

  return user;
}

/**
 * @brief Find a user in the session, given a token and cookie.
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
gsad_user_session_find (const gchar *cookie, const gchar *token,
                        const char *address, gsad_user_t **user_return)
{
  gsad_user_t *user = NULL;
  if (token == NULL)
    return USER_BAD_MISSING_TOKEN;

  user = gsad_session_get_user_by_id (token);

  if (user)
    {
      if (gsad_user_session_is_expired (user))
        {
          if (user->username && user->password)
            logout_gmp (user->username, user->password);
          gsad_session_remove_user (user->token);
          gsad_user_free (user);
          return USER_EXPIRED_TOKEN;
        }

      else if ((cookie == NULL) || !str_equal (user->cookie, cookie))
        {
          gsad_user_free (user);
          return USER_BAD_MISSING_COOKIE;
        }

      /* Verify that the user address matches the client's address. */
      else if (address == NULL || !str_equal (address, user->address))
        {
          gsad_user_free (user);
          return USER_IP_ADDRESS_MISSMATCH;
        }
      else
        {
          gsad_session_renew_user (user->token);

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
gsad_user_session_get_timeout (gsad_user_t *user)
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
gsad_user_session_renew_timeout (gsad_user_t *user)
{
  user->time = time (NULL);
}
