/* Copyright (C) 2016-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_user_session.h"

#include "gsad_gmp_auth.h" /* for logout_gmp */
#include "gsad_session.h" /* for gsad_session_get_user_by_id, gsad_session_remove_user, gsad_session_add_user, gsad_session_get_users_by_username */
#include "gsad_settings.h" /* for gsad_settings_get_session_timeout  */
#include "gsad_user_internal.h"
#include "gsad_utils.h" /* for str_equal */

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
 * @param[in]  user      User to add.
 *
 * @return 0 success, 1 if session limit exceeded
 */
int
gsad_user_session_add (gsad_user_t *user)
{
  GList *current_user_item, *user_list;
  int session_count = 0;
  gsad_user_t *current_user = NULL;

  user_list = current_user_item =
    gsad_session_get_users_by_username (gsad_user_get_username (user));
  while (current_user_item)
    {
      current_user = current_user_item->data;
      if (gsad_user_session_is_expired (current_user))
        {
          if (current_user->username && current_user->password)
            logout_gmp (current_user->username, current_user->password);
          gsad_session_remove_user (current_user);
        }
      else
        session_count++;
      current_user_item = current_user_item->next;
    }
  g_list_free_full (user_list, (GDestroyNotify) gsad_user_free);

  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  int session_limit =
    gsad_settings_get_user_session_limit (gsad_global_settings);
  if (session_limit && (session_count >= session_limit))
    return 1;

  gsad_session_add_user (user);

  return 0;
}

/**
 * @brief Find a user in the session, given a token and cookie.
 *
 * If a user is returned it's up to the caller to free the user.
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
          gsad_session_remove_user (user);
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
 * @brief Renew the session timeout of a user by updating the login time to the
 * current time and replacing the user in the session store with the updated
 * user.
 *
 * This function should be called when the session timeout of a user needs to be
 * extended.
 */
void
gsad_user_session_renew_timeout (gsad_user_t *user)
{
  if (!user)
    {
      return;
    }
  gsad_user_renew_time (user);
  gsad_session_replace_user_if_exists (user);
}
