/* Copyright (C) 2018-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_session.c
 * @brief GSAD user session handling
 */

#include "gsad_session.h"

#include "gsad_gmp_auth.h"
#include "gsad_user.h"         /* for gsad_user_t */
#include "gsad_user_session.h" /* for gsad_user_session_timeout */
#include "gsad_utils.h"        /* for str_equal */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad session"

/**
 * @brief User session data.
 */
GPtrArray *users = NULL;

/**
 * @brief Mutex to prevent concurrent access to the session.
 */
static GMutex *mutex = NULL;

/**
 * @brief Internal function to get the number of users in the session.
 *
 * This function does not lock the mutex.
 */
int
gsad_session_get_user_count (void)
{
  return users->len;
}

/**
 * @brief Find a user by a session identifier without locking the mutex.
 *
 * @param[in]  id  Unique identifier.
 *
 * @return Return the user or NULL if not found
 */
gsad_user_t *
gsad_session_get_user_by_id_internal (const gchar *id)
{
  if (!id)
    {
      return NULL;
    }

  int index;
  for (index = 0; index < users->len; index++)
    {
      gsad_user_t *item = (gsad_user_t *) g_ptr_array_index (users, index);
      const gchar *token = gsad_user_get_token (item);

      if (str_equal (id, token))
        {
          return item;
        }
    }

  return NULL;
}

/**
 * @brief Remove a user from the session "database" without locking the mutex.
 *
 * @param[in]  id  Unique identifier (token).
 */
void
gsad_session_remove_user_internal (const gchar *id)
{
  gsad_user_t *user = gsad_session_get_user_by_id_internal (id);

  if (user)
    {
      // user is freed by the free function of the users array, so we only need
      // to remove it
      g_ptr_array_remove (users, (gpointer) user);
    }
}

/**
 * @brief Add user to the session "database" without locking the mutex.
 *
 * @param[in]  user  User to add. The session will make a copy of the user, so
 * the caller retains ownership of the user object and is responsible for
 * freeing it. The session will free the user object when it is removed from the
 * session.
 */
void
gsad_session_add_user_internal (gsad_user_t *user)
{
  g_ptr_array_add (users, (gpointer) gsad_user_copy (user));
}

/**
 * @brief Initialize the session handling.
 */
void
gsad_session_init (void)
{
  mutex = g_malloc (sizeof (GMutex));
  g_mutex_init (mutex);
  users = g_ptr_array_new_with_free_func ((GDestroyNotify) gsad_user_free);
}

/**
 * @brief Clean up the session handling.
 */
void
gsad_session_cleanup (void)
{
  g_mutex_lock (mutex);
  g_ptr_array_free (users, TRUE);
  g_mutex_unlock (mutex);
  g_mutex_clear (mutex);
  g_free (mutex);
}

/**
 * Find a user by a session identifier
 *
 * @param[in]  id  Unique identifier (token).
 *
 * @return Return a copy of the user or NULL if not found
 */
gsad_user_t *
gsad_session_get_user_by_id (const gchar *id)
{
  gsad_user_t *user;

  g_mutex_lock (mutex);

  user = gsad_user_copy (gsad_session_get_user_by_id_internal (id));

  g_mutex_unlock (mutex);

  return user;
}

/**
 * Find all users with the given username
 *
 * @param[in]  username  Username to search for.
 *
 * @return Return a list with copies of the users or NULL if not found. The
 * caller is responsible for freeing the returned list and the users in it.
 */
GList *
gsad_session_get_users_by_username (const gchar *username)
{
  int index;
  GList *list = NULL;

  if (!username)
    {
      return NULL;
    }

  g_mutex_lock (mutex);

  for (index = 0; index < users->len; index++)
    {
      gsad_user_t *item = (gsad_user_t *) g_ptr_array_index (users, index);
      const gchar *name = gsad_user_get_username (item);

      if (str_equal (name, username))
        {
          gsad_user_t *user = NULL;
          user = gsad_user_copy (item);
          list = g_list_prepend (list, user);
        }
    }

  g_mutex_unlock (mutex);

  return list;
}

/**
 * @brief Add user to the session "database"
 *
 * @param[in]  id     Unique identifier (token).
 * @param[in]  user   User to add. The session will make a copy of the user, so
 * the caller retains ownership of the user object and is responsible for
 * freeing it. The session will free the user object when it is removed from the
 * session.
 */
void
gsad_session_add_user (const gchar *id, gsad_user_t *user)
{
  g_mutex_lock (mutex);

  gsad_session_remove_user_internal (id);

  gsad_session_add_user_internal (user);

  g_mutex_unlock (mutex);
}

/**
 * @brief Remove a user from the session "database"
 *
 * @param[in]  id  Unique identifier.
 */
void
gsad_session_remove_user (const gchar *id)
{
  g_mutex_lock (mutex);

  gsad_session_remove_user_internal (id);

  g_mutex_unlock (mutex);
}

/**
 * @brief Removes all session of the user, except the one with the passed id.
 *
 * @param[in] keep_id   ID of the session to keep
 * @param[in] username  The user to logout.
 *
 */
void
gsad_session_remove_other_sessions (const gchar *keep_id, const gchar *username)
{
  int index;

  g_mutex_lock (mutex);

  for (index = 0; index < users->len; index++)
    {
      gsad_user_t *item = (gsad_user_t *) g_ptr_array_index (users, index);

      const gchar *itemtoken = gsad_user_get_token (item);
      const gchar *itemname = gsad_user_get_username (item);

      if (str_equal (itemname, username) && !str_equal (keep_id, itemtoken))
        {
          const char *itempassword = gsad_user_get_password (item);

          g_debug ("%s: logging out user '%s', token '%s'", __func__, itemname,
                   itemtoken);

          if (itemname && itempassword)
            logout_gmp (itemname, itempassword);

          /* user is freed by g_ptr_array_remove via the free function */
          g_ptr_array_remove (users, (gpointer) item);

          index--;
        }
    }

  g_mutex_unlock (mutex);
}

/**
 * @brief Update timestamp of given user to now
 *
 * @param[in] id  ID of the session
 */
void
gsad_session_renew_user (const gchar *id)
{
  g_mutex_lock (mutex);

  gsad_user_t *user = gsad_session_get_user_by_id_internal (id);
  if (user)
    {
      gsad_user_session_renew_timeout (user);
    }

  g_mutex_unlock (mutex);
}
