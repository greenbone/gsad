/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_watcher.h"

#include <pthread.h>
#include <unistd.h> /* for sleep */

struct gsad_connection_watcher_data
{
  int client_socket_fd;
  gvm_connection_t *connection;
  int connection_closed;
  pthread_mutex_t mutex;
  gsad_settings_t *gsad_settings;
};

typedef struct gsad_connection_watcher_data gsad_connection_watcher_data_t;

struct gsad_connection_watcher
{
  pthread_t thread;
  gsad_connection_watcher_data_t *data;
};

/**
 * @brief  Create a new connection watcher thread data structure.
 *
 * @param[in]  gsad_settings    Settings to get the watch interval from.
 * @param[in]  connection       GVM connection to close if client conn. closes.
 * @param[in]  client_socket_fd File descriptor of client connection to watch.
 *
 * @return  Newly allocated watcher thread data.
 */
gsad_connection_watcher_data_t *
gsad_connection_watcher_data_new (gsad_settings_t *gsad_settings,
                                  gvm_connection_t *connection,
                                  int client_socket_fd)
{
  gsad_connection_watcher_data_t *watcher_data =
    g_malloc (sizeof (gsad_connection_watcher_data_t));

  watcher_data->connection = connection;
  watcher_data->client_socket_fd = client_socket_fd;
  watcher_data->connection_closed = 0;
  watcher_data->gsad_settings = gsad_settings;
  pthread_mutex_init (&(watcher_data->mutex), NULL);

  return watcher_data;
}

/**
 * @brief   Free the connection watcher thread data structure.
 *
 * @param[in]  watcher_data    The connection watcher thread data to free.
 */
void
gsad_connection_watcher_data_free (gsad_connection_watcher_data_t *watcher_data)
{
  pthread_mutex_destroy (&(watcher_data->mutex));
  gsad_settings_free (watcher_data->gsad_settings);
  g_free (watcher_data);
}

/**
 * @brief   Thread start routine watching the client connection.
 *
 * @param[in] data  The connection data watcher struct.
 */
static void *
gsad_watch_client_connection (void *data)
{
  int active;

  pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
  gsad_connection_watcher_data_t *watcher_data =
    (gsad_connection_watcher_data_t *) data;

  pthread_mutex_lock (&(watcher_data->mutex));
  active = 1;
  pthread_mutex_unlock (&(watcher_data->mutex));

  while (active)
    {
      pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
      sleep (
        gsad_settings_get_client_watch_interval (watcher_data->gsad_settings));
      pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);

      pthread_mutex_lock (&(watcher_data->mutex));

      if (watcher_data->connection_closed)
        {
          active = 0;
          pthread_mutex_unlock (&(watcher_data->mutex));
          continue;
        }
      int ret;
      gchar buf[1];
      errno = 0;
      ret = recv (watcher_data->client_socket_fd, buf, 1, MSG_PEEK);

      if (ret >= 0)
        {
          if (watcher_data->connection_closed == 0)
            {
              watcher_data->connection_closed = 1;
              active = 0;
              g_debug ("Client connection closed");

              if (watcher_data->connection->tls)
                {
                  gvm_connection_t *gvm_conn;
                  gvm_conn = watcher_data->connection;
                  gnutls_bye (gvm_conn->session, GNUTLS_SHUT_RDWR);
                }
              else
                {
                  gvm_connection_close (watcher_data->connection);
                }
            }
        }

      pthread_mutex_unlock (&(watcher_data->mutex));
    }

  return NULL;
}

/**
 * @brief   Create a new connection watcher
 *
 * @param[in]  gsad_settings    Settings to get the watch interval from.
 * @param[in]  connection       GVM connection to close if client conn. closes.
 * @param[in]  client_socket_fd File descriptor of client connection to watch.
 *
 * @return  Newly allocated connection watcher.
 * */
gsad_connection_watcher_t *
gsad_connection_watcher_new (gsad_settings_t *gsad_settings,
                             gvm_connection_t *gvm_connection,
                             int client_socket_fd)
{
  gsad_connection_watcher_t *watcher =
    g_malloc0 (sizeof (gsad_connection_watcher_t));
  watcher->data = gsad_connection_watcher_data_new (
    gsad_settings, gvm_connection, client_socket_fd);
  return watcher;
}

void
gsad_connection_watcher_start (gsad_connection_watcher_t *watcher)
{
  pthread_create (&(watcher->thread), NULL, gsad_watch_client_connection,
                  watcher->data);
}

/**
 * @brief   Stop the connection watcher thread and close the connection if not
 *          already closed.
 *
 * @note    This function will block until the thread has stopped.
 *
 * @param[in]  watcher The connection watcher to stop.
 */
void
gsad_connection_watcher_stop (gsad_connection_watcher_t *watcher)
{
  pthread_mutex_lock (&(watcher->data->mutex));
  gsad_connection_watcher_data_t *watcher_data = watcher->data;
  if (watcher_data->connection_closed == 0 || watcher_data->connection->tls)
    {
      gvm_connection_close (watcher_data->connection);
    }
  watcher_data->connection_closed = 1;
  g_debug ("Stopping connection watcher thread");
  pthread_mutex_unlock (&(watcher->data->mutex));
  pthread_cancel (watcher->thread);
  pthread_join (watcher->thread, NULL);
}

/**
 * @brief   Free the connection watcher.
 *
 * @param[in]  watcher The connection watcher to free.
 */
void
gsad_connection_watcher_free (gsad_connection_watcher_t *watcher)
{
  gsad_connection_watcher_data_free (watcher->data);
  g_free (watcher);
}
