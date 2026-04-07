/* Copyright (C) 2009-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_manager.h"

#include "gsad_settings.h" /* for gsad_settings_get_manager_address and gsad_settings_get_manager_port */

#include <netinet/in.h> /* for sockaddr_in */
#include <sys/socket.h>
#include <sys/un.h> /* for sockaddr_un */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad manager"

/**
 * @brief Connect to Greenbone Vulnerability Manager daemon.
 *
 * @param[in]  path  Path to the Manager socket.
 *
 * @return Socket, or -1 on error.
 */
static int
connect_unix (const gchar *path)
{
  struct sockaddr_un address;
  int sock;

  /* Make socket. */

  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock == -1)
    {
      g_warning ("Failed to create server socket");
      return -1;
    }

  /* Connect to server. */

  address.sun_family = AF_UNIX;
  strncpy (address.sun_path, path, sizeof (address.sun_path) - 1);
  if (connect (sock, (struct sockaddr *) &address, sizeof (address)) == -1)
    {
      g_warning ("Failed to connect to server via unix socket at %s: %s", path,
                 strerror (errno));
      close (sock);
      return -1;
    }

  return sock;
}

/**
 * @brief Connect to an address.
 *
 * @param[out]  connection  Connection.
 * @param[out]  address     Address.
 * @param[out]  port        Port.
 *
 * @return 0 success, -1 failed to connect.
 */
static int
gvm_connection_open (gvm_connection_t *connection, const gchar *address,
                     int port)
{
  if (address == NULL)
    return -1;

  gboolean manager_use_tls = port > 0;

  connection->tls = manager_use_tls;

  if (manager_use_tls)
    {
      connection->socket =
        gvm_server_open (&connection->session, address, port);
      connection->credentials = NULL;
    }
  else
    connection->socket = connect_unix (address);

  if (connection->socket == -1)
    return -1;

  return 0;
}

/**
 * @brief Connect and authenticate to Greenbone Vulnerability Manager daemon
 * using gsad credentials.
 *
 * @param[out]  connection   Connection to Manager on success.
 * @param[in]   credentials  Username and password for authentication.
 *
 * @return 0 success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, 4 failed to connect, -1 on error
 */
int
gsad_manager_connect_with_credentials (gvm_connection_t *connection,
                                       gsad_credentials_t *credentials)
{
  gsad_user_t *user = gsad_credentials_get_user (credentials);
  return gsad_manager_connect_with_username_password (
    connection, gsad_user_get_username (user), gsad_user_get_password (user));
}

/**
 * @brief Connect and authenticate to Greenbone Vulnerability Manager daemon
 * using gsad credentials.
 *
 * @param[out]  connection   Connection to Manager on success.
 * @param[in]   credentials  Username and password for authentication.
 *
 * @return 0 success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, 4 failed to connect, -1 on error
 */
int
gsad_manager_connect_with_username_password (gvm_connection_t *connection,
                                             const gchar *username,
                                             const gchar *password)
{
  gmp_authenticate_info_opts_t auth_opts;
  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = username;
  auth_opts.password = password;
  return gsad_manager_connect (connection, auth_opts);
}

/**
 * @brief Connect and authenticate to Greenbone Vulnerability Manager daemon
 * using gmp auth info opts.
 *
 * @param[out]      connection Connection to Manager on success.
 * @param[in, out]  auth_opts  In: Struct containing the options to apply.
 *                             Out: Additional account information if
 *                                  authentication was successful.
 *
 * @return 0 success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, 4 failed to connect, -1 on error
 */
int
gsad_manager_connect (gvm_connection_t *connection,
                      gmp_authenticate_info_opts_t auth_opts)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();

  if (gvm_connection_open (
        connection, gsad_settings_get_manager_address (gsad_global_settings),
        gsad_settings_get_manager_port (gsad_global_settings)))
    {
      return 4;
    }

  int ret = gmp_authenticate_info_ext_c (connection, auth_opts);

  if (ret)
    {
      gvm_connection_close (connection);
      return ret;
    }
#ifdef DEBUG
  /* Enable this if you need the CGI to sleep after launch. This can be useful
   * if you need to attach to manager process the CGI is talking to for
   * debugging purposes.
   *
   * An easier method is to run gsad under gdb and set a breakpoint here.
   */
  g_debug ("Sleeping!");
  sleep (10);
#endif
  return 0;
}
