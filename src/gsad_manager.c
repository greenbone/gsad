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
 * @brief Authenticate with the manager using XML.
 *
 * @param[in]  connection  Connection
 * @param[in]  xml         XML to authenticate with
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
static int
gmp_authenticate_with_xml (gvm_connection_t *connection, const gchar *xml)
{
  entity_t entity = NULL;
  const char *status;
  char first;
  int ret;

  /* Send the auth request. */
  ret = gvm_connection_sendf (connection,
                              "<authenticate>"
                              "<credentials>%s</credentials>"
                              "</authenticate>",
                              xml);
  if (ret)
    return ret;

  /* Read the response. */
  switch (try_read_entity_c (connection, 0, &entity))
    {
    case 0:
      break;
    case -4:
      return 3;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first != '2')
    {
      free_entity (entity);
      return 2;
    }
  free_entity (entity);
  return 0;
}

/**
 * @brief Authenticate with the manager using a JWT.
 *
 * @param[in]  connection  Connection
 * @param[in]  token       Token to authenticate with
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
static int
gmp_authenticate_with_jwt (gvm_connection_t *connection, const gchar *token)
{
  const gchar *xml = g_markup_printf_escaped ("<token>%s</token>", token);
  int ret = gmp_authenticate_with_xml (connection, xml);
  g_free (xml);
  return ret;
}

/**
 * @brief Authenticate with the manager using a token.
 *
 * @param[in]  connection  Connection
 * @param[in]  token       Token to authenticate with
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
static int
gmp_authenticate_with_username_password (gvm_connection_t *connection,
                                         const gchar *username,
                                         const gchar *password)
{
  const gchar *xml = g_markup_printf_escaped (
    "<username>%s</username><password>%s</password>", username, password);
  int ret = gmp_authenticate_with_xml (connection, xml);
  g_free (xml);
  return ret;
}

/**
 * @brief Connect to an address.
 *
 * @param[out]  connection       Connection.
 * @param[in]   unix_socket_path Path to the Unix socket.
 *
 * @return 0 success, -1 failed to connect.
 */
static int
gsad_manager_open_unix_socket_connection (gvm_connection_t *connection,
                                          const gchar *unix_socket_path)
{
  if (unix_socket_path == NULL)
    return -1;

  int sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock == -1)
    {
      g_warning ("Failed to create server socket");
      return -1;
    }

  connection->socket = sock;
  connection->tls = 0;

  struct sockaddr_un address;
  address.sun_family = AF_UNIX;
  strncpy (address.sun_path, unix_socket_path, sizeof (address.sun_path) - 1);
  if (connect (sock, (struct sockaddr *) &address, sizeof (address)) == -1)
    {
      g_warning ("Failed to connect to server via unix socket at %s: %s",
                 unix_socket_path, strerror (errno));
      close (sock);
      return -1;
    }

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
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  if (gsad_manager_open_unix_socket_connection (
        connection, gsad_settings_get_manager_address (gsad_global_settings)))
    {
      return 4;
    }
  int ret =
    gmp_authenticate_with_username_password (connection, username, password);
  if (ret)
    {
      gvm_connection_close (connection);
    }
  return ret;
}

/**
 * @brief Connect and authenticate to Greenbone Vulnerability Manager daemon
 * using a JWT.
 *
 * @param[out]  connection   Connection to Manager on success.
 * @param[in]   token        JWT for authentication.
 *
 * @return 0 success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, 4 failed to connect, -1 on error
 */
int
gsad_manager_connect_with_jwt (gvm_connection_t *connection, const gchar *token)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();
  if (gsad_manager_open_unix_socket_connection (
        connection, gsad_settings_get_manager_address (gsad_global_settings)))
    {
      return 4;
    }
  int ret = gmp_authenticate_with_jwt (connection, token);
  if (ret)
    {
      gvm_connection_close (connection);
    }
  return ret;
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
gsad_manager_connect_with_auth_opts (gvm_connection_t *connection,
                                     gmp_authenticate_info_opts_t auth_opts)
{
  gsad_settings_t *gsad_global_settings = gsad_settings_get_global_settings ();

  if (gsad_manager_open_unix_socket_connection (
        connection, gsad_settings_get_manager_address (gsad_global_settings)))
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
