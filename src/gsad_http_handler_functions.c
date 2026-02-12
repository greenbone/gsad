/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "gsad_gmp.h" /* for manager_connect */
#include "gsad_http_handler.h"
#include "gsad_i18n.h"       /* for accept_language_to_env_fmt */
#include "gsad_params_mhd.h" /* for params_mhd_add */
#include "validator.h"       /* for gvm_validate */

#include <gvm/base/networking.h>  /* for INET6_ADDRSTRLEN */
#include <gvm/util/serverutils.h> /* for gvm_connection_t */
#include <stdlib.h>               /* for abort */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad http handler functions"

#define TOKEN_REGEXP "^[a-z0-9\\-]+$"
#define SLAVE_ID_REGEXP "^[a-z0-9\\-]+$"

/**
 * @brief Validator instance for http params
 */
validator_t http_validator;

/**
 * @brief A handler for validating the URL of incoming HTTP requests.
 *
 * If the URL is invalid, an error response will be sent and the request handler
 * will be aborted. Otherwise, the next handler in the chain will be called.
 *
 * @return MHD_YES
 */
http_result_t
handle_validate (http_handler_t *handler_next, void *handler_data,
                 http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  const gchar *url = gsad_connection_info_get_url (con_info);

  g_debug ("Validating url %s", url);

  /* If called with undefined URL, abort request handler. */
  if (url == NULL || url[0] == '\0')
    {
      gsad_http_send_response_for_content (
        connection, BAD_REQUEST_PAGE, MHD_HTTP_BAD_REQUEST, NULL,
        GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  /* Prevent guest link from leading to URL redirection. */
  if (url && (url[0] == '/') && (url[1] == '/'))
    {
      gsad_http_send_response_for_content (
        connection, BAD_REQUEST_PAGE, MHD_HTTP_BAD_REQUEST, NULL,
        GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  /* Many Glib functions require valid UTF-8. */
  if (url && (g_utf8_validate (url, -1, NULL) == FALSE))
    {
      gsad_http_send_response_for_content (
        connection, UTF8_ERROR_PAGE ("URL"), MHD_HTTP_BAD_REQUEST, NULL,
        GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  return http_handler_call (handler_next, connection, con_info, data);
}

http_result_t
handle_invalid_method (http_handler_t *handler_next, void *handler_data,
                       http_connection_t *connection,
                       gsad_connection_info_t *con_info, void *data)
{
  /* Only accept GET and POST methods and send ERROR_PAGE in other cases. */
  if (con_info == NULL
      || (gsad_connection_info_get_method_type (con_info) != METHOD_TYPE_GET
          && gsad_connection_info_get_method_type (con_info)
               != METHOD_TYPE_POST))
    {
      gsad_http_send_response_for_content (
        connection, ERROR_PAGE, MHD_HTTP_NOT_ACCEPTABLE, NULL,
        GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  return http_handler_call (handler_next, connection, con_info, data);
}

static int
get_user_from_connection (http_connection_t *connection, user_t **user)
{
  const gchar *cookie;
  const gchar *token;
  gchar client_address[INET6_ADDRSTRLEN];
  int ret;

  token =
    MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, "token");
  if (token == NULL)
    {
      return USER_BAD_MISSING_TOKEN;
    }

  if (gvm_validate (http_validator, "token", token))
    {
      return USER_BAD_MISSING_TOKEN;
    }

  cookie =
    MHD_lookup_connection_value (connection, MHD_COOKIE_KIND, SID_COOKIE_NAME);

  if (gvm_validate (http_validator, "token", cookie))
    {
      return USER_BAD_MISSING_COOKIE;
    }

  ret = get_client_address (connection, client_address);
  if (ret == 1)
    {
      return USER_IP_ADDRESS_MISSMATCH;
    }

  return user_find (cookie, token, client_address, user);
}

http_result_t
handle_get_user (http_handler_t *handler_next, void *handler_data,
                 http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  user_t *user = NULL;
  get_user_from_connection (connection, &user);
  return http_handler_call (handler_next, connection, con_info, user);
}

http_result_t
handle_setup_user (http_handler_t *handler_next, void *handler_data,
                   http_connection_t *connection,
                   gsad_connection_info_t *con_info, void *data)
{
  int ret;
  int http_response_code = MHD_HTTP_OK;
  authentication_reason_t auth_reason;

  user_t *user;

  ret = get_user_from_connection (connection, &user);

  if (ret == USER_GMP_DOWN)
    {
      return gsad_http_send_reauthentication (
        connection, MHD_HTTP_SERVICE_UNAVAILABLE, GMP_SERVICE_DOWN);
    }

  const gchar *url = gsad_connection_info_get_url (con_info);

  if ((ret == USER_EXPIRED_TOKEN) || (ret == USER_BAD_MISSING_COOKIE)
      || (ret == USER_BAD_MISSING_TOKEN) || (ret == USER_IP_ADDRESS_MISSMATCH))
    {
      if (ret == USER_EXPIRED_TOKEN)
        {
          if (strncmp (url, LOGOUT_URL, strlen (LOGOUT_URL)))
            http_response_code = MHD_HTTP_UNAUTHORIZED;
          else
            http_response_code = MHD_HTTP_BAD_REQUEST;
        }
      else
        http_response_code = MHD_HTTP_UNAUTHORIZED;

      auth_reason =
        (ret == USER_EXPIRED_TOKEN)
          ? (strncmp (url, LOGOUT_URL, strlen (LOGOUT_URL)) ? SESSION_EXPIRED
                                                            : LOGOUT_ALREADY)
          : ((ret == USER_BAD_MISSING_COOKIE) ? BAD_MISSING_COOKIE
                                              : BAD_MISSING_TOKEN);

      return gsad_http_send_reauthentication (connection, http_response_code,
                                              auth_reason);
    }

  if (ret)
    {
      g_warning ("%s: unexpected auth error %d", __func__, ret);
      return gsad_http_send_reauthentication (connection, MHD_HTTP_UNAUTHORIZED,
                                              UNKNOWN_ERROR);
    }

  g_debug ("Found user %s\n", user_get_username (user));

  return http_handler_call (handler_next, connection, con_info, user);
}

http_result_t
handle_setup_credentials (http_handler_t *handler_next, void *handler_data,
                          http_connection_t *connection,
                          gsad_connection_info_t *con_info, void *data)
{
  user_t *user = (user_t *) data;
  const gchar *accept_language;
  credentials_t *credentials;
  char client_address[INET6_ADDRSTRLEN];

  get_client_address (connection, client_address);

  gchar *language = g_strdup (user_get_language (user));

  if (!language)
    /* Accept-Language: de; q=1.0, en; q=0.5 */
    {
      accept_language = MHD_lookup_connection_value (
        connection, MHD_HEADER_KIND, "Accept-Language");
      if (accept_language
          && g_utf8_validate (accept_language, -1, NULL) == FALSE)
        {
          gsad_http_send_response_for_content (
            connection, UTF8_ERROR_PAGE ("'Accept-Language' header"),
            MHD_HTTP_BAD_REQUEST, NULL, GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
          return MHD_YES;
        }
      language = accept_language_to_env_fmt (accept_language);
      credentials = credentials_new (user, language);
    }
  else
    {
      credentials = credentials_new (user, language);
    }

  user_free (user);
  g_free (language);

  return http_handler_call (handler_next, connection, con_info, credentials);
}

http_result_t
handle_logout (http_handler_t *handler_next, void *handler_data,
               http_connection_t *connection, gsad_connection_info_t *con_info,
               void *data)
{
  user_t *user = (user_t *) data;

  if (user != NULL)
    {
      user_logout (user);

      g_debug ("Logged out user %s\n", user_get_username (user));

      user_free (user);
    }
  return gsad_http_send_response_for_content (
    connection, "", MHD_HTTP_OK, REMOVE_SID, GSAD_CONTENT_TYPE_TEXT_HTML, NULL,
    0);
}

http_result_t
handle_gmp_get (http_handler_t *handler_next, void *handler_data,
                http_connection_t *connection, gsad_connection_info_t *con_info,
                void *data)
{
  /* URL requests to run GMP command. */
  credentials_t *credentials = (credentials_t *) data;

  int ret = exec_gmp_get (connection, con_info, credentials);

  credentials_free (credentials);
  return ret;
}

http_result_t
handle_gmp_post (http_handler_t *handler_next, void *handler_data,
                 http_connection_t *connection,
                 gsad_connection_info_t *con_info, void *data)
{
  const gchar *sid, *accept_language;
  char client_address[INET6_ADDRSTRLEN];

  sid =
    MHD_lookup_connection_value (connection, MHD_COOKIE_KIND, SID_COOKIE_NAME);

  if (gvm_validate (http_validator, "token", sid))
    gsad_connection_info_set_cookie (con_info, NULL);
  else
    gsad_connection_info_set_cookie (con_info, sid);

  accept_language = MHD_lookup_connection_value (connection, MHD_HEADER_KIND,
                                                 "Accept-Language");
  if (accept_language && g_utf8_validate (accept_language, -1, NULL) == FALSE)
    {
      gsad_http_send_response_for_content (
        connection, UTF8_ERROR_PAGE ("'Accept-Language' header"),
        MHD_HTTP_BAD_REQUEST, NULL, GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  gsad_connection_info_set_language (
    con_info, accept_language_to_env_fmt (accept_language));

  if (get_client_address (connection, client_address))
    {
      gsad_http_send_response_for_content (
        connection, UTF8_ERROR_PAGE ("'X-Real-IP' header"),
        MHD_HTTP_BAD_REQUEST, NULL, GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  return exec_gmp_post (connection, con_info, client_address);
}

http_result_t
handle_system_report (http_handler_t *handler_next, void *handler_data,
                      http_connection_t *connection,
                      gsad_connection_info_t *con_info, void *data)
{
  params_t *params = params_new ();
  credentials_t *credentials = (credentials_t *) data;
  const gchar *url = gsad_connection_info_get_url (con_info);
  const char *slave_id;
  gchar *res;
  gvm_connection_t con;
  cmd_response_data_t *response_data;

  g_debug ("Request for system report url %s", url);

  MHD_get_connection_values (connection, MHD_GET_ARGUMENT_KIND, params_mhd_add,
                             params);

  params_mhd_validate (params);

  slave_id =
    MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, "slave_id");

  if (slave_id && gvm_validate (http_validator, "slave_id", slave_id))
    {
      credentials_free (credentials);
      g_warning ("%s: failed to validate slave_id, dropping request", __func__);
      return MHD_NO;
    }

  response_data = cmd_response_data_new ();

  /* Connect to manager */
  switch (manager_connect (credentials, &con))
    {
    case 0: /* success */
      res = get_system_report_gmp_from_url (
        &con, credentials, &url[0] + strlen ("/system_report/"), params,
        response_data);
      gvm_connection_close (&con);
      if (res == NULL)
        {
          g_info ("%s: failed to get system report for sensor %s", __func__,
                  slave_id);
          cmd_response_data_set_status_code (response_data,
                                             MHD_HTTP_INTERNAL_SERVER_ERROR);
          res =
            gsad_message (credentials, "Internal error", __func__, __LINE__,
                          "An internal error occurred. "
                          "Diagnostics: Could not receive the system report. ",
                          response_data);
        }
      break;
    case 1: /* manager closed connection */
      cmd_response_data_set_status_code (response_data,
                                         MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_message (credentials, "Internal error", __func__, __LINE__,
                          "An internal error occurred. "
                          "Diagnostics: Failure to connect to manager daemon. "
                          "Manager daemon doesn't respond.",
                          response_data);
      break;
    case 2: /* authentication failed */
      cmd_response_data_free (response_data);
      credentials_free (credentials);
      return gsad_http_send_reauthentication (connection, MHD_HTTP_UNAUTHORIZED,
                                              LOGIN_FAILED);

      break;
    case 3: /* timeout */
      cmd_response_data_set_status_code (response_data,
                                         MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_message (credentials, "Internal error", __func__, __LINE__,
                          "An internal error occurred. "
                          "Diagnostics: Failure to connect to manager daemon. "
                          "Timeout while waiting for manager response.",
                          response_data);
      break;
    case 4: /* failed to connect to manager */
      cmd_response_data_set_status_code (response_data,
                                         MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_message (credentials, "Internal error", __func__, __LINE__,
                          "An internal error occurred. "
                          "Diagnostics: Failure to connect to manager daemon. "
                          "Could not open a connection.",
                          response_data);
      break;
    default:
      cmd_response_data_set_status_code (response_data,
                                         MHD_HTTP_INTERNAL_SERVER_ERROR);
      res = gsad_message (credentials, "Internal error", __func__, __LINE__,
                          "An internal error occurred. "
                          "Diagnostics: Failure to connect to manager daemon. "
                          "Unknown error.",
                          response_data);
      break;
    }

  if (res == NULL)
    {
      credentials_free (credentials);
      g_warning ("%s: failed to get system reports, dropping request",
                 __func__);
      cmd_response_data_free (response_data);
      return MHD_NO;
    }

  credentials_free (credentials);

  return gsad_http_create_response (connection, res, response_data, NULL);
}

http_result_t
handle_index (http_handler_t *handler_next, void *handler_data,
              http_connection_t *connection, gsad_connection_info_t *con_info,
              void *data)
{
  http_response_t *response;
  cmd_response_data_t *response_data;

  response_data = cmd_response_data_new ();
  cmd_response_data_set_allow_caching (response_data, FALSE);

  const gchar *url = gsad_connection_info_get_url (con_info);

  g_debug ("Returning index page for url %s", url);

  response = gsad_http_create_file_content_response (
    connection, url, "index.html", response_data);
  return gsad_http_send_response (connection, response, response_data, NULL);
}

http_result_t
handle_static_file (http_handler_t *handler_next, void *handler_data,
                    http_connection_t *connection,
                    gsad_connection_info_t *con_info, void *data)
{
  gchar *path;
  http_response_t *response;
  char *default_file = "index.html";
  cmd_response_data_t *response_data;
  const gchar *url = gsad_connection_info_get_url (con_info);

  /** @todo validation, URL length restriction (allows you to view ANY
   *       file that the user running the gsad might look at!) */
  /** @todo use glibs path functions */
  /* Attempt to prevent disclosing non-gsa content. */
  if (strstr (url, ".."))
    path = g_strconcat (default_file, NULL);
  else
    {
      /* Ensure that url is relative. */
      const char *relative_url = url;
      if (*url == '/')
        relative_url = url + 1;
      path = g_strconcat (relative_url, NULL);
    }

  g_debug ("Requesting url %s for static path %s", url, path);

  response_data = cmd_response_data_new ();
  cmd_response_data_set_allow_caching (response_data, TRUE);

  response = gsad_http_create_file_content_response (connection, url, path,
                                                     response_data);

  g_free (path);

  return gsad_http_send_response (connection, response, response_data, NULL);
}

http_result_t
handle_static_content (http_handler_t *handler_next, void *handler_data,
                       http_connection_t *connection,
                       gsad_connection_info_t *con_info, void *data)
{
  gchar *path;
  http_response_t *response;
  char *default_file = "index.html";
  cmd_response_data_t *response_data;
  const gchar *url = gsad_connection_info_get_url (con_info);

  /** @todo validation, URL length restriction (allows you to view ANY
   *       file that the user running the gsad might look at!) */
  /** @todo use glibs path functions */
  /* Attempt to prevent disclosing non-gsa content. */
  if (strstr (url, ".."))
    path = g_strconcat (default_file, NULL);
  else
    {
      /* Ensure that url is relative. */
      const char *relative_url = url;
      if (*url == '/')
        relative_url = url + 1;
      path = g_strconcat (relative_url, NULL);
    }

  g_debug ("Requesting url %s for static content %s", url, path);

  if (g_file_test (path, (G_FILE_TEST_IS_DIR)))
    {
      if (url[strlen (url) - 1] != '/')
        {
          g_debug ("Redirecting to %s/", url);
          gchar *new_url = g_strconcat (url, "/", NULL);
          response =
            MHD_create_response_from_buffer (0, NULL, MHD_RESPMEM_PERSISTENT);
          MHD_add_response_header (response, "Location", new_url);
          response_data = cmd_response_data_new ();
          cmd_response_data_set_status_code (response_data,
                                             MHD_HTTP_MOVED_PERMANENTLY);
          g_free (path);
          g_free (new_url);
          return gsad_http_send_response (connection, response, response_data,
                                          NULL);
        }

      gchar *old_path = path;
      path = g_strconcat (path, "/", default_file, NULL);
      g_free (old_path);
    }

  response_data = cmd_response_data_new ();
  cmd_response_data_set_allow_caching (response_data, TRUE);

  response = gsad_http_create_file_content_response (connection, url, path,
                                                     response_data);

  g_free (path);

  return gsad_http_send_response (connection, response, response_data, NULL);
}

http_result_t
handle_static_config (http_handler_t *handler_next, void *handler_data,
                      http_connection_t *connection,
                      gsad_connection_info_t *con_info, void *data)
{
  gchar *path;
  http_response_t *response;
  cmd_response_data_t *response_data;
  const gchar *url = gsad_connection_info_get_url (con_info);

  /* Ensure that url is relative. */
  const char *relative_url = url;
  if (*url == '/')
    {
      relative_url = url + 1;
    }
  path = g_strconcat (relative_url, NULL);

  g_debug ("Requesting url %s for static config path %s", url, path);

  response_data = cmd_response_data_new ();

  // don't cache config file
  cmd_response_data_set_allow_caching (response_data, FALSE);

  if (g_file_test (path, G_FILE_TEST_EXISTS))
    {
      response = gsad_http_create_file_content_response (connection, url, path,
                                                         response_data);
      g_free (path);
      return gsad_http_send_response (connection, response, response_data,
                                      NULL);
    }

  g_free (path);

  // send empty config
  cmd_response_data_set_status_code (response_data, MHD_HTTP_OK);
  return gsad_http_create_response (connection, g_strdup (""), response_data,
                                    NULL);
}

void
init_validator (void)
{
  http_validator = gvm_validator_new ();
  gvm_validator_add (http_validator, "slave_id", SLAVE_ID_REGEXP);
  gvm_validator_add (http_validator, "token", TOKEN_REGEXP);
}

void
cleanup_validator (void)
{
  gvm_validator_free (http_validator);
}
