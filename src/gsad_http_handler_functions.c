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
 * @param[in] handler_next The next handler in the chain
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL and HTTP method
 * @param[in] data Additional data to pass to the next handler (not used in this
 * handler)
 *
 * @return Result value from the next handler in the chain or MHD_YES if the URL
 * was invalid and an error response was sent.
 */
gsad_http_result_t
gsad_http_handle_validate (gsad_http_handler_t *handler_next,
                           void *handler_data,
                           gsad_http_connection_t *connection,
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

  return gsad_http_handler_call (handler_next, connection, con_info, data);
}

/**
 * @brief Handler for validating the HTTP method of incoming requests.
 *
 * It only accepts GET and POST methods. If the method is not accepted, an error
 * response will be sent and the request handler will be aborted. Otherwise, the
 * next handler in the chain will be called.
 *
 * @param[in] handler_next The next handler in the chain
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL and HTTP method
 * @param[in] data Additional data to pass to the next handler (not used in this
 * handler)
 *
 * @return Result value from the next handler in the chain or MHD_YES if the
 * method was invalid and an error response was sent.
 */
gsad_http_result_t
gsad_http_handle_invalid_method (gsad_http_handler_t *handler_next,
                                 void *handler_data,
                                 gsad_http_connection_t *connection,
                                 gsad_connection_info_t *con_info, void *data)
{
  /* Only accept GET and POST methods and send ERROR_PAGE in other cases. */
  if (con_info == NULL
      || (gsad_connection_info_get_method_type (con_info) != METHOD_TYPE_GET
          && gsad_connection_info_get_method_type (con_info)
               != METHOD_TYPE_POST))
    {
      gsad_http_send_response_for_content (
        connection, ERROR_PAGE, MHD_HTTP_METHOD_NOT_ALLOWED, NULL,
        GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
      return MHD_YES;
    }

  return gsad_http_handler_call (handler_next, connection, con_info, data);
}

/**
 * Internal function for getting user information from the connection.
 *
 * @param[in] connection The HTTP connection for which the request was made
 * @param[out] user The user information retrieved from the connection
 *
 * @return 0 on success, otherwise an error code indicating the type of error
 * that occurred while getting the user information.
 */
static int
get_user_from_connection (gsad_http_connection_t *connection, user_t **user)
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

/**
 * @brief Handler for getting user information for incoming HTTP requests.
 *
 * This handler gets user information from the connection and passes it to the
 * next handler in the chain. If the user is not logged in, NULL will be passed
 * to the next handler.
 *
 * @param[in] handler_next The next handler in the chain
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data to pass to the next handler (not used in this
 * handler)
 *
 * @return Result value from the next handler in the chaing
 */
gsad_http_result_t
gsad_http_handle_get_user (gsad_http_handler_t *handler_next,
                           void *handler_data,
                           gsad_http_connection_t *connection,
                           gsad_connection_info_t *con_info, void *data)
{
  user_t *user = NULL;
  get_user_from_connection (connection, &user);
  return gsad_http_handler_call (handler_next, connection, con_info, user);
}

/**
 * @brief Handler for setting up user information for incoming HTTP requests.
 *
 * This handler gets user information from the connection and passes it to the
 * next handler in the chain. If the user is not logged in, it sends a
 * reauthentication response.
 *
 * @param[in] handler_next The next handler in the chain
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data to pass to the next handler (not used in this
 * handler)
 *
 * @return Result value from the next handler in the chain or MHD_NO if an error
 * occurred while getting the user information or sending the reauthentication
 * response.
 */
gsad_http_result_t
gsad_http_handle_setup_user (gsad_http_handler_t *handler_next,
                             void *handler_data,
                             gsad_http_connection_t *connection,
                             gsad_connection_info_t *con_info, void *data)
{
  int ret;
  int http_response_code = MHD_HTTP_OK;
  gsad_authentication_reason_t auth_reason;

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

  return gsad_http_handler_call (handler_next, connection, con_info, user);
}

/**
 * @brief Handler for setting up user credentials for incoming HTTP requests.
 *
 * It takes the user information from the previous handler, creates credentials
 * for that user, and passes the credentials to the next handler in the chain.
 * If there is an error while setting up the credentials, it sends an
 * appropriate HTTP response.
 *
 * @param[in] handler_next The next handler in the chain
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data The user information passed from the previous handler
 * (requires the gsad_http_handle_get_user handler to be called before this
 * handler in the handler chain)
 *
 * @return Result value from the next handler in the chain
 */
gsad_http_result_t
gsad_http_handle_setup_credentials (gsad_http_handler_t *handler_next,
                                    void *handler_data,
                                    gsad_http_connection_t *connection,
                                    gsad_connection_info_t *con_info,
                                    void *data)
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

  return gsad_http_handler_call (handler_next, connection, con_info,
                                 credentials);
}

/**
 * @brief Handler for processing logout requests
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data The user making the logout request (requires the
 * gsad_http_handle_get_user and gsad_http_handle_setup_user handlers to be
 * called before this handler in the handler chain)
 *
 * @return MHD_YES after processing the logout request or MHD_NO if an error
 * occurred
 */
gsad_http_result_t
gsad_http_handle_logout (gsad_http_handler_t *handler_next, void *handler_data,
                         gsad_http_connection_t *connection,
                         gsad_connection_info_t *con_info, void *data)
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

/**
 * @brief Handler for processing /gmp GET requests
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data The credentials of the user making the request (requires the
 * gsad_http_handle_setup_credentials handler to be called before this handler
 * in the handler chain)
 *
 * @return MHD_YES after processing the request or MHD_NO if an error occurred
 */
gsad_http_result_t
gsad_http_handle_gmp_get (gsad_http_handler_t *handler_next, void *handler_data,
                          gsad_http_connection_t *connection,
                          gsad_connection_info_t *con_info, void *data)
{
  /* URL requests to run GMP command. */
  credentials_t *credentials = (credentials_t *) data;

  int ret = exec_gmp_get (connection, con_info, credentials);

  credentials_free (credentials);
  return ret;
}

/**
 * @brief Handler for processing /gmp POST requests
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data passed to the handler (not used in this
 * handler)
 *
 * @return MHD_YES after processing the request or MHD_NO if an error occurred
 */
gsad_http_result_t
gsad_http_handle_gmp_post (gsad_http_handler_t *handler_next,
                           void *handler_data,
                           gsad_http_connection_t *connection,
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

/**
 * @brief Serve the system report
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data The credentials of the user making the request (requires the
 * gsad_http_handle_setup_credentials handler to be called before this handler
 * in the handler chain)
 *
 * @return MHD_YES after sending the response or MHD_NO if an error occurred
 * while sending the response
 */
gsad_http_result_t
gsad_http_handle_system_report (gsad_http_handler_t *handler_next,
                                void *handler_data,
                                gsad_http_connection_t *connection,
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

/**
 * @brief Serve the index.html page for the requested URL.
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data passed to the handler (not used in this
 * handler)
 *
 * @return MHD_YES after sending the response or MHD_NO if an error occurred
 * while sending the response
 */
gsad_http_result_t
gsad_http_handle_index (gsad_http_handler_t *handler_next, void *handler_data,
                        gsad_http_connection_t *connection,
                        gsad_connection_info_t *con_info, void *data)
{
  gsad_http_response_t *response;
  cmd_response_data_t *response_data;

  response_data = cmd_response_data_new ();
  cmd_response_data_set_allow_caching (response_data, FALSE);

  const gchar *url = gsad_connection_info_get_url (con_info);

  g_debug ("Returning index page for url %s", url);

  response = gsad_http_create_file_content_response (
    connection, url, "index.html", response_data);
  return gsad_http_send_response (connection, response, response_data, NULL);
}

/**
 * @brief Handler for serving static files based on the requested URL.
 *
 * If the file is not found, a 404 response with the index.html page will be
 * sent. Otherwise, the file content will be served with appropriate headers.
 * The next handler in the chain will not be called, as this handler handles the
 * request completely.
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data passed to the handler (not used in this
 * handler)
 *
 * @return MHD_YES after sending the response or MHD_NO if an error occurred
 * while sending the response
 */
gsad_http_result_t
gsad_http_handle_static_file (gsad_http_handler_t *handler_next,
                              void *handler_data,
                              gsad_http_connection_t *connection,
                              gsad_connection_info_t *con_info, void *data)
{
  gchar *path;
  gsad_http_response_t *response;
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

/**
 * @brief Handler for serving static content based on the requested URL.
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data passed to the handler (not used in this
 * handler)
 *
 * @return MHD_YES after sending the response or MHD_NO if an error occurred
 * while sending the response
 */
gsad_http_result_t
gsad_http_handle_static_content (gsad_http_handler_t *handler_next,
                                 void *handler_data,
                                 gsad_http_connection_t *connection,
                                 gsad_connection_info_t *con_info, void *data)
{
  gchar *path;
  gsad_http_response_t *response;
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

/**
 * @brief Handler for serving static config.js files.
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data passed to the handler (not used in this
 * handler)
 *
 * @return MHD_YES after sending the response or MHD_NO if an error occurred
 * while sending the response
 */
gsad_http_result_t
gsad_http_handle_static_config (gsad_http_handler_t *handler_next,
                                void *handler_data,
                                gsad_http_connection_t *connection,
                                gsad_connection_info_t *con_info, void *data)
{
  gchar *path;
  gsad_http_response_t *response;
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

/**
 * @brief Handler for returning a 404 Not Found response
 *
 * @param[in] handler_next The next handler in the chain (not used in this
 * handler)
 * @param[in] handler_data Data associated with this handler (not used in this
 * handler)
 * @param[in] connection The HTTP connection for which the request was made
 * @param[in] con_info Information about the HTTP connection, including the
 * requested URL
 * @param[in] data Additional data passed to the handler (not used in this
 * handler)
 *
 * @return MHD_YES after sending the response or MHD_NO if an error occurred
 * while sending the response
 */
gsad_http_result_t
gsad_http_handle_not_found (gsad_http_handler_t *handler_next,
                            void *handler_data,
                            gsad_http_connection_t *connection,
                            gsad_connection_info_t *con_info, void *data)
{
  const gchar *url = gsad_connection_info_get_url (con_info);

  g_debug ("Returning not found for url %s", url);

  cmd_response_data_t *response_data = cmd_response_data_new ();
  gsad_http_response_t *response =
    gsad_http_create_not_found_response (response_data);
  return gsad_http_send_response (connection, response, response_data, NULL);
}

/**
 * @brief Initialize the basic HTTP parameter validator.
 */
void
gsad_http_init_validator (void)
{
  http_validator = gvm_validator_new ();
  gvm_validator_add (http_validator, "slave_id", SLAVE_ID_REGEXP);
  gvm_validator_add (http_validator, "token", TOKEN_REGEXP);
}

/**
 * @brief Clean up the basic HTTP parameter validator.
 */
void
gsad_http_cleanup_validator (void)
{
  gvm_validator_free (http_validator);
}
