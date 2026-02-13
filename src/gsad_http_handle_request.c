/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_http.h"
#include "gsad_http_handler.h"
#include "gsad_http_handler_functions.h"
#include "gsad_http_method_handler.h"
#include "gsad_http_url_handler.h"
#include "gsad_params_mhd.h" /* for params_mhd_add */
#include "utils.h"           /* for str_equal */
#include "validator.h"       /* for gvm_validator_t */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "gsad http handle request"

/**
 * @brief Global HTTP handler chain.
 *
 * This is initialized in init_http_handlers and cleaned up in
 * gsad_http_request_cleanup_handlers in the atexit function.
 */
gsad_http_handler_t *global_handlers;

static gsad_http_handler_t *
make_url_handlers ()
{
  gsad_http_handler_t *url_handlers;
  gsad_http_handler_t *gmp_handler, *gmp_url_handler;
  gsad_http_handler_t *system_report_handler, *system_report_url_handler;
  gsad_http_handler_t *logout_handler, *logout_url_handler;
  gsad_http_handler_t *next;

  url_handlers = gsad_http_url_handler_from_func ("^/(img|js|css|locales)/.+$",
                                                  gsad_http_handle_static_file);
  next = gsad_http_handler_set_next (
    url_handlers, gsad_http_url_handler_from_func (
                    "^/robots\\.txt$", gsad_http_handle_static_file));
  next = gsad_http_handler_set_next (
    next, gsad_http_url_handler_from_func ("^/config\\.*js$",
                                           gsad_http_handle_static_config));
  next = gsad_http_handler_set_next (
    next, gsad_http_url_handler_from_func ("^/assets/.+$",
                                           gsad_http_handle_static_file));
  next = gsad_http_handler_set_next (
    next, gsad_http_url_handler_from_func ("^/static/(img|js|css|media)/.+$",
                                           gsad_http_handle_static_file));
  next = gsad_http_handler_set_next (
    next, gsad_http_url_handler_from_func ("^/manual/.+$",
                                           gsad_http_handle_static_content));

  // Create /gmp handler chain.

  gmp_handler = gsad_http_handler_new (gsad_http_handle_setup_user);
  gsad_http_handler_add (
    gmp_handler, gsad_http_handler_new (gsad_http_handle_setup_credentials));
  gsad_http_handler_add (gmp_handler,
                         gsad_http_handler_new (gsad_http_handle_gmp_get));
  gmp_url_handler = gsad_http_url_handler_new ("^/gmp$", gmp_handler);
  next = gsad_http_handler_set_next (next, gmp_url_handler);

  // Create /system_report handler chain.

  system_report_handler = gsad_http_handler_new (gsad_http_handle_setup_user);
  gsad_http_handler_add (
    system_report_handler,
    gsad_http_handler_new (gsad_http_handle_setup_credentials));
  gsad_http_handler_add (
    system_report_handler,
    gsad_http_handler_new (gsad_http_handle_system_report));
  system_report_url_handler =
    gsad_http_url_handler_new ("^/system_report/.+$", system_report_handler);
  next = gsad_http_handler_set_next (next, system_report_url_handler);

  // Create /logout handler chain.

  logout_handler = gsad_http_handler_new (gsad_http_handle_get_user);
  gsad_http_handler_add (logout_handler,
                         gsad_http_handler_new (gsad_http_handle_logout));
  logout_url_handler =
    gsad_http_url_handler_new ("^/logout/?$", logout_handler);
  next = gsad_http_handler_set_next (next, logout_url_handler);

  // fallback to index handler
  gsad_http_handler_set_next (next,
                              gsad_http_handler_new (gsad_http_handle_index));

  return url_handlers;
}

gsad_http_handler_t *
gsad_http_request_init_handlers ()
{
  gsad_http_handler_t *method_router, *gmp_post_handler, *url_handlers;
  gsad_http_init_validator ();

  global_handlers = gsad_http_handler_new (gsad_http_handle_validate);

  method_router = gsad_http_method_handler_new ();
  gmp_post_handler = gsad_http_handler_new (gsad_http_handle_gmp_post);

  gsad_http_handler_add (global_handlers, method_router);

  url_handlers = make_url_handlers ();

  gsad_http_method_handler_set_get_handler (method_router, url_handlers);
  gsad_http_method_handler_set_post_handler (method_router, gmp_post_handler);

  gsad_http_handler_add (
    global_handlers, gsad_http_handler_new (gsad_http_handle_invalid_method));

  return global_handlers;
}

/**
 * @brief Cleanup routine for HTTP handlers.
 *
 * Cleanup the global HTTP handler chain and the validator. This is registered
 * as an atexit function in gsad.c, so it will be called when the program exits.
 * It is also called manually in gsad.c during shutdown.
 */
void
gsad_http_request_cleanup_handlers ()
{
  g_debug ("Cleaning up http handlers");

  gsad_http_handler_free (global_handlers);
  global_handlers = NULL;

  gsad_http_cleanup_validator ();
}

/**
 * @brief HTTP request handler for gsad.
 *
 * This routine is an MHD_AccessHandlerCallback, the request handler for
 * microhttpd. It is called by microhttpd for each HTTP request. It dispatches
 * the request to the appropriate handler based on the URL and HTTP method. It
 * also performs some basic validation of the request and sets up
 * connection-related data.
 *
 * @param[in]  cls              A pointer to http_handler_t
 * @param[in]  connection       Connection handle, e.g. used to send response.
 * @param[in]  url              The URL requested.
 * @param[in]  method           "GET" or "POST", others are disregarded.
 * @param[in]  version          Not used for this callback.
 * @param[in]  upload_data      Data used for POST requests.
 * @param[in]  upload_data_size Size of upload_data.
 * @param[out] con_cls          For exchange of connection-related data
 *                              (here a struct gsad_connection_info).
 *
 * @return MHD_NO in case of problems. MHD_YES if all is OK.
 */
gsad_http_result_t
gsad_http_handle_request (void *cls, gsad_http_connection_t *connection,
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls)
{
  gsad_connection_info_t *con_info = *con_cls;
  gsad_http_handler_t *handlers = (gsad_http_handler_t *) cls;
  gboolean new_connection = (con_info == NULL);

  if (handlers == NULL)
    {
      g_critical ("No handlers found, cannot handle request");
      return MHD_NO;
    }

  /* Never respond on first call of a GET. */
  if (new_connection)
    {
      if ((str_equal (method, "GET")))
        {
          /* First call for this request, a GET. */

          /* Freed by MHD_OPTION_NOTIFY_COMPLETED callback, free_resources. */
          con_info = gsad_connection_info_new (METHOD_TYPE_GET, url);
          params_t *params = gsad_connection_info_get_params (con_info);
          MHD_get_connection_values (connection, MHD_GET_ARGUMENT_KIND,
                                     params_mhd_add, params);
          params_mhd_validate (params);

          *con_cls = (void *) con_info;
          return MHD_YES;
        }
      if (str_equal (method, "POST"))
        {
          /* First call for this request, a POST. */

          con_info = gsad_connection_info_new (METHOD_TYPE_POST, url);

          /* Freed by MHD_OPTION_NOTIFY_COMPLETED callback, free_resources. */
          struct MHD_PostProcessor *postprocessor = MHD_create_post_processor (
            connection, POST_BUFFER_SIZE, serve_post, (void *) con_info);

          if (postprocessor == NULL)
            {
              /* Both bad request or running out of memory will lead here, but
               * we return the Bad Request page always, to prevent bad requests
               * from leading to "Internal application error" in the log. */
              gsad_http_send_response_for_content (
                connection, BAD_REQUEST_PAGE, MHD_HTTP_NOT_ACCEPTABLE, NULL,
                GSAD_CONTENT_TYPE_TEXT_HTML, NULL, 0);
              gsad_connection_info_free (con_info);
              return MHD_YES;
            }

          gsad_connection_info_set_postprocessor (con_info, postprocessor);

          *con_cls = (void *) con_info;
          return MHD_YES;
        }

      con_info = gsad_connection_info_new (METHOD_TYPE_UNKNOWN, url);
      *con_cls = (void *) con_info;
      return MHD_YES;
    }

  if (gsad_connection_info_get_method_type (con_info) == METHOD_TYPE_POST)
    {
      /* Second or later call for this request, a POST. */
      if (*upload_data_size != 0)
        {
          MHD_post_process (gsad_connection_info_get_postprocessor (con_info),
                            upload_data, *upload_data_size);
          *upload_data_size = 0;
          return MHD_YES;
        }
    }

  g_debug ("Handling %s request for %s", method, url);

  return gsad_http_handler_call (handlers, connection, con_info, NULL);
}
