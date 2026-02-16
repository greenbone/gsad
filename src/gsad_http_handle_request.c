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

gsad_http_handler_t *
gsad_http_request_init_handlers ()
{
  gsad_http_init_validator ();

  global_handlers = gsad_http_handler_new (gsad_http_handle_validate);

  gsad_http_handler_t *url_handlers = NULL;
  gsad_http_handler_t *next = NULL;

  // Create /gmp POST and GET handler chain.
  gsad_http_handler_t *gmp_post_handler =
    gsad_http_handler_new (gsad_http_handle_gmp_post);
  gsad_http_handler_t *gmp_get_handler =
    gsad_http_handler_new (gsad_http_handle_setup_user);
  gsad_http_handler_add_from_func (gmp_get_handler,
                                   gsad_http_handle_setup_credentials);
  gsad_http_handler_add_from_func (gmp_get_handler, gsad_http_handle_gmp_get);
  gsad_http_handler_t *gmp_url_handler = gsad_http_url_handler_new (
    "^/gmp$", gsad_http_method_handler_new_with_handlers (gmp_get_handler,
                                                          gmp_post_handler));
  url_handlers = gsad_http_handler_add (url_handlers, gmp_url_handler);

  // Create static file handlers for various URL patterns.
  gsad_http_handler_t *image_url_handler = gsad_http_url_handler_new (
    "^/(img|js|css|locales)/.+$",
    gsad_http_method_handler_new_get_from_func (gsad_http_handle_static_file));
  next = gsad_http_handler_add (url_handlers, image_url_handler);

  gsad_http_handler_t *robots_url_handler = gsad_http_url_handler_new (
    "^/robots\\.txt$",
    gsad_http_method_handler_new_get_from_func (gsad_http_handle_static_file));
  next = gsad_http_handler_add (next, robots_url_handler);

  gsad_http_handler_t *favicon_url_handler = gsad_http_url_handler_new (
    "^/favicon\\.ico$",
    gsad_http_method_handler_new_get_from_func (gsad_http_handle_static_file));
  next = gsad_http_handler_add (next, favicon_url_handler);

  gsad_http_handler_t *config_js_handler = gsad_http_url_handler_new (
    "^/config\\.*js$", gsad_http_method_handler_new_get_from_func (
                         gsad_http_handle_static_config));
  next = gsad_http_handler_add (next, config_js_handler);

  gsad_http_handler_t *assets_url_handler = gsad_http_url_handler_new (
    "^/assets/.+$",
    gsad_http_method_handler_new_get_from_func (gsad_http_handle_static_file));
  next = gsad_http_handler_add (next, assets_url_handler);

  gsad_http_handler_t *static_url_handler = gsad_http_url_handler_new (
    "^/static/(img|js|css|media)/.+$",
    gsad_http_method_handler_new_get_from_func (gsad_http_handle_static_file));
  next = gsad_http_handler_add (next, static_url_handler);

  gsad_http_handler_t *manual_handler = gsad_http_url_handler_new (
    "^/manual/.+$", gsad_http_method_handler_new_get_from_func (
                      gsad_http_handle_static_content));
  next = gsad_http_handler_add (next, manual_handler);

  // Create /system_report handler
  // chain.
  gsad_http_handler_t *system_report_handler =
    gsad_http_handler_new (gsad_http_handle_setup_user);
  gsad_http_handler_add_from_func (system_report_handler,
                                   gsad_http_handle_setup_credentials);
  gsad_http_handler_add_from_func (system_report_handler,
                                   gsad_http_handle_system_report);
  gsad_http_handler_t *system_report_url_handler = gsad_http_url_handler_new (
    "^/system_report/.+$",
    gsad_http_method_handler_new_get (system_report_handler));
  next = gsad_http_handler_add (next, system_report_url_handler);

  // Create /logout handler chain.
  gsad_http_handler_t *logout_handler =
    gsad_http_handler_new (gsad_http_handle_get_user);
  gsad_http_handler_add_from_func (logout_handler, gsad_http_handle_logout);
  gsad_http_handler_t *logout_url_handler = gsad_http_url_handler_new (
    "^/logout/?$", gsad_http_method_handler_new_get (logout_handler));
  next = gsad_http_handler_add (next, logout_url_handler);

  // fallback to index handler for get requests
  gsad_http_handler_t *index_url_handler = gsad_http_url_handler_new (
    "^/.*$", gsad_http_method_handler_new_with_handlers (
               // get
               gsad_http_handler_new (gsad_http_handle_index),
               // post
               gsad_http_handler_new (gsad_http_handle_not_found)));
  next = gsad_http_handler_add (next, index_url_handler);
  next =
    gsad_http_handler_add_from_func (next, gsad_http_handle_invalid_method);

  gsad_http_handler_add (global_handlers, url_handlers);

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
