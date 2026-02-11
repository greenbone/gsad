/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_http.h
 * @brief HTTP handling of GSA.
 */

#ifndef _GSAD_HTTP_H
#define _GSAD_HTTP_H

#include "gsad_cmd.h"             /* for cmd_response_data_t */
#include "gsad_connection_info.h" /* for gsad_connection_info_t */
#include "gsad_content_type.h"    /* for content_type_t */
#include "gsad_credentials.h"     /* for credentials_t */
#include "gsad_user.h"            /* for user_t */

#include <glib.h>
#include <microhttpd.h>

/**
 * @brief At least maximum length of rfc2822 format date.
 */
#define DATE_2822_LEN 100

/**
 * @brief Max length of cookie expires param.
 */
#define EXPIRES_LENGTH 100

/*
 * UTF-8 Error page HTML.
 */
#define UTF8_ERROR_PAGE(location)                                     \
  "<html>"                                                            \
  "<head><title>Invalid request</title></head>"                       \
  "<body>The request contained invalid UTF-8 in " location ".</body>" \
  "</html>"

/**
 * @brief Name of the cookie used to store the SID.
 */
#define SID_COOKIE_NAME "GSAD_SID"

#define REMOVE_SID "0"

/**
 * @brief Title for "Page not found" messages.
 */
#define NOT_FOUND_TITLE "Invalid request"

/**
 * @brief Main message for "Page not found" messages.
 */
#define NOT_FOUND_MESSAGE "The requested page or file does not exist."

/**
 * @brief Error page HTML.
 */
#define ERROR_PAGE "<html><body>HTTP Method not supported</body></html>"

/**
 * @brief Bad request error HTML.
 */
#define BAD_REQUEST_PAGE "<html><body>Bad request.</body></html>"

/**
 * @brief Server error HTML.
 */
#define SERVER_ERROR \
  "<html><body>An internal server error has occurred.</body></html>"

#undef MAX_HOST_LEN

/**
 * @brief Maximum length of the host portion of the redirect address.
 */
#define MAX_HOST_LEN 1000

#define LOGIN_URL "/login"
#define LOGOUT_URL "/logout"

/**
 * @brief Buffer size for POST processor.
 */
#define POST_BUFFER_SIZE 500000

/**
 * @brief The symbol is deprecated, but older versions (0.9.37 - Debian
 * jessie) don't define it yet.
 */
#ifndef MHD_HTTP_NOT_ACCEPTABLE
#define MHD_HTTP_NOT_ACCEPTABLE MHD_HTTP_METHOD_NOT_ACCEPTABLE
#endif

/**
 * @brief Maximum length of "file name" for /help/ URLs.
 */
#define MAX_FILE_NAME_SIZE 128

typedef struct MHD_Connection http_connection_t;

typedef struct MHD_Response http_response_t;

#if MHD_VERSION < 0x00097002
typedef int http_result_t;
#else
typedef enum MHD_Result http_result_t;
#endif

content_type_t
guess_content_type (const gchar *path);

void
gsad_add_content_type_header (http_response_t *response, content_type_t *ct);

http_result_t
handler_create_response (http_connection_t *connection, gchar *data,
                         cmd_response_data_t *response_data, const gchar *sid);

http_result_t
handler_send_response (http_connection_t *connection, http_response_t *response,
                       cmd_response_data_t *response_data, const gchar *sid);

/**
 * @brief Content types.
 */
enum authentication_reason
{
  LOGIN_FAILED,
  LOGIN_ERROR,
  LOGOUT,
  LOGOUT_ALREADY,
  GMP_SERVICE_DOWN,
  SESSION_EXPIRED,
  BAD_MISSING_COOKIE,
  BAD_MISSING_TOKEN,
  TOO_MANY_USER_SESSIONS,
  UNKOWN_ERROR,
};

typedef enum authentication_reason authentication_reason_t;

http_result_t
handler_send_reauthentication (http_connection_t *connection,
                               int http_status_code,
                               authentication_reason_t reason);

http_result_t
send_response (http_connection_t *connection, const char *content,
               int status_code, const gchar *sid, content_type_t content_type,
               const char *content_disposition, size_t content_length);

http_result_t
send_redirect_to_uri (http_connection_t *connection, const char *uri,
                      const gchar *sid);

void
add_security_headers (http_response_t *response);

void
add_guest_chart_content_security_headers (http_response_t *response);

void
add_cors_headers (http_response_t *response);

void
add_forbid_caching_headers (http_response_t *response);

/* helper functions required in gsad_http */
http_response_t *
file_content_response (http_connection_t *connection, const char *url,
                       const char *path, cmd_response_data_t *response_data);

gchar *
reconstruct_url (http_connection_t *connection, const char *url);

int
get_client_address (http_connection_t *conn, char *client_address);

http_result_t
serve_post (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
            const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, uint64_t off,
            size_t size);

http_result_t
remove_sid (http_response_t *response);

http_result_t
attach_sid (http_response_t *response, const char *sid);

http_result_t
attach_remove_sid (http_response_t *response, const gchar *sid);

/* exec_gmp functions are still in gsad.c */
http_result_t
exec_gmp_get (http_connection_t *connection, gsad_connection_info_t *con_info,
              credentials_t *credentials);

http_result_t
exec_gmp_post (http_connection_t *connection, gsad_connection_info_t *con_info,
               const gchar *client_address);

gchar *
gsad_message (credentials_t *, const gchar *, const gchar *, int, const gchar *,
              cmd_response_data_t *);

#endif /* _GSAD_HTTP_H */
