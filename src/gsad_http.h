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

typedef struct MHD_Connection gsad_http_connection_t;

typedef struct MHD_Response gsad_http_response_t;

#if MHD_VERSION < 0x00097002
typedef int gsad_http_result_t;
#else
typedef enum MHD_Result gsad_http_result_t;
#endif

content_type_t
gsad_http_guess_content_type (const gchar *);

gsad_http_result_t
gsad_http_create_response (gsad_http_connection_t *, gchar *,
                           cmd_response_data_t *, const gchar *);

gsad_http_result_t
gsad_http_send_response (gsad_http_connection_t *, gsad_http_response_t *,
                         cmd_response_data_t *, const gchar *);

/**
 * @brief Content types.
 */
typedef enum gsad_authentication_reason
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
  UNKNOWN_ERROR,
} gsad_authentication_reason_t;

gsad_http_result_t
gsad_http_send_reauthentication (gsad_http_connection_t *, int,
                                 gsad_authentication_reason_t);

gsad_http_result_t
gsad_http_send_response_for_content (gsad_http_connection_t *, const gchar *,
                                     int, const gchar *, content_type_t,
                                     const gchar *, size_t);

gsad_http_result_t
gsad_http_send_redirect_to_uri (gsad_http_connection_t *, const gchar *,
                                const gchar *);

void
gsad_http_add_security_headers (gsad_http_response_t *);

void
gsad_http_add_guest_chart_content_security_headers (gsad_http_response_t *);

void
gsad_http_add_cors_headers (gsad_http_response_t *);

void
gsad_http_add_forbid_caching_headers (gsad_http_response_t *);

void
gsad_http_add_content_type_header (gsad_http_response_t *, content_type_t *);

gsad_http_response_t *
gsad_http_create_file_content_response (gsad_http_connection_t *, const gchar *,
                                        const gchar *, cmd_response_data_t *);

/* helper functions required in gsad_http */
int
get_client_address (gsad_http_connection_t *conn, char *client_address);

gsad_http_result_t
serve_post (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
            const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, uint64_t off,
            size_t size);

gsad_http_result_t
remove_sid (gsad_http_response_t *response);

gsad_http_result_t
attach_sid (gsad_http_response_t *response, const char *sid);

gsad_http_result_t
attach_remove_sid (gsad_http_response_t *response, const gchar *sid);

/* exec_gmp functions are still in gsad.c */
gsad_http_result_t
exec_gmp_get (gsad_http_connection_t *connection,
              gsad_connection_info_t *con_info, credentials_t *credentials);

gsad_http_result_t
exec_gmp_post (gsad_http_connection_t *connection,
               gsad_connection_info_t *con_info, const gchar *client_address);

gchar *
gsad_message (credentials_t *, const gchar *, const gchar *, int, const gchar *,
              cmd_response_data_t *);

#endif /* _GSAD_HTTP_H */
