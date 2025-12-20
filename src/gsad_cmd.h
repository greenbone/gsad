/* Copyright (C) 2016-2021 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_cmd.h
 * @brief Headers for Response Data struct
 */

#ifndef _GSAD_CMD_H
#define _GSAD_CMD_H

#include "gsad_content_type.h" /* for content_type_t */

#include <glib.h>

typedef struct cmd_response_data cmd_response_data_t;

cmd_response_data_t *
cmd_response_data_new ();

void
cmd_response_data_free (cmd_response_data_t *data);

void
cmd_response_data_set_allow_caching (cmd_response_data_t *data,
                                     gboolean allow_caching);

gboolean
cmd_response_data_is_allow_caching (cmd_response_data_t *data);

void
cmd_response_data_set_content_type (cmd_response_data_t *data,
                                    content_type_t content_type);

content_type_t
cmd_response_data_get_content_type (cmd_response_data_t *data);

void
cmd_response_data_set_status_code (cmd_response_data_t *data,
                                   int http_status_code);

int
cmd_response_data_get_status_code (cmd_response_data_t *data);

void
cmd_response_data_set_content_length (cmd_response_data_t *data,
                                      gsize content_length);

gsize
cmd_response_data_get_content_length (cmd_response_data_t *data);

void
cmd_response_data_set_content_disposition (cmd_response_data_t *data,
                                           gchar *content_disposition);

const gchar *
cmd_response_data_get_content_disposition (cmd_response_data_t *data);

void
cmd_response_data_set_content_type_string (cmd_response_data_t *data,
                                           gchar *content_type_string);

const gchar *
cmd_response_data_get_content_type_string (cmd_response_data_t *data);
#endif /* not _GSAD_CMD_H */
