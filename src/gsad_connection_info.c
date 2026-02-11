/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_connection_info.h"

struct gsad_connection_info
{
  struct MHD_PostProcessor *postprocessor; ///< POST processor.
  params_t *params;                        ///< Request parameters.
  char *cookie;                            ///< Value of SID cookie param.
  char *language;                          ///< Language code e.g. en
  enum method_type method_type;            ///< 1=POST, 2=GET.
  gchar *redirect;                         ///< Redirect URL.
};

gsad_connection_info_t *
gsad_connection_info_new (enum method_type method_type)
{
  gsad_connection_info_t *con_info =
    g_malloc0 (sizeof (gsad_connection_info_t));
  con_info->postprocessor = NULL;
  con_info->params = params_new ();
  con_info->cookie = NULL;
  con_info->language = NULL;
  con_info->method_type = method_type;
  con_info->redirect = NULL;
  return con_info;
}

void
gsad_connection_info_free (gsad_connection_info_t *con_info)
{
  if (con_info == NULL)
    return;

  if (con_info->postprocessor != NULL)
    MHD_destroy_post_processor (con_info->postprocessor);

  params_free (con_info->params);
  g_free (con_info->cookie);
  g_free (con_info->language);
  g_free (con_info->redirect);
  g_free (con_info);
}

params_t *
gsad_connection_info_get_params (const gsad_connection_info_t *con_info)
{
  return con_info->params;
}

struct MHD_PostProcessor *
gsad_connection_info_get_postprocessor (const gsad_connection_info_t *con_info)
{
  return con_info->postprocessor;
}

void
gsad_connection_info_set_postprocessor (gsad_connection_info_t *con_info,
                                        struct MHD_PostProcessor *postprocessor)
{
  con_info->postprocessor = postprocessor;
}

const gchar *
gsad_connection_info_get_cookie (const gsad_connection_info_t *con_info)
{
  return con_info->cookie;
}

void
gsad_connection_info_set_cookie (gsad_connection_info_t *con_info,
                                 const gchar *cookie)
{
  g_free (con_info->cookie);
  con_info->cookie = g_strdup (cookie);
}

const gchar *
gsad_connection_info_get_language (const gsad_connection_info_t *con_info)
{
  return con_info->language;
}

void
gsad_connection_info_set_language (gsad_connection_info_t *con_info,
                                   const gchar *language)
{
  g_free (con_info->language);
  con_info->language = g_strdup (language);
}
