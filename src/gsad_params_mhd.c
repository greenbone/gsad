/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gsad_params_mhd.h"

#include "gsad_validator.h" /* for validator_t */

/**
 * @brief Append a chunk to a request parameter.
 *
 * @param[in]   params        Request parameters.
 * @param[out]  name          Parameter.
 * @param[out]  filename      Filename if uploaded file.
 * @param[in]   chunk_data    Incoming chunk data.
 * @param[out]  chunk_size    Size of chunk.
 * @param[out]  chunk_offset  Offset into all data.
 */
http_result_t
params_mhd_append (params_t *params, const gchar *name, const gchar *filename,
                   const gchar *chunk_data, int chunk_size, int chunk_offset)
{
  if ((strncmp (name, "bulk_selected:", strlen ("bulk_selected:")) == 0)
      || (strncmp (name, "chart_gen:", strlen ("chart_gen:")) == 0)
      || (strncmp (name, "chart_init:", strlen ("chart_init:")) == 0)
      || (strncmp (name, "condition_data:", strlen ("condition_data:")) == 0)
      || (strncmp (name, "data_columns:", strlen ("data_columns:")) == 0)
      || (strncmp (name, "event_data:", strlen ("event_data:")) == 0)
      || (strncmp (name, "settings_changed:", strlen ("settings_changed:"))
          == 0)
      || (strncmp (name, "settings_default:", strlen ("settings_default:"))
          == 0)
      || (strncmp (name, "settings_filter:", strlen ("settings_filter:")) == 0)
      || (strncmp (name, "exclude_file:", strlen ("exclude_file:")) == 0)
      || (strncmp (name, "file:", strlen ("file:")) == 0)
      || (strncmp (name, "include_id_list:", strlen ("include_id_list:")) == 0)
      || (strncmp (name, "parameter:", strlen ("parameter:")) == 0)
      || (strncmp (name, "param:", strlen ("param:")) == 0)
      || (strncmp (name,
                   "param_using_default:", strlen ("param_using_default:"))
          == 0)
      || (strncmp (name, "password:", strlen ("password:")) == 0)
      || (strncmp (name, "preference:", strlen ("preference:")) == 0)
      || (strncmp (name, "select:", strlen ("select:")) == 0)
      || (strncmp (name, "text_columns:", strlen ("text_columns:")) == 0)
      || (strncmp (name, "trend:", strlen ("trend:")) == 0)
      || (strncmp (name, "method_data:", strlen ("method_data:")) == 0)
      || (strncmp (name, "nvt:", strlen ("nvt:")) == 0)
      || (strncmp (name, "alert_id_optional:", strlen ("alert_id_optional:"))
          == 0)
      || (strncmp (name, "group_id_optional:", strlen ("group_id_optional:"))
          == 0)
      || (strncmp (name, "role_id_optional:", strlen ("role_id_optional:"))
          == 0)
      || (strncmp (name, "related:", strlen ("related:")) == 0)
      || (strncmp (name, "sort_fields:", strlen ("sort_fields:")) == 0)
      || (strncmp (name, "sort_orders:", strlen ("sort_orders:")) == 0)
      || (strncmp (name, "sort_stats:", strlen ("sort_stats:")) == 0)
      || (strncmp (name, "y_fields:", strlen ("y_fields:")) == 0)
      || (strncmp (name, "z_fields:", strlen ("z_fields:")) == 0))
    {
      param_t *param;
      const gchar *colon;
      gchar *prefix;

      colon = strchr (name, ':');

      /* Hashtable param, like for radios. */

      if ((colon - name) == (strlen (name) - 1))
        {
          /* name: "example:", value "abc". */

          params_append_bin (params, name, chunk_data, chunk_size);

          return MHD_YES;
        }

      /* name: "nvt:1.3.6.1.4.1.25623.1.0.105058", value "1". */

      prefix = g_strndup (name, 1 + colon - name);
      param = params_get (params, prefix);

      if (param == NULL)
        {
          param = params_add (params, prefix, "");
          param->values = params_new ();
        }
      else if (param->values == NULL)
        param->values = params_new ();

      g_free (prefix);

      params_append_bin (param->values, colon + 1, chunk_data, chunk_size);
      if (filename)
        {
          g_free (param->filename);
          param->filename = g_strdup (filename);
        }

      return MHD_YES;
    }

  /*
   * Array param
   * Can be accessed like a hashtable param,with ascending numbers as the
   *  key, which are automatically generated instead of being part of the
   *  full name.
   * For example multiple instances of "x:" in the request
   *  become "x:1", "x:2", "x:3", etc.
   */
  if ((strcmp (name, "alert_ids:") == 0) || (strcmp (name, "role_ids:") == 0)
      || (strcmp (name, "group_ids:") == 0)
      || (strcmp (name, "report_format_ids:") == 0)
      || (strcmp (name, "id_list:") == 0)
      || (strcmp (name, "resource_ids:") == 0) || (strcmp (name, "kdcs:") == 0)
      || (strcmp (name, "agent_ids:") == 0)
      || (strcmp (name, "scheduler_cron_times:") == 0)
      || (strcmp (name, "alive_tests:") == 0))
    {
      param_t *param;
      gchar *index_str;

      param = params_get (params, name);

      if (param == NULL)
        {
          param = params_add (params, name, "");
          param->values = params_new ();
        }
      else if (param->values == NULL)
        param->values = params_new ();

      if (chunk_offset == 0)
        param->array_len += 1;

      index_str = g_strdup_printf ("%d", param->array_len);

      params_append_bin (param->values, index_str, chunk_data, chunk_size);

      g_free (index_str);

      if (filename && param->filename == NULL)
        param->filename = g_strdup (filename);

      return MHD_YES;
    }

  /* Single value param. */

  params_append_bin (params, name, chunk_data, chunk_size);

  return MHD_YES;
}

/**
 * @brief Add a param.
 *
 * @param[in]  params  Params.
 * @param[in]  kind    MHD header kind.
 * @param[in]  name    Name.
 * @param[in]  value   Value.
 */
http_result_t
params_mhd_add (void *params, enum MHD_ValueKind kind, const gchar *name,
                const gchar *value)
{
  if ((strncmp (name, "bulk_selected:", strlen ("bulk_selected:")) == 0)
      || (strncmp (name, "chart_gen:", strlen ("chart_gen:")) == 0)
      || (strncmp (name, "chart_init:", strlen ("chart_init:")) == 0)
      || (strncmp (name, "condition_data:", strlen ("condition_data:")) == 0)
      || (strncmp (name, "data_columns:", strlen ("data_columns:")) == 0)
      || (strncmp (name, "event_data:", strlen ("event_data:")) == 0)
      || (strncmp (name, "settings_changed:", strlen ("settings_changed:"))
          == 0)
      || (strncmp (name, "settings_default:", strlen ("settings_default:"))
          == 0)
      || (strncmp (name, "settings_filter:", strlen ("settings_filter:")) == 0)
      || (strncmp (name, "exclude_file:", strlen ("exclude_file:")) == 0)
      || (strncmp (name, "file:", strlen ("file:")) == 0)
      || (strncmp (name, "include_id_list:", strlen ("include_id_list:")) == 0)
      || (strncmp (name, "parameter:", strlen ("parameter:")) == 0)
      || (strncmp (name, "password:", strlen ("password:")) == 0)
      || (strncmp (name, "preference:", strlen ("preference:")) == 0)
      || (strncmp (name, "select:", strlen ("select:")) == 0)
      || (strncmp (name, "text_columns:", strlen ("text_columns:")) == 0)
      || (strncmp (name, "trend:", strlen ("trend:")) == 0)
      || (strncmp (name, "method_data:", strlen ("method_data:")) == 0)
      || (strncmp (name, "nvt:", strlen ("nvt:")) == 0)
      || (strncmp (name, "alert_id_optional:", strlen ("alert_id_optional:"))
          == 0)
      || (strncmp (name, "group_id_optional:", strlen ("group_id_optional:"))
          == 0)
      || (strncmp (name, "role_id_optional:", strlen ("role_id_optional:"))
          == 0)
      || (strncmp (name, "related:", strlen ("related:")) == 0)
      || (strncmp (name, "sort_fields:", strlen ("sort_fields:")) == 0)
      || (strncmp (name, "sort_orders:", strlen ("sort_orders:")) == 0)
      || (strncmp (name, "sort_stats:", strlen ("sort_stats:")) == 0)
      || (strncmp (name, "y_fields:", strlen ("y_fields:")) == 0)
      || (strncmp (name, "z_fields:", strlen ("z_fields:")) == 0))
    {
      param_t *param;
      const gchar *colon;
      gchar *prefix;
      int value_size = value ? strlen (value) : 0;

      /* Hashtable param, like for radios. */

      colon = strchr (name, ':');

      if ((colon - name) == (strlen (name) - 1))
        {
          params_append_bin (params, name, value, value_size);

          return MHD_YES;
        }

      prefix = g_strndup (name, 1 + colon - name);
      param = params_get (params, prefix);

      if (param == NULL)
        {
          param = params_add (params, prefix, "");
          param->values = params_new ();
        }
      else if (param->values == NULL)
        param->values = params_new ();

      g_free (prefix);

      params_append_bin (param->values, colon + 1, value, value_size);

      return MHD_YES;
    }

  /*
   * Array param (See params_append_mhd for a description)
   */
  if ((strcmp (name, "alert_ids:") == 0) || (strcmp (name, "role_ids:") == 0)
      || (strcmp (name, "group_ids:") == 0)
      || (strcmp (name, "report_format_ids:") == 0)
      || (strcmp (name, "id_list:") == 0) || (strcmp (name, "agent_ids:") == 0)
      || (strcmp (name, "scheduler_cron_times:") == 0)
      || (strcmp (name, "alive_tests:") == 0))
    {
      param_t *param;
      gchar *index_str;
      int value_size = value ? strlen (value) : 0;

      param = params_get (params, name);

      if (param == NULL)
        {
          param = params_add (params, name, "");
          param->values = params_new ();
        }
      else if (param->values == NULL)
        param->values = params_new ();

      param->array_len += 1;

      index_str = g_strdup_printf ("%d", param->array_len);

      params_append_bin (param->values, index_str, value, value_size);

      g_free (index_str);

      return MHD_YES;
    }

  /* Single value param. */

  params_add ((params_t *) params, name, value);
  return MHD_YES;
}

/**
 * @brief Validate param values.
 *
 * @param[in]  parent_name  Name of the parent param.
 * @param[in]  params       Values.
 */
void
params_mhd_validate_values (const gchar *parent_name, void *params)
{
  params_iterator_t iter;
  param_t *param;
  gchar *name, *name_name, *value_name;

  name_name = g_strdup_printf ("%sname", parent_name);
  value_name = g_strdup_printf ("%svalue", parent_name);
  validator_t validator = gsad_get_validator ();

  params_iterator_init (&iter, params);

  while (params_iterator_next (&iter, &name, &param))
    {
      gchar *item_name;

      if ((g_utf8_validate (name, -1, NULL) == FALSE))
        {
          param->original_value = param->value;
          param->value = NULL;
          param->value_size = 0;
          param->valid = 0;
          param->valid_utf8 = 0;
          item_name = NULL;
        }
      /* Item specific value validator like "method_data:to_adddress:". */
      else
        switch (gvm_validate (
          validator, (item_name = g_strdup_printf ("%s%s:", parent_name, name)),
          param->value))
          {
          case 0:
            param->valid_utf8 = g_utf8_validate (param->value, -1, NULL);
            break;
          case 1:
            /* General name validator for collection like "method_data:name". */
            if (gvm_validate (validator, name_name, name))
              {
                param->original_value = param->value;
                param->value = NULL;
                param->value_size = 0;
                param->valid = 0;
                param->valid_utf8 = 0;
              }
            /* General value validator like "method_data:value". */
            else if (gvm_validate (validator, value_name, param->value))
              {
                param->original_value = param->value;
                param->value = NULL;
                param->value_size = 0;
                param->valid = 0;
                param->valid_utf8 = 0;
              }
            else
              {
                const gchar *alias_for;

                param->valid = 1;
                param->valid_utf8 = g_utf8_validate (param->value, -1, NULL);

                alias_for = gvm_validator_alias_for (validator, name);
                if ((param->value && (strcmp ((gchar *) name, "number") == 0))
                    || (alias_for
                        && (strcmp ((gchar *) alias_for, "number") == 0)))
                  /* Remove any leading or trailing space from numbers. */
                  param->value = g_strstrip (param->value);
              }
            break;
          case 2:
          default:
            {
              param->original_value = param->value;
              param->value = NULL;
              param->value_size = 0;
              param->valid = 0;
              param->valid_utf8 = 0;
            }
          }

      g_free (item_name);
    }

  g_free (name_name);
  g_free (value_name);
}

/**
 * @brief Validate params.
 *
 * @param[in]  params  Params.
 */
void
params_mhd_validate (void *params)
{
  GHashTableIter iter;
  gpointer name, value;

  validator_t validator = gsad_get_validator ();

  g_hash_table_iter_init (&iter, params);
  while (g_hash_table_iter_next (&iter, &name, &value))
    {
      param_t *param;
      param = (param_t *) value;

      param->valid_utf8 =
        (g_utf8_validate (name, -1, NULL)
         && (param->value == NULL || g_utf8_validate (param->value, -1, NULL)));

      if ((!g_str_has_prefix (name, "osp_pref_")
           && gvm_validate (validator, name, param->value)))
        {
          param->original_value = param->value;
          param->value = NULL;
          param->valid = 0;
          param->valid_utf8 = 0;
        }
      else
        {
          const gchar *alias_for;

          param->valid = 1;

          alias_for = gvm_validator_alias_for (validator, name);
          if ((param->value && (strcmp ((gchar *) name, "number") == 0))
              || (alias_for && (strcmp ((gchar *) alias_for, "number") == 0)))
            /* Remove any leading or trailing space from numbers. */
            param->value = g_strstrip (param->value);
        }

      if (param->values)
        params_mhd_validate_values (name, param->values);
    }
}
