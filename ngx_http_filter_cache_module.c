#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t  ngx_http_filter_cache_module;

static ngx_int_t ngx_http_filter_cache_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_filter_cache_handler(ngx_http_request_t *r);
static void *ngx_http_filter_cache_create_conf(ngx_conf_t *cf);
static char *ngx_http_filter_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_filter_cache_init(ngx_conf_t *cf);
static char *ngx_http_filter_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_filter_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_int_t index;
    ngx_path_t *cache_path;
    time_t cache_use_stale;
    ngx_http_complex_value_t cache_key;
} ngx_http_filter_cache_conf_t;

static ngx_command_t  ngx_http_filter_cache_commands[] = {

    { ngx_string("filter_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_filter_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("filter_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_path),
      NULL},
    { ngx_string("filter_cache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_use_stale),
      NULL },
    ngx_null_command
};

static ngx_str_t ngx_http_filter_cache_key = ngx_string("filter_cache_key");

static char *
ngx_http_filter_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_filter_cache_conf_t *flcf = conf;
    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if(flcf->enable) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        clcf->handler =  ngx_http_filter_cache_handler;

        flcf->index = ngx_http_get_variable_index(cf, &ngx_http_filter_cache_key);

        if (flcf->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}
