#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t  ngx_http_cache_filter_module;

static ngx_int_t ngx_http_cache_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_cache_filter_handler(ngx_http_request_t *r);
static void *ngx_http_cache_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_cache_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_cache_filter_init(ngx_conf_t *cf);
static char *ngx_http_cache_filter_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_path_t *cache_path;
    ngx_uint_t cache_use_stale;
    ngx_http_complex_value_t cache_key;
} ngx_http_cache_filter_conf_t;

