#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t  ngx_http_filter_cache_module;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
static ngx_str_t ngx_http_filter_cache_key = ngx_string("filter_cache_key");
static ngx_int_t ngx_http_filter_cache_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_filter_cache_handler(ngx_http_request_t *r);
static void *ngx_http_filter_cache_create_conf(ngx_conf_t *cf);
static char *ngx_http_filter_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_filter_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_filter_cache_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_filter_cache_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

/*config */
typedef struct {
    size_t                   buffer_size;
    ngx_int_t                index;
    ngx_http_complex_value_t cache_key;
    ngx_shm_zone_t *cache;
    ngx_uint_t cache_min_uses;
    ngx_uint_t cache_use_stale;
    ngx_uint_t cache_methods;
    ngx_array_t *cache_valid;
    ngx_array_t *cache_bypass;
    ngx_array_t *no_cache;
    ngx_path_t *temp_path;
} ngx_http_filter_cache_conf_t;

/*meta information prepended to every cache file */
typedef struct
{
    uint32_t crc32;
    time_t   expires;
} ngx_http_filter_cache_meta_t;

/*context for the filter*/
typedef struct
{
    ngx_int_t cacheable;
    ngx_str_t key;
    ngx_http_cache_t *cache;
    ngx_http_cache_t *orig_cache;
    ngx_temp_file_t *tf;
    ngx_buf_t buffer;
} ngx_http_filter_cache_ctx_t;

static ngx_conf_bitmask_t  ngx_http_filter_cache_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};

static ngx_command_t  ngx_http_filter_cache_commands[] = {

    { ngx_string("filter_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_filter_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("filter_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      0,
      0,
      &ngx_http_filter_cache_module },

    { ngx_string("filter_cache_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_bypass),
      NULL },

    { ngx_string("filter_cache_disable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, no_cache),
      NULL },

    { ngx_string("filter_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_valid),
      NULL },

    { ngx_string("filter_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_min_uses),
      NULL },

    { ngx_string("filter_cache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_use_stale),
      &ngx_http_filter_cache_next_upstream_masks },

    { ngx_string("filter_cache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, cache_methods),
      &ngx_http_upstream_cache_method_mask },

    { ngx_string("filter_cache_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, temp_path),
      NULL },

    { ngx_string("filter_cache_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, buffer_size),
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_filter_cache_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_filter_cache_init,         /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_filter_cache_create_conf,         /* create location configuration */
    ngx_http_filter_cache_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_filter_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_filter_cache_module_ctx,  /* module context */
    ngx_http_filter_cache_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_filter_cache_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_filter_cache_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_filter_cache_body_filter;

    return NGX_OK;
}

static void *
ngx_http_filter_cache_create_conf(ngx_conf_t *cf)
{
    ngx_http_filter_cache_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_filter_cache_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->cache = NGX_CONF_UNSET_PTR;
    conf->cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->cache_bypass = NGX_CONF_UNSET_PTR;
    conf->no_cache = NGX_CONF_UNSET_PTR;
    conf->cache_valid = NGX_CONF_UNSET_PTR;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    return conf;
}


static ngx_path_init_t  ngx_http_filter_cache_temp_path = {
    ngx_string("/tmp/filter_cache"), { 1, 2, 0 }
};

static char *
ngx_http_filter_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_filter_cache_conf_t *prev = parent;
    ngx_http_filter_cache_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->cache,
                             prev->cache, NULL);

    if (conf->cache && conf->cache->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->cache;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"fastcgi_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->cache_min_uses,
                              prev->cache_min_uses, 1);

    ngx_conf_merge_bitmask_value(conf->cache_use_stale,
                              prev->cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->cache_methods == 0) {
        conf->cache_methods = prev->cache_methods;
    }

    conf->cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->cache_bypass,
                             prev->cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->no_cache,
                             prev->no_cache, NULL);

    if (conf->no_cache && conf->cache_bypass == NULL) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "\"filter_cache_disable\" should be used together with \"filter_cache_bypass\"");
    }

    ngx_conf_merge_ptr_value(conf->cache_valid,
                             prev->cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    if (ngx_conf_merge_path_value(cf, &conf->temp_path,
                                  prev->temp_path,
                                  &ngx_http_filter_cache_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size,
                              (size_t) ngx_pagesize);


    return NGX_CONF_OK;
}

static char *
ngx_http_filter_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_filter_cache_conf_t *lcf = conf;
    ngx_http_core_loc_conf_t  *core_conf;
    ngx_str_t  *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lcf->cache = NULL;
        return NGX_CONF_OK;
    }

    if (lcf->cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    lcf->index = ngx_http_get_variable_index(cf, &ngx_http_filter_cache_key);

    if (lcf->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    lcf->cache = ngx_shared_memory_add(cf, &value[1], 0,
                                       &ngx_http_filter_cache_module);
    if (lcf->cache == NULL) {
        return NGX_CONF_ERROR;
    }

    core_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_conf->handler =  ngx_http_filter_cache_handler;

    return NGX_CONF_OK;
}


static ngx_int_t cache_miss(ngx_http_request_t *r,  ngx_http_filter_cache_ctx_t *ctx, int set_filter)
{
    if(ctx) {
        r->cache = ctx->orig_cache;

        if(set_filter) {
            ngx_http_set_ctx(r, ctx, ngx_http_filter_cache_module);
        }
    }

    return NGX_HTTP_NOT_FOUND;
}

static ngx_int_t
filter_cache_send(ngx_http_request_t *r)
{
    ngx_http_cache_t  *c;

    r->headers_out.status = 200;

    r->cached = 1;
    c = r->cache;

    /* if (c->header_start == c->body_start) { */
    /*     r->http_version = NGX_HTTP_VERSION_9; */
    /*     return ngx_http_cache_send(r); */
    /* }  */

    /*TODO: process headers*/
    return ngx_http_cache_send(r);
}

static ngx_int_t
ngx_http_filter_cache_handler(ngx_http_request_t *r)
{
    ngx_http_filter_cache_ctx_t *ctx;
    ngx_http_filter_cache_conf_t *conf;
    ngx_http_variable_value_t      *vv;
    ngx_http_cache_t  *c;
    ngx_str_t                    *key;
    ngx_int_t          rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_filter_cache_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_filter_cache_module);

    if(ctx) {
        /*loop detected??*/
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_filter_cache_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    vv = ngx_http_get_indexed_variable(r, conf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the \"filter_cache_key\" variable is not set");
        return NGX_ERROR;
    }

    ctx->key.data = vv->data;
    ctx->key.len = vv->len;

    ctx->orig_cache = r->cache;
    c = r->cache = NULL;

    switch (ngx_http_test_predicates(r, conf->cache_bypass)) {
    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        return cache_miss(r, ctx, 0);
    default: /* NGX_OK */
        break;
    }

    if (!(r->method & conf->cache_methods)) {
        return cache_miss(r, ctx, 0);
        }

    if (ngx_http_file_cache_new(r) != NGX_OK) {
        return NGX_ERROR;
    }

    key = ngx_array_push(&r->cache->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }
    key->data = ctx->key.data;
    key->len = ctx->key.len;

    ngx_http_file_cache_create_key(r);

    c = r->cache;

    c->min_uses = conf->cache_min_uses;
    c->body_start = conf->buffer_size;
    c->file_cache = conf->cache->data;

    ctx->cache = r->cache;
    ctx->cache->file_cache = conf->cache->data;

    rc = ngx_http_file_cache_open(r);

    if(NGX_HTTP_CACHE_UPDATING == rc) {
        if (conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING) {
            c->updating = 1;
            rc = NGX_OK;
        } else {
            rc = NGX_HTTP_CACHE_STALE;
        }
    }

    switch (rc) {

    case NGX_OK:
        return filter_cache_send(r);

        break;
    case NGX_HTTP_CACHE_STALE:
        break;
    case NGX_DECLINED:
        break;
    case NGX_HTTP_CACHE_SCARCE:
        return cache_miss(r, ctx, 0);
        break;
    case NGX_AGAIN:
        return NGX_BUSY;
    case NGX_ERROR:
        return NGX_ERROR;
    default:
        /*????*/
        break;
    }
    return cache_miss(r, ctx, 1);
}

static ngx_int_t
ngx_http_filter_cache_header_filter(ngx_http_request_t *r)
{
    ngx_http_filter_cache_ctx_t *ctx;
    ngx_http_filter_cache_conf_t *conf;
    time_t  now, valid;
    ngx_temp_file_t *tf;
    ngx_chain_t   out;
    ssize_t offset;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_filter_cache_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_filter_cache_module);

    if(!ctx) {
        return ngx_http_next_header_filter(r);
    }

    if(r->cache != ctx->cache) {
        ctx->orig_cache = r->cache;
        r->cache = ctx->cache;
    }

    if (r->cache && r->cache->file.fd != NGX_INVALID_FILE) {
        ngx_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = NGX_INVALID_FILE;
    }

    now = ngx_time();

    valid = 0;
    valid = ngx_http_file_cache_valid(conf->cache_valid,
                                      r->headers_out.status);
    if (valid) {
        r->cache->valid_sec = now + valid;
    }

    if (!valid) {
        r->cache = ctx->orig_cache;
        return ngx_http_next_header_filter(r);
    }

    tf =  ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));

    if (tf == NULL) {
        return NGX_ERROR;
    }

    tf->file.fd = NGX_INVALID_FILE;
    tf->file.log = r->connection->log;
    tf->path = conf->temp_path;
    tf->pool = r->pool;
    tf->persistent = 1;

    if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                             tf->persistent, tf->clean, tf->access)
        != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->buffer.pos = ctx->buffer.start = ngx_palloc(r->pool, conf->buffer_size);
    ctx->buffer.end = ctx->buffer.start + conf->buffer_size;
    ctx->buffer.temporary = 1;
    ctx->buffer.memory = 1;
    ctx->buffer.last_buf = 1;

    ctx->buffer.pos += r->cache->header_start;
    ctx->buffer.last = ctx->buffer.pos;

    r->cache->last_modified = r->headers_out.last_modified_time;
    r->cache->date = now;

    /*add in headers starting at ctx->buffer.pos. update ctx->buffer.last and r->cache->body_start when done*/

    r->cache->body_start = (u_short) (ctx->buffer.pos - ctx->buffer.start);
    ngx_http_file_cache_set_header(r, ctx->buffer.start);

    /*write to temp file*/
    ctx->buffer.pos =  ctx->buffer.start;
    out.buf = &ctx->buffer;
    out.next = NULL;
    offset = ngx_write_chain_to_temp_file(tf, &out);
    tf->offset += offset;

    ctx->tf = tf;

    r->cache = ctx->orig_cache;
    ctx->cacheable = 1;
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_filter_cache_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_filter_cache_ctx_t *ctx;
    ngx_http_filter_cache_conf_t *conf;
    ssize_t offset;
    int chain_contains_last_buffer = 0;
    ngx_chain_t *chain_link;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_filter_cache_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_filter_cache_module);

    if (!ctx || !ctx->cacheable) {
        return ngx_http_next_body_filter(r, in);
    }

    offset = ngx_write_chain_to_temp_file(ctx->tf, in);
    ctx->tf->offset += offset;

    /*XXX: need to find out if we reached the end*/
    for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {
        if (chain_link->buf->last_buf)
            chain_contains_last_buffer = 1;
    }

    if(r->cache != ctx->cache) {
        ctx->orig_cache = r->cache;
        r->cache = ctx->cache;
    }

    if(chain_contains_last_buffer) {
        r->cache->updated = 0;
        ngx_http_file_cache_update(r, ctx->tf);
    }

    r->cache = ctx->orig_cache;
    return ngx_http_next_body_filter(r, in);
}
