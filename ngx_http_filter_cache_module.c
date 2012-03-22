#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* see ngx_http_request.h */
#define NGX_HTTP_FILTERCACHE_BUFFERED 0x80

ngx_module_t  ngx_http_filter_cache_module;

/*config */
typedef struct {
    ngx_http_upstream_conf_t upstream; /*we use upstream, just bcs configs and helper functions already exist*/
    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;
    ngx_int_t                index;
    ngx_flag_t               handler;
    time_t grace; /*how long after something is stale will be allow to serve stale*/
    ngx_http_complex_value_t cache_key;
} ngx_http_filter_cache_conf_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
static ngx_str_t ngx_http_filter_cache_key = ngx_string("filter_cache_key");
static ngx_int_t ngx_http_filter_cache_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_filter_cache_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_filter_cache_handler(ngx_http_request_t *r);
static void *ngx_http_filter_cache_create_conf(ngx_conf_t *cf);
static char *ngx_http_filter_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_filter_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_filter_cache_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_filter_cache_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_filter_cache_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_gzip_ok_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_filter_cache_status(ngx_http_request_t *r,
                                              ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_filter_cache_new(ngx_http_request_t *r);
/*static ngx_int_t ngx_http_filter_cache_create(ngx_http_request_t *r);*/
static void ngx_http_filter_cache_create_key(ngx_http_request_t *r);
static ngx_int_t ngx_http_filter_cache_open(ngx_http_request_t *r);
static void ngx_http_filter_cache_set_header(ngx_http_request_t *r, u_char *buf);
static void ngx_http_filter_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf);
static void ngx_http_filter_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf);
static time_t ngx_http_filter_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status);
static ngx_int_t ngx_http_filter_cache_send_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_filter_cache_send(ngx_http_request_t *r);

/*meta information prepended to every cache file */
typedef struct
{
    ngx_uint_t status;
    unsigned gzip_vary:1; /* Note: we leave this in on every compile, just in case someone switches between nginx binaries with/without gzip support while object is valid.  A long shot I know*/
    time_t last_modified_time;
} ngx_http_filter_cache_meta_t;

#define FILTER_TRYCACHE 0
#define FILTER_CACHEABLE 1
#define FILTER_DONOTCACHE 2 /*don't attempt to cache */
#define FILTER_CACHEDONE 3 /* we are done cacheing*/

/*context for the filter*/
typedef struct
{
    unsigned cache_status:3;
    unsigned cacheable:3;
    ngx_str_t key;
    ngx_http_cache_t *cache;
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

static ngx_str_t ngx_http_filter_cache_hide_headers[] = {
    ngx_string("Content-Length"),
    ngx_string("Content-Encoding"),
    ngx_string("Set-Cookie"),
    ngx_string("Last-Modified"),
    ngx_null_string
};

static ngx_command_t  ngx_http_filter_cache_commands[] = {

    { ngx_string("filter_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
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
      offsetof(ngx_http_filter_cache_conf_t, upstream.cache_bypass),
      NULL },

    { ngx_string("filter_cache_disable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.no_cache),
      NULL },

    { ngx_string("filter_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.cache_valid),
      NULL },

    { ngx_string("filter_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.cache_min_uses),
      NULL },

    { ngx_string("filter_cache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.cache_use_stale),
      &ngx_http_filter_cache_next_upstream_masks },

    { ngx_string("filter_cache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.cache_methods),
      &ngx_http_upstream_cache_method_mask },

    { ngx_string("filter_cache_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.temp_path),
      NULL },

    { ngx_string("filter_cache_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("filter_cache_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, upstream.hide_headers),
      NULL },

    { ngx_string("filter_cache_grace"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_filter_cache_conf_t, grace),
    NULL },

     { ngx_string("filter_cache_headers_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, headers_hash_max_size),
      NULL },

    { ngx_string("filter_cache_headers_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, headers_hash_bucket_size),
      NULL },

    { ngx_string("filter_cache_handler"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_filter_cache_conf_t, handler),
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_filter_cache_module_ctx = {
    ngx_http_filter_cache_add_variables, /* preconfiguration */
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

/* will cleanup the cache, including possible temp file, if we didn't cache it*/
static void
filter_cache_cleanup(void *data)
{
    ngx_http_filter_cache_ctx_t *ctx = data;

    /*if(ctx && !ctx->cacheable && ctx->cache) {*/
    if( ctx && (FILTER_CACHEDONE != ctx->cacheable) && ctx->cache) {
        ngx_http_filter_cache_free(ctx->cache, ctx->tf);
    }
}

static ngx_http_variable_t  ngx_http_filter_cache_vars[] = {

    { ngx_string("filter_cache_status"), NULL,
      ngx_http_filter_cache_status, 0,
      NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("gzip_ok"), NULL,
      ngx_http_gzip_ok_variable, 0,
      NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
ngx_http_filter_cache_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_filter_cache_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_gzip_ok_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    char ok = '0';

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (!r->gzip_tested) {
        ngx_http_gzip_ok(r);
    }
    if (r->gzip_ok) {
        ok = '1';
    }

    v->data = ngx_pnalloc(r->pool, 2);
    v->data[0] = ok;
    v->data[1] = '\0';
    v->len = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_filter_cache_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_filter_cache_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_filter_cache_body_filter;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_filter_cache_rewrite_handler;

    return NGX_OK;
}

static void *
ngx_http_filter_cache_create_conf(ngx_conf_t *cf)
{
    ngx_http_filter_cache_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_filter_cache_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->upstream.cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->grace = NGX_CONF_UNSET;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;
    conf->handler = NGX_CONF_UNSET;

    return conf;
}


static ngx_path_init_t  ngx_http_filter_cache_temp_path = {
    ngx_string("/tmp/filter_cache"), { 1, 2, 0 }
};

static ngx_int_t find_string_in_array(ngx_str_t *s, ngx_array_t *array)
{
    ngx_uint_t i;
    ngx_str_t *h;

    if(!s || !array || !s->len || !s->data || !array->nelts) {
        return 0;
    }

    h =  array->elts;

    for (i = 0; i < array->nelts; i++) {
        /* we already made sure s->len is not 0 above */
        if( (h[i].len == s->len) && h[i].data ) {
            /*only need to do check if lengths are the same*/
            if(!ngx_strncasecmp((u_char *)h[i].data, (u_char *)s->data, s->len)) {
                return 1;
            }
        }
    }
    return 0;
}

static ngx_int_t ngx_http_filter_cache_hide_headers_merge(ngx_conf_t *cf, ngx_http_filter_cache_conf_t *conf, ngx_http_filter_cache_conf_t *prev, ngx_str_t *default_hide_headers)
{
    ngx_str_t *h, *hk;
    ngx_int_t merge = 0;

    if (conf->upstream.hide_headers == NGX_CONF_UNSET_PTR) {
        conf->upstream.hide_headers = ngx_array_create(cf->pool, 16, sizeof(ngx_str_t));
        if (conf->upstream.hide_headers == NULL) {
            return NGX_ERROR;
        }
    }

    if(prev->upstream.hide_headers == NGX_CONF_UNSET_PTR) {
        /*easy case, neither are set*/
        for (h = default_hide_headers; h->len && h->data; h++) {
            hk = ngx_array_push(conf->upstream.hide_headers);
            if (hk == NULL) {
                return NGX_ERROR;
            }
            *hk = *h;
        }
    } else {
        merge = 1;
    }

    if(merge) {
        /*probably wrong.  just make this a list*/
        for (h = prev->upstream.hide_headers->elts; h->len; h++) {
            /*if we really wanted to squeeze the nth degree out of this, we could sort them and jump out if we find a value "larger" than us??
             * or use something qsort and disgard the duplicates? find_string_in_array is pretty effecient, as it only uses stncasecmp as a last resort
             */
            if(!find_string_in_array(h, conf->upstream.hide_headers)){
                hk = ngx_array_push(conf->upstream.hide_headers);
                if (hk == NULL) {
                    return NGX_ERROR;
                }
                *hk = *h;
            }
        }
    }
    return NGX_OK;
}

static char *
ngx_http_filter_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_filter_cache_conf_t *prev = parent;
    ngx_http_filter_cache_conf_t *conf = child;
    /* ngx_hash_init_t             hash; */

    ngx_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);

    conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
                                               ngx_cacheline_size);

    if (ngx_http_filter_cache_hide_headers_merge(cf, conf, prev, ngx_http_filter_cache_hide_headers)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->upstream.cache,
                             prev->upstream.cache, NULL);

    if (conf->upstream.cache && conf->upstream.cache->data == NULL) {
        ngx_shm_zone_t  *shm_zone = NULL;

        shm_zone = conf->upstream.cache;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"filter_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    if (conf->upstream.no_cache && conf->upstream.cache_bypass == NULL) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                      "\"filter_cache_disable\" should generally be used together with \"filter_cache_bypass\"");
    }

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                                  prev->upstream.temp_path,
                                  &ngx_http_filter_cache_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);


    /* hash.max_size = conf->headers_hash_max_size; */
    /* hash.bucket_size = conf->headers_hash_bucket_size; */
    /* hash.name = "filter_cache_headers_hash"; */

    /* if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, */
    /*         &prev->upstream, ngx_http_filter_cache_hide_headers, &hash) */
    /*     != NGX_OK) */
    /* { */
    /*     return NGX_CONF_ERROR; */
    /* } */

    ngx_conf_merge_value(conf->grace,
                         prev->grace, 0);

    ngx_conf_merge_value(conf->handler,
                         prev->handler, 1);

    return NGX_CONF_OK;
}

static char *
ngx_http_filter_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_filter_cache_conf_t *lcf = conf;
    ngx_http_core_loc_conf_t  *core_conf = NULL;
    ngx_str_t  *value = NULL;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lcf->upstream.cache = NULL;
        return NGX_CONF_OK;
    }

    if (lcf->upstream.cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    lcf->index = ngx_http_get_variable_index(cf, &ngx_http_filter_cache_key);

    if (lcf->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    lcf->upstream.cache = ngx_shared_memory_add(cf, &value[1], 0,
                                       &ngx_http_filter_cache_module);
    if (lcf->upstream.cache == NULL) {
        return NGX_CONF_ERROR;
    }

    if(lcf->handler) {
        core_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        core_conf->handler = ngx_http_filter_cache_handler;
    }

    return NGX_CONF_OK;
}

/* return 598 when we are not goign to attempt to cache this, 599 if it was just a cache miss of some type */
static ngx_int_t cache_miss(ngx_http_request_t *r,  ngx_http_filter_cache_ctx_t *ctx, int set_filter, int handler)
{
    if(ctx) {
        if(set_filter && !r->header_only) {
            r->filter_cache = ctx;
            ctx->cacheable = FILTER_TRYCACHE; /*this is a hack. the filter will figure out if it is cacheable?? */
            if(handler) {
                return 599;
            }

        }
    }

    return handler ? 598 : NGX_DECLINED;
}

static ngx_int_t
filter_cache_send(ngx_http_request_t *r)
{
    ngx_http_cache_t  *c = NULL;
    u_char *raw,*p,*hs;
    int flag = 0;
    ngx_table_elt_t *h = NULL;
    ngx_str_t key,value;

    ngx_http_filter_cache_meta_t *meta;
    ngx_http_filter_cache_ctx_t *ctx =  r->filter_cache;

    r->cached = 1;
    c = ctx->cache;

    if (c->header_start == c->body_start) {
        r->http_version = NGX_HTTP_VERSION_9;
        return ngx_http_filter_cache_send(r);
    }
    r->headers_out.content_length_n = c->length - c->body_start;

    /* Headers */
    /* Headers that arent' in the table */

    /*initialize ptrs*/
    hs = raw = (u_char *)(c->buf->start + c->header_start);

    /* Meta data */
    meta = (ngx_http_filter_cache_meta_t *)raw;
    raw += sizeof(ngx_http_filter_cache_meta_t);

    r->headers_out.status = meta->status;

#if (NGX_HTTP_GZIP)
    r->gzip_vary = meta->gzip_vary;
#endif
    r->headers_out.last_modified_time = meta->last_modified_time;

    /* ngx_memcpy((void *)(&r->headers_out.status), (void *)raw, sizeof(ngx_int_t)); */
    /* raw += sizeof(ngx_int_t); */

    /* Content Type */
    key.data = raw;
    p = memchr((void *)raw, '\0', c->length - c->header_start);
    if ( !p ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    key.len = p - raw;
    raw = p + 1;

    r->headers_out.content_type.data = key.data;
    r->headers_out.content_type.len = key.len;
    r->headers_out.content_type_len = key.len;
    r->headers_out.content_type_lowcase = ngx_pnalloc(r->pool, key.len);
    if (r->headers_out.content_type_lowcase == NULL ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_strlow(r->headers_out.content_type_lowcase, key.data, key.len);
    r->headers_out.content_type_hash = ngx_hash_key_lc(key.data, key.len);

    /* Charset */
    key.data = raw;
    p = memchr( (void *)raw, '\0', c->length - c->header_start - ( raw - hs ));
    key.len = p - raw;
    raw = p + 1;
    r->headers_out.charset.data = key.data;
    r->headers_out.charset.len = key.len;

    /* content encoding */
    key.data = raw;
    p = memchr( (void *)raw, '\0', c->length - c->header_start - ( raw - hs ));
    key.len = p - raw;
    if(key.len) {
        /*copied from ngx_http_gzip_static_module.c */
        h = ngx_list_push(&r->headers_out.headers);
        if ( h == NULL ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_str_set(&h->key, "Content-Encoding");
        h->hash = 1;
        h->value.len = key.len;
        h->value.data = key.data;
        r->headers_out.content_encoding = h;
        r->ignore_content_encoding = 1;
    }
    raw = p + 1;

    /* last-modified*/
    key.data = raw;
    p = memchr( (void *)raw, '\0', c->length - c->header_start - ( raw - hs ));
    key.len = p - raw;
    if(key.len) {
        /*copied from ngx_http_gzip_static_module.c */
        h = ngx_list_push(&r->headers_out.headers);
        if ( h == NULL ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_str_set(&h->key, "Last-Modified");
        h->hash = 1;
        h->value.len = key.len;
        h->value.data = key.data;
        r->headers_out.last_modified = h;
    }
    raw = p + 1;

    /* Stuff from the Table */
    key.data = raw;
    key.len = 0;
    value.data = NULL;
    value.len = 0;
    while( raw < c->buf->start + c->body_start ) {
        if ( *raw == '\0' ) {
            if ( flag == 0 ) {
                flag = 1;
                key.len = raw - key.data;
                value.data = raw + 1;
            }
            else {
                flag = 0;
                value.len = raw - value.data;
                /* all this crap pushes a header */
                h = ngx_list_push(&r->headers_out.headers);
                if ( h == NULL ) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                h->key.len = key.len;
                h->key.data = key.data;
                h->hash = ngx_hash_key_lc(key.data, key.len);
                h->value.len = value.len;
                h->value.data = value.data;
                if((h->lowcase_key = ngx_pnalloc(r->pool, h->key.len +1)) == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
                key.data = raw + 1;
            }
        }
        raw++;
    }

    return ngx_http_filter_cache_send(r);
}

static ngx_int_t
ngx_http_filter_cache_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_filter_cache_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_filter_cache_module);
    if(conf->handler) {
        return NGX_DECLINED;
    } else {
        return ngx_http_filter_cache_handler(r);
    }
}

static ngx_int_t
ngx_http_filter_cache_handler(ngx_http_request_t *r)
{
    ngx_http_filter_cache_ctx_t *ctx = NULL;
    ngx_http_filter_cache_conf_t *conf = NULL;
    ngx_http_variable_value_t      *vv = NULL;
    ngx_http_cache_t  *c = NULL;
    ngx_str_t                    *key = NULL;
    ngx_int_t          rc = NGX_ERROR;

    if(r != r->main) {
        /* we don't currently serve subrequests
         * if we ever do subrequests, we will need a way to associate a ctx with this request
         * maybe keep an r in ctx and compare to r here?
         */
        return cache_miss(r, NULL, 0, 0);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_filter_cache_module);

    /* turned off */
    if (NULL == conf->upstream.cache) {
        return cache_miss(r, NULL, 0, conf->handler);
    }

    ctx = r->filter_cache;

    if(ctx) {
        /*loop detected??*/
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "cache loop in " __FILE__);
        /* XXX: this causes a 598 to be returned.  Is that what we want???
         * should loop return yet another status code??
         * be configurable and default to 598??
         */
        return cache_miss(r, NULL, 0, conf->handler);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_filter_cache_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->cache = NULL;
    ctx->cacheable = FILTER_DONOTCACHE;
    ctx->cache_status = NGX_HTTP_CACHE_MISS;

    /* needed so the ctx works in cache status*/
    r->filter_cache = ctx;

    switch (ngx_http_test_predicates(r, conf->upstream.cache_bypass)) {
    case NGX_ERROR:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, __FILE__" ngx_http_test_predicates returned an error for bypass");
        return NGX_ERROR;
    case NGX_DECLINED:
        ctx->cache_status = NGX_HTTP_CACHE_BYPASS;
        return cache_miss(r, NULL, 0, conf->handler);
    default: /* NGX_OK */
        break;
    }

    if (!(r->method & conf->upstream.cache_methods)) {
        return cache_miss(r, NULL, 0, conf->handler);
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    vv = ngx_http_get_indexed_variable(r, conf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the \"filter_cache_key\" variable is not set");
        return NGX_ERROR;
    }

    ctx->key.data = vv->data;
    ctx->key.len = vv->len;
    c = ctx->cache = NULL;

    if (ngx_http_filter_cache_new(r) != NGX_OK) {
        return NGX_ERROR;
    }

    key = ngx_array_push(&ctx->cache->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }
    key->data = ctx->key.data;
    key->len = ctx->key.len;

    ctx->cache->file_cache = conf->upstream.cache->data;
    ngx_http_filter_cache_create_key(r);
    /* ngx_http_filter_cache_create(r); */

    c = ctx->cache;

    c->min_uses = conf->upstream.cache_min_uses;
    c->body_start = conf->upstream.buffer_size;
    c->file_cache = conf->upstream.cache->data;

    rc = ngx_http_filter_cache_open(r);

    switch(rc) {
    case NGX_HTTP_CACHE_UPDATING:
        if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING) {
            if(ctx->cache && conf->grace && ( (ctx->cache->valid_sec - ngx_time() ) < conf->grace)) {
                ctx->cache_status = NGX_HTTP_CACHE_UPDATING;
                rc = NGX_OK;
            } else {
                rc = NGX_HTTP_CACHE_STALE;
            }
        } else {
            rc = NGX_HTTP_CACHE_STALE;
        }
        break;
    case NGX_OK:
        ctx->cache_status = NGX_HTTP_CACHE_HIT;
    }

    switch (rc) {
    case NGX_OK:
        return filter_cache_send(r);
        break;
    case NGX_HTTP_CACHE_STALE:
        ctx->cache_status = NGX_HTTP_CACHE_EXPIRED;
        /*return 599;*/
        break;
    case NGX_DECLINED:
        break;
    case NGX_HTTP_CACHE_SCARCE:
        return cache_miss(r, ctx, 0, conf->handler);
        break;
    case NGX_AGAIN:
        return NGX_BUSY;
    case NGX_ERROR:
        return NGX_ERROR;
    default:
        /*????*/
        break;
    }

    return cache_miss(r, ctx, 1, conf->handler);
}

static ngx_int_t
ngx_http_filter_cache_header_filter(ngx_http_request_t *r)
{
    ngx_http_filter_cache_ctx_t *ctx = NULL;
    ngx_http_filter_cache_conf_t *conf = NULL;
    time_t  now, valid;
    ngx_temp_file_t *tf;
    ngx_chain_t   out;
    ssize_t offset;
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;
    u_char *p;
    size_t len;
    ngx_pool_cleanup_t *cln = NULL;

    ngx_http_filter_cache_meta_t meta;

    if(r != r->main) {
        /*just skip as we got headers in main*/
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_filter_cache_module);

    switch (ngx_http_test_predicates(r, conf->upstream.no_cache)) {
    case NGX_ERROR:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, __FILE__" ngx_http_test_predicates returned an error for no_cache");
        return NGX_ERROR;
    case NGX_DECLINED:
        goto nocache;
    default: /* NGX_OK */
        break;
    }

    ctx = r->filter_cache;

    if(!ctx || (FILTER_DONOTCACHE == ctx->cacheable)) {
        goto nocache;
    }
    /* ngx_http_filter_cache_create(r); */

    if (ctx->cache && ctx->cache->file.fd != NGX_INVALID_FILE) {
        ngx_pool_run_cleanup_file(r->pool, ctx->cache->file.fd);
        ctx->cache->file.fd = NGX_INVALID_FILE;
    }

    ctx->cache->valid_sec = 0;

    now = ngx_time();

    valid = 0;
    valid = ngx_http_filter_cache_valid(conf->upstream.cache_valid,
                                      r->headers_out.status);
    if (valid) {
        ctx->cache->valid_sec = now + valid;
    } else {
        goto nocache;
    }

    tf =  ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));

    if (tf == NULL) {
        return NGX_ERROR;
    }

    tf->file.fd = NGX_INVALID_FILE;
    tf->file.log = r->connection->log;
    tf->path = conf->upstream.temp_path;
    tf->pool = r->pool;
    tf->persistent = 1;

    if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                             tf->persistent, tf->clean, tf->access)
        != NGX_OK) {
        return NGX_ERROR;
    }
    ctx->tf = tf;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }
    cln->handler = filter_cache_cleanup;
    cln->data = ctx;

    ctx->buffer.pos = ctx->buffer.start = ngx_palloc(r->pool, conf->upstream.buffer_size);
    ctx->buffer.end = ctx->buffer.start + conf->upstream.buffer_size;
    ctx->buffer.temporary = 1;
    ctx->buffer.memory = 1;
    ctx->buffer.last_buf = 1;

    ctx->buffer.pos += ctx->cache->header_start;

    ctx->cache->last_modified = r->headers_out.last_modified_time;
    ctx->cache->date = now;

    /* Headers */

    /* fill in the metadata*/
    meta.status = r->headers_out.status;

#if (NGX_HTTP_GZIP)
    meta.gzip_vary = r->gzip_vary; /* Note: there is still some wierdness to how gzip_vary works...*/
#endif

    meta.last_modified_time = r->headers_out.last_modified_time;

    ngx_memcpy((void *)(ctx->buffer.pos), (void *)(&meta), sizeof(ngx_http_filter_cache_meta_t) );
    ctx->buffer.pos += sizeof(ngx_http_filter_cache_meta_t);

    /* Headers taht aren't in teh table for some reason */

    /*Do we need to try to set it if it's not set???*/
    /* Content Type */
    if ( r->headers_out.content_type.data ) {
        p = memchr((void *)r->headers_out.content_type.data, ';', r->headers_out.content_type.len );
        if ( p ) {
            len = p - r->headers_out.content_type.data;
            ngx_cpystrn( ctx->buffer.pos, r->headers_out.content_type.data, len + 1);
            ctx->buffer.pos += len + 1;
        }
        else {
            ngx_cpystrn( ctx->buffer.pos, r->headers_out.content_type.data, r->headers_out.content_type.len + 1 );
            ctx->buffer.pos += r->headers_out.content_type.len + 1;
        }
    }
    else {
        *ctx->buffer.pos = (u_char)'\0';
        ctx->buffer.pos++;
    }

    /* Charset */
    if ( r->headers_out.charset.data ) {
        ngx_cpystrn( ctx->buffer.pos, r->headers_out.charset.data, r->headers_out.charset.len + 1 );
        ctx->buffer.pos += r->headers_out.charset.len + 1;
    }
    else {
        *ctx->buffer.pos = (u_char)'\0';
        ctx->buffer.pos++;
    }

    /* Content Encoding */
    if ( r->headers_out.content_encoding && r->headers_out.content_encoding->value.len) {
        ngx_cpystrn( ctx->buffer.pos, r->headers_out.content_encoding->value.data, r->headers_out.content_encoding->value.len + 1 );
        ctx->buffer.pos += r->headers_out.content_encoding->value.len + 1;
    }
    else {
        *ctx->buffer.pos = (u_char)'\0';
        ctx->buffer.pos++;
    }

    /* Last-Modified */
    if(r->headers_out.last_modified_time && r->headers_out.last_modified && r->headers_out.last_modified->value.len) {
        ngx_cpystrn( ctx->buffer.pos, r->headers_out.last_modified->value.data, r->headers_out.last_modified->value.len + 1 );
        ctx->buffer.pos += r->headers_out.last_modified->value.len + 1;
    } else {
        *ctx->buffer.pos = (u_char)'\0';
        ctx->buffer.pos++;
    }


    /* XXX: is last-modified special???*/
    /* Everything From the Table */
    part = &r->headers_out.headers.part;
    h = part->elts;
    for (i=0; /* void */; i++) {
        if ( i >= part->nelts || !part->nelts ) {
            if ( part->next == NULL ) {
                ctx->cacheable = FILTER_CACHEABLE;
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*need to be really sure this header is "valid"*/
        /* if(h[i].key.len && h[i].value.len && h[i].hash && h[i].lowcase_key) {*/

            /* if(!h[i].lowcase_key) { */
            /*     if((h[i].lowcase_key = ngx_pnalloc(r->pool, h->key.len +1)) == NULL) { */
            /*         continue; */
            /*     } */
            /*     ngx_strlow(h[i].lowcase_key, h[i].key.data, h[i].key.len); */
            /* } */

            /* if(!h[i].hash) { */
            /*     h[i].hash = ngx_hash_key_lc(h[i].key.data, h[i].key.len); */
            /* } */

            /* if (ngx_hash_find(&conf->upstream.hide_headers_hash, h[i].hash, */
            /*                   h[i].lowcase_key, h[i].key.len)) */
            /* { */
            /*     continue; */
            /* } */

        if(h[i].key.len && h[i].value.len) {
            if(find_string_in_array(&(h[i].key), conf->upstream.hide_headers)){
                continue;
            }
            if ( (ngx_uint_t)(h[i].key.len + h[i].value.len + 4) > (ngx_uint_t)(ctx->buffer.last - ctx->buffer.pos) ) {
                ctx->cacheable = FILTER_DONOTCACHE;
                break;
            }

            ngx_cpystrn( ctx->buffer.pos, h[i].key.data, h[i].key.len + 1 );
            ctx->buffer.pos += h[i].key.len + 1;

            ngx_cpystrn( ctx->buffer.pos, h[i].value.data, h[i].value.len + 1 );
            ctx->buffer.pos += h[i].value.len + 1;
        }

    }

    if(FILTER_CACHEABLE != ctx->cacheable) {
        goto nocache;
    }

    ctx->buffer.last = ctx->buffer.pos;

    ctx->cache->body_start = (u_short) (ctx->buffer.pos - ctx->buffer.start);
    ngx_http_filter_cache_set_header(r, ctx->buffer.start);
    ctx->cache->date = now;

    /*write to temp file*/
    ctx->buffer.pos =  ctx->buffer.start;
    out.buf = &ctx->buffer;
    out.next = NULL;
    offset = ngx_write_chain_to_temp_file(tf, &out);
    tf->offset += offset;


    r->main_filter_need_in_memory = 1;

    return ngx_http_next_header_filter(r);

nocache:

    if(ctx) {
        ctx->cacheable = FILTER_DONOTCACHE;
        /* if(ctx->cache) { */
            /* ngx_http_filter_cache_free(ctx->cache, ctx->tf); */
        /* } */

    }
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_filter_cache_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_filter_cache_ctx_t *ctx = NULL;
    ssize_t offset = 0;
    ngx_chain_t *chain_link = NULL;
    int done = 0;

    /* ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, */
    /*                "ngx_http_filter_cache_body_filter start"); */

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = r->main->filter_cache;

    if (!ctx || (FILTER_CACHEABLE != ctx->cacheable)) {
        /* ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, */
        /*                "ngx_http_filter_cache_body_filter not cacheable"); */
        return ngx_http_next_body_filter(r, in);
    }

    if( ctx->tf->file.fd == NGX_INVALID_FILE ) {
        /* ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, */
        /*                "ngx_http_filter_cache_body_filter invalid temp file"); */
        return ngx_http_next_body_filter(r, in);
    } else {
        ngx_chain_t *cl = NULL;
        ngx_chain_t *head = NULL;
        ngx_buf_t *b = NULL;

        for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {
            b = chain_link->buf;

            if(b->pos && b->last) {
                if(!cl) {
                    head = cl = ngx_alloc_chain_link(r->pool);
                } else {
                    cl->next = ngx_alloc_chain_link(r->pool);
                    cl = cl->next;
                }
                 if (cl == NULL) {
                        return NGX_ERROR;
                 }
                 cl->buf = b;
                 cl->next = NULL;
            }
        }

        if (head) {
            offset = ngx_write_chain_to_temp_file(ctx->tf, head);
            ctx->tf->offset += offset;
        }
    }

    r->connection->buffered |= NGX_HTTP_FILTERCACHE_BUFFERED;

    for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {
        /* last_in_chain is used for sub requests?  also maybe need to find out about ->sync??*/
        /* if (chain_link->buf->last_buf || chain_link->buf->last_in_chain) { */
        if (chain_link->buf->last_buf) {
            done = 1;
        }
    }

    if(done) {
        ngx_http_filter_cache_update(r, ctx->tf);
        ctx->cacheable = FILTER_CACHEDONE;
        r->connection->buffered &= ~NGX_HTTP_FILTERCACHE_BUFFERED;
    }
    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t ngx_http_filter_cache_status(ngx_http_request_t *r,
                                                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  n;
    ngx_http_filter_cache_ctx_t *ctx = NULL;

    ctx = r->filter_cache;

    if (ctx == NULL || ctx->cache_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    n = ctx->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_cache_status[n].len;
    v->data = ngx_http_cache_status[n].data;

    return NGX_OK;
}

static ngx_int_t ngx_http_filter_cache_new(ngx_http_request_t *r)
{
    ngx_http_cache_t *c = NULL;
    ngx_http_filter_cache_ctx_t *ctx = NULL;
    ngx_int_t rc;

    ctx = r->filter_cache;
    c = r->cache;
    rc = ngx_http_file_cache_new(r);
    if(NGX_OK == rc) {
        ctx->cache = r->cache;
    }
    r->cache = c;
    return rc;
}


/* static ngx_int_t ngx_http_filter_cache_create(ngx_http_request_t *r) */
/* { */
/*     ngx_http_cache_t *c = NULL; */
/*     ngx_http_filter_cache_ctx_t *ctx = NULL; */
/*     ngx_int_t rc; */

/*     ctx = ngx_http_get_module_ctx(r, ngx_http_filter_cache_module); */
/*     c = r->cache; */
/*     r->cache = ctx->cache; */
/*     rc = ngx_http_file_cache_create(r); */
/*     r->cache = c; */
/*     return rc; */
/* } */

static void ngx_http_filter_cache_create_key(ngx_http_request_t *r)
{
    ngx_http_cache_t *c = NULL;
    ngx_http_filter_cache_ctx_t *ctx = NULL;

    ctx = r->filter_cache;
    c = r->cache;
    r->cache = ctx->cache;
    ngx_http_file_cache_create_key(r);
    r->cache = c;
}


static ngx_int_t ngx_http_filter_cache_open(ngx_http_request_t *r)
{
    ngx_http_cache_t *c = NULL;
    ngx_http_filter_cache_ctx_t *ctx = NULL;
    ngx_int_t rc;
    unsigned  cached = r->cached;

    ctx = r->filter_cache;
    c = r->cache;
    r->cache = ctx->cache;
    rc = ngx_http_file_cache_open(r);
    r->cache = c;

    r->cached = cached;

    return rc;
}


static void ngx_http_filter_cache_set_header(ngx_http_request_t *r, u_char *buf)
{
    ngx_http_cache_t *c = NULL;
    ngx_http_filter_cache_ctx_t *ctx = NULL;

    ctx = r->filter_cache;
    c = r->cache;
    r->cache = ctx->cache;
    ngx_http_file_cache_set_header(r, buf);
    r->cache = c;
}


static void ngx_http_filter_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf)
{
    ngx_http_cache_t *c = NULL;
    ngx_http_filter_cache_ctx_t *ctx = NULL;

    ctx = r->filter_cache;
    c = r->cache;
    r->cache = ctx->cache;
    ngx_http_file_cache_update(r, tf);
    r->cache = c;
}


static void ngx_http_filter_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf)
{
    ngx_http_file_cache_free(c, tf);
}


static time_t ngx_http_filter_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status)
{
    return ngx_http_file_cache_valid(cache_valid, status);
}

static ngx_int_t
ngx_http_filter_cache_send_header(ngx_http_request_t *r)
{
    if (r->err_status) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }
    /* we use the filter after the cache filter */
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_filter_cache_send(ngx_http_request_t *r)
{
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_http_cache_t  *c = NULL;
    ngx_http_cache_t *orig = NULL;
    ngx_http_filter_cache_ctx_t *ctx = NULL;

    ctx = r->filter_cache;
    orig = r->cache;
    c = r->cache = ctx->cache;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache send: %s", c->file.name.data);

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        r->cache = orig;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        r->cache = orig;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->header_only = (c->length - c->body_start) == 0;

    r->cache = orig;
    rc = ngx_http_filter_cache_send_header(r);
    c = r->cache = ctx->cache;

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        r->cache = orig;
        return rc;
    }

    b->file_pos = c->body_start;
    b->file_last = c->length;

    b->in_file = 1;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = c->file.fd;
    b->file->name = c->file.name;
    b->file->log = r->connection->log;

    out.buf = b;
    out.next = NULL;

    r->cache = orig;
    /* we use the filter after the cache filter */
    return ngx_http_next_body_filter(r, &out);
}

