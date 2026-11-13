
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_EXPR)
#include <ngx_http_expr_module.h>
#endif


#define NGX_HTTP_SSL_STRICT_SERVER_NAME_OFF   0
#define NGX_HTTP_SSL_STRICT_SERVER_NAME_ON    1
#define NGX_HTTP_SSL_STRICT_SERVER_NAME_AUTO  2


typedef struct {
#if (NGX_EXPR)
    ngx_array_t  *mode;
#else
    ngx_uint_t    mode;
#endif
} ngx_http_ssl_strict_server_name_srv_conf_t;


static ngx_int_t ngx_http_ssl_strict_server_name_handler(ngx_http_request_t *r);
static void *ngx_http_ssl_strict_server_name_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_strict_server_name_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_ssl_strict_server_name_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_ssl_strict_server_name_modes[] = {
    { ngx_string("off"), NGX_HTTP_SSL_STRICT_SERVER_NAME_OFF },
    { ngx_string("on"), NGX_HTTP_SSL_STRICT_SERVER_NAME_ON },
    { ngx_string("auto"), NGX_HTTP_SSL_STRICT_SERVER_NAME_AUTO },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_ssl_strict_server_name_commands[] = {

    { ngx_string("ssl_strict_server_name"),
#if (NGX_EXPR)
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF
      |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_conditional_enum_slot,
#else
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
#endif
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_strict_server_name_srv_conf_t, mode),
      &ngx_http_ssl_strict_server_name_modes },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_strict_server_name_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ssl_strict_server_name_init,  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_strict_server_name_create_srv_conf,
                                           /* create server configuration */
    ngx_http_ssl_strict_server_name_merge_srv_conf,
                                           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_strict_server_name_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_strict_server_name_module_ctx,  /* module context */
    ngx_http_ssl_strict_server_name_commands,     /* module directives */
    NGX_HTTP_MODULE,                              /* module type */
    NULL,                                         /* init master */
    NULL,                                         /* init module */
    NULL,                                         /* init process */
    NULL,                                         /* init thread */
    NULL,                                         /* exit thread */
    NULL,                                         /* exit process */
    NULL,                                         /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_ssl_strict_server_name_handler(ngx_http_request_t *r)
{
    ngx_str_t                                   *host;
    ngx_uint_t                                   mode;
    ngx_http_connection_t                       *hc;
    ngx_http_ssl_strict_server_name_srv_conf_t  *conf;
#if (NGX_RESTY_EXT)
    ngx_http_ssl_srv_conf_t                     *sscf;
#endif

    if (r->connection->ssl == NULL) {
        return NGX_DECLINED;
    }

    hc = r->http_connection;

    if (hc->ssl_servername == NULL) {
        return NGX_DECLINED;
    }

    host = &r->headers_in.server;

    if (hc->ssl_servername->len == host->len
        && ngx_strncmp(hc->ssl_servername->data, host->data, host->len) == 0)
    {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_srv_conf(r,
                                        ngx_http_ssl_strict_server_name_module);
#if (NGX_EXPR)
    mode = ngx_http_get_expr_enum_value(r, conf->mode);
#else
    mode = conf->mode;
#endif

    if (mode == NGX_HTTP_SSL_STRICT_SERVER_NAME_OFF) {
        return NGX_DECLINED;
    }

    if (mode == NGX_HTTP_SSL_STRICT_SERVER_NAME_AUTO) {
#if (NGX_RESTY_EXT)
        sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

        if (!sscf->verify) {
            return NGX_DECLINED;
        }
#else
        return NGX_DECLINED;
#endif
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client attempted to request the server name "
                  "different from the one that was negotiated");

    return NGX_HTTP_MISDIRECTED_REQUEST;
}


static void *
ngx_http_ssl_strict_server_name_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_strict_server_name_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_ssl_strict_server_name_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_EXPR)
    conf->mode = NGX_CONF_UNSET_PTR;
#else
    conf->mode = NGX_CONF_UNSET_UINT;
#endif

    return conf;
}


static char *
ngx_http_ssl_strict_server_name_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_ssl_strict_server_name_srv_conf_t *prev = parent;
    ngx_http_ssl_strict_server_name_srv_conf_t *conf = child;

#if (NGX_EXPR)
    if (ngx_conf_merge_expr_enum_value(cf, &conf->mode, prev->mode,
                                       NGX_HTTP_SSL_STRICT_SERVER_NAME_AUTO)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#else
    ngx_conf_merge_uint_value(conf->mode, prev->mode,
                              NGX_HTTP_SSL_STRICT_SERVER_NAME_AUTO);
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ssl_strict_server_name_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_ssl_strict_server_name_handler;

    return NGX_OK;
}
