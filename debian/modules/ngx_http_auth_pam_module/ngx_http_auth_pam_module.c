/*
 * Copyright (C) 2008-2010 Sergio Talens-Oliag <sto@iti.upv.es>
 *
 * Based on nginx's 'ngx_http_auth_basic_module.c' by Igor Sysoev and apache's
 * 'mod_auth_pam.c' by Ingo Luetkebolhe.
 *
 * SVN Id: $Id: ngx_http_auth_pam_module.c 4487 2010-11-15 09:57:03Z sto $
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <security/pam_appl.h>

#define NGX_PAM_SERVICE_NAME    "nginx"

/* Module context data */
typedef struct {
    ngx_str_t  passwd;
} ngx_http_auth_pam_ctx_t;

/* PAM userinfo */
typedef struct {
    ngx_str_t  username;
    ngx_str_t  password;
} ngx_pam_userinfo;

/* Module configuration struct */
typedef struct {
    ngx_str_t	realm;		/* http basic auth realm */
    ngx_str_t	service_name;	/* pam service name */
} ngx_http_auth_pam_loc_conf_t;

/* Module handler */
static ngx_int_t ngx_http_auth_pam_handler(ngx_http_request_t *r);

/* Function that authenticates the user -- is the only function that uses PAM */
static ngx_int_t ngx_http_auth_pam_authenticate(ngx_http_request_t *r,
    ngx_http_auth_pam_ctx_t *ctx, ngx_str_t *passwd, void *conf);

static ngx_int_t ngx_http_auth_pam_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);

static void *ngx_http_auth_pam_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_auth_pam_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_auth_pam_init(ngx_conf_t *cf);

static char *ngx_http_auth_pam(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt  ngx_http_auth_pam_p = ngx_http_auth_pam;

static int ngx_auth_pam_talker(int num_msg, const struct pam_message ** msg,
    struct pam_response ** resp, void *appdata_ptr);

static ngx_command_t  ngx_http_auth_pam_commands[] = {

    { ngx_string("auth_pam"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_pam_loc_conf_t, realm),
      &ngx_http_auth_pam_p },

    { ngx_string("auth_pam_service_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_pam_loc_conf_t, service_name),
      NULL },
};


static ngx_http_module_t  ngx_http_auth_pam_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_pam_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_pam_create_loc_conf,     /* create location configuration */
    ngx_http_auth_pam_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_auth_pam_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_pam_module_ctx,         /* module context */
    ngx_http_auth_pam_commands,            /* module directives */
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

/*
 * ngx_auth_pam_talker: supply authentication information to PAM when asked
 *
 * Assumptions:
 *   A password is asked for by requesting input without echoing
 *   A username is asked for by requesting input _with_ echoing
 */
static int
ngx_auth_pam_talker(int num_msg, const struct pam_message ** msg,
		    struct pam_response ** resp, void *appdata_ptr)
{
    int  i;
    ngx_pam_userinfo  *uinfo;
    struct pam_response  *response;

    uinfo = (ngx_pam_userinfo *) appdata_ptr;
    response = NULL;

    /* parameter sanity checking */
    if (!resp || !msg || !uinfo)
	return PAM_CONV_ERR;

    /* allocate memory to store response */
    response = malloc(num_msg * sizeof(struct pam_response));
    if (!response)
	return PAM_CONV_ERR;

    /* copy values */
    for (i = 0; i < num_msg; i++) {
	/* initialize to safe values */
	response[i].resp_retcode = 0;
	response[i].resp = 0;

	/* select response based on requested output style */
	switch (msg[i]->msg_style) {
	case PAM_PROMPT_ECHO_ON:
	    /* on memory allocation failure, auth fails */
	    response[i].resp = strdup((const char *)uinfo->username.data);
	    break;
	case PAM_PROMPT_ECHO_OFF:
	    response[i].resp = strdup((const char *)uinfo->password.data);
	    break;
	default:
	    if (response) {
		free(response);
	    }
	    return PAM_CONV_ERR;
	}
    }
    /* everything okay, set PAM response values */
    *resp = response;
    return PAM_SUCCESS;
}

static ngx_int_t
ngx_http_auth_pam_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_http_auth_pam_ctx_t  *ctx;
    ngx_http_auth_pam_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_pam_module);

    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_pam_module);

    if (ctx) {
        return ngx_http_auth_pam_authenticate(r, ctx, &ctx->passwd, alcf);
    }

    /* Decode http auth user and passwd, leaving values on the request */
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        return ngx_http_auth_pam_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check user & password using PAM */
    return ngx_http_auth_pam_authenticate(r, ctx, &ctx->passwd, alcf);
}

static ngx_int_t
ngx_http_auth_pam_authenticate(ngx_http_request_t *r,
    ngx_http_auth_pam_ctx_t *ctx, ngx_str_t *passwd, void *conf)
{
    ngx_int_t   rc;
    ngx_http_auth_pam_loc_conf_t  *alcf;

    ngx_pam_userinfo  uinfo;
    struct pam_conv   conv_info;	/* PAM struct */
    pam_handle_t      *pamh;
    u_char            *service_name;

    alcf = conf;

    size_t   len;
    u_char  *uname_buf, *p;

    /**
     * Get username and password, note that r->headers_in.user contains the
     * string 'user:pass', so we need to copy the username
     **/
    for (len = 0; len < r->headers_in.user.len; len++) {
	if (r->headers_in.user.data[len] == ':') {
            break;
	}
    }
    uname_buf = ngx_palloc(r->pool, len+1);
    if (uname_buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p = ngx_cpymem(uname_buf, r->headers_in.user.data , len);
    *p ='\0';

    uinfo.username.data = uname_buf;
    uinfo.username.len  = len;
    
    uinfo.password.data = r->headers_in.passwd.data;
    uinfo.password.len  = r->headers_in.passwd.len;

    conv_info.conv = &ngx_auth_pam_talker;
    conv_info.appdata_ptr = (void *) &uinfo;
    
    pamh = NULL;

    /* Initialize PAM */
    if (alcf->service_name.data == NULL) {
	service_name = (u_char *) NGX_PAM_SERVICE_NAME;
    } else {
	service_name = alcf->service_name.data;
    }
    if ((rc = pam_start((const char *) service_name,
			(const char *) uinfo.username.data,
			&conv_info,
			&pamh)) != PAM_SUCCESS) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "PAM: Could not start pam service: %s",
		      pam_strerror(pamh, rc));
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* try to authenticate user, log error on failure */
    if ((rc = pam_authenticate(pamh,
			       PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "PAM: user '%s' - not authenticated: %s",
		      uinfo.username.data, pam_strerror(pamh, rc));
	pam_end(pamh, PAM_SUCCESS);
    	return ngx_http_auth_pam_set_realm(r, &alcf->realm);
    }	/* endif authenticate */

    /* check that the account is healthy */
    if ((rc = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		      "PAM: user '%s'  - invalid account: %s",
		      uinfo.username.data, pam_strerror(pamh, rc));
	pam_end(pamh, PAM_SUCCESS);
    	return ngx_http_auth_pam_set_realm(r, &alcf->realm);
    }

    pam_end(pamh, PAM_SUCCESS);
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_pam_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static void *
ngx_http_auth_pam_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_pam_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_pam_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_auth_pam_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_pam_loc_conf_t  *prev = parent;
    ngx_http_auth_pam_loc_conf_t  *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->service_name.data == NULL) {
        conf->service_name = prev->service_name;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_pam_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_pam_handler;

    return NGX_OK;
}

static char *
ngx_http_auth_pam(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    size_t   len;
    u_char  *basic, *p;

    if (ngx_strcmp(realm->data, "off") == 0) {
        realm->len = 0;
        realm->data = (u_char *) "";

        return NGX_CONF_OK;
    }

    len = sizeof("Basic realm=\"") - 1 + realm->len + 1;

    basic = ngx_palloc(cf->pool, len);
    if (basic == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    realm->len = len;
    realm->data = basic;

    return NGX_CONF_OK;
}

/* SVN Id: $Id: ngx_http_auth_pam_module.c 4487 2010-11-15 09:57:03Z sto $ */
