#include "main.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

#include <openssl/asn1.h>

#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/ossl_typ.h>


BIO *bio_err = NULL;


#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6
#define FORMAT_ENGINE   7
#define FORMAT_IISSGC   8   /* XXX this stupid macro helps us to avoid
                 * adding yet another param to load_*key() */
#define FORMAT_PEMRSA   9   /* PEM RSAPubicKey format */
#define FORMAT_ASN1RSA  10  /* DER RSAPubicKey format */
#define FORMAT_MSBLOB   11  /* MS Key blob format */
#define FORMAT_PVK  12  /* MS PVK file format */

#define L_ERROR  0  /* errors */
#define L_WARN   1  /* all unusual */
#define L_INFO   2  /* all status changes etc. */
#define L_DEBUG  3  /* all, including trace */


int    log_level = 10;
char  *fileName  = NULL;

void Log( int msg_level, const char *msg, ...)
{
    va_list argp;

    if ( log_level >= msg_level )
    {
        if (msg_level == L_WARN )  fprintf( stderr, "Warning: " );
        if (msg_level == L_INFO )  fprintf( stderr, "Info:    " );
        if (msg_level == L_DEBUG ) fprintf( stderr, "Debug:   " );
        va_start( argp, msg );
        vfprintf( stderr, msg, argp );
        va_end( argp );
        fprintf( stderr, "\n" );
    }
}

void Error( const char *operation, const char *msg, ...)
{
    va_list argp;

    fprintf( stderr, "ERROR:  %s: ", operation );
    va_start( argp, msg );
    vfprintf( stderr, msg, argp );
    va_end( argp );
    fprintf( stderr, "\n" );
}

#include <curl/curl.h>


static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    BIO *data = (BIO *)userp;
    size_t i;
    size_t written = 0;

    printf("nmemb: %d, size: %d\n", nmemb, size);

#if 1
    FILE *f = NULL;
    f = fopen("/tmp/ocsp_response_http.out", "w+");
    fwrite(contents, size, nmemb, f);
    fflush(f);
    fclose(f);
#endif

    BIO_write(data, contents, size * nmemb);
    written = BIO_number_written(data);

    return written;
}

struct WriteThis {
  const char *readptr;
  long sizeleft;
};

static size_t
read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct WriteThis *pooh = (struct WriteThis *)userp;

    if(size*nmemb < 1)
        return 0;

    if(pooh->sizeleft) {
        *(char *)ptr = pooh->readptr[0];
        pooh->readptr++;
        pooh->sizeleft--;
        return 1;
    }

    /* Done */
    return 0;
}


BIO *
verify_ocsp_http(const char *url, const char *ocsp_request_buf, const long ocsp_request_len, short do_get) {
    CURL *curl;
    CURLcode res;

    char *full_url = NULL;
    struct WriteThis uploading_data;
    BIO *returned_data = NULL;
    struct curl_slist *headers_out = NULL;

    returned_data = BIO_new(BIO_s_mem());
    if (returned_data == NULL) {
        return NULL;
    }

    /* curl_global_init(CURL_GLOBAL_DEFAULT); */
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)returned_data);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-lcmaps-agent");

        if (do_get == 0) { /* aka POST */
            curl_easy_setopt(curl, CURLOPT_URL, url);

            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            /* curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)ocsp_request_buf); */
            /* curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(ocsp_request_buf)); */

            uploading_data.readptr  = ocsp_request_buf;
            uploading_data.sizeleft = ocsp_request_len;
            printf("strlen(ocsp_request_buf): %d\n", ocsp_request_len);

            curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
            curl_easy_setopt(curl, CURLOPT_READDATA, &uploading_data);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, uploading_data.sizeleft);

            headers_out = curl_slist_append(headers_out, "Content-Type: application/ocsp-request");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_out);
        } else { /* aka GET */
            full_url = malloc(strlen(url) + 1 + ocsp_request_len + 1);
            if (full_url == NULL)
                return NULL;

            memset(full_url, 0, strlen(url) + 1 + ocsp_request_len + 1);
            strcat(full_url, url);
            strcat(full_url, "/");
            strncat(full_url, ocsp_request_buf, ocsp_request_len);

            curl_easy_setopt(curl, CURLOPT_URL, full_url);
        }
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        /* curl_easy_getinfo(hc->curl, CURLINFO_RESPONSE_CODE, &(hc->httpresp)); */

        curl_easy_cleanup(curl);
    }
    /* curl_global_cleanup(); */

    free(full_url);


#if 0
        long ocsp_response_len = BIO_get_mem_data(returned_data, NULL);
        printf("HTTP OCSP Response length %d\n", ocsp_response_len);
        unsigned char *ocsp_response_raw = malloc(ocsp_response_len);

        printf("HTTP OCSP Response length %d\n", ocsp_response_len);
        memset(returned_data, 0, ocsp_response_len);

        BIO_read(returned_data, ocsp_response_raw, ocsp_response_len);
#endif


    return returned_data;
}


static const char *extract_responder_uri(X509 *cert)
{
    STACK_OF(ACCESS_DESCRIPTION) *values;
    char *result = NULL;
    int j;

    values = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (!values) {
        return NULL;
    }

    for (j = 0; j < sk_ACCESS_DESCRIPTION_num(values) && !result; j++) {
        ACCESS_DESCRIPTION *value = sk_ACCESS_DESCRIPTION_value(values, j);

        /* Name found in extension, and is a URI: */
        if (OBJ_obj2nid(value->method) == NID_ad_OCSP
            && value->location->type == GEN_URI) {
            /* result = apr_pstrdup(pool, */
                                 /* (char *)value->location->d.uniformResourceIdentifier->data); */
        }
    }

    AUTHORITY_INFO_ACCESS_free(values);

    return result;
}

static int load_pkcs12(BIO *err, BIO *in, const char *desc,
        pem_password_cb *pem_cb,  void *cb_data,
        EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char tpass[PEM_BUFSIZE];
    int len, ret = 0;
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL)
    {
        BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);
        goto die;
    }
    /* See if an empty password will do */
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
        pass = "";
    else
    {
        if (!pem_cb)
            pem_cb = NULL;
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if (len < 0)
        {
            BIO_printf(err, "Passpharse callback error for %s\n",
                    desc);
            goto die;
        }
        if (len < PEM_BUFSIZE)
            tpass[len] = 0;
        if (!PKCS12_verify_mac(p12, tpass, len))
        {
            BIO_printf(err,
                    "Mac verify error (wrong password?) in PKCS12 file for %s\n", desc);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
die:
    if (p12)
        PKCS12_free(p12);
    return ret;
}

X509 *load_cert(BIO *err, const char *file, int format,
        const char *pass, ENGINE *e, const char *cert_descrip)
{
    X509 *x=NULL;
    BIO *cert;

    if ((cert=BIO_new(BIO_s_file())) == NULL)
    {
        ERR_print_errors(err);
        goto end;
    }

    if (file == NULL)
    {
#ifdef _IONBF
        setvbuf(stdin, NULL, _IONBF, 0);
#endif
        BIO_set_fp(cert,stdin,BIO_NOCLOSE);
    }
    else
    {
        if (BIO_read_filename(cert,file) <= 0)
        {
            BIO_printf(err, "Error opening %s %s\n",
                    cert_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    }

    if  (format == FORMAT_ASN1)
        x=d2i_X509_bio(cert,NULL);

    else if (format == FORMAT_PEM)
        x=PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    else if (format == FORMAT_PKCS12)
    {
        if (!load_pkcs12(err, cert,cert_descrip, NULL, NULL,
                    NULL, &x, NULL))
            goto end;
    }
    else    {
        BIO_printf(err,"bad input format specified for %s\n",
                cert_descrip);
        goto end;
    }
end:
    if (x == NULL)
    {
        BIO_printf(err,"unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != NULL) BIO_free(cert);
    return(x);
}


/* =============================================== */

#  define openssl_fdset(a,b) FD_SET(a, b)

#if 0
int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx, OCSP_REQUEST *req)
{
    static const char req_hdr[] =
        "Content-Type: application/ocsp-request\r\n"
        "Content-Length: %d\r\n\r\n";

    BIO *bio = NULL;
    /* if (BIO_printf(rctx->mem, req_hdr, i2d_OCSP_REQUEST(req, NULL)) <= 0) */
        /* return 0; */
    /* if (i2d_OCSP_REQUEST_bio(rctx->mem, req) <= 0) */
        /* return 0; */
    /* rctx->state = OHS_ASN1_WRITE; */
    /* rctx->asn1_len = BIO_get_mem_data(rctx->mem, NULL); */


    static char buffer[2048];
    buffer[2047] = '\0';

    BIO_read(rctx->mem, buffer, 2047);
    BIO_printf(bio_err, "OCSP:\n%s\n", buffer);

    return 1;
}

/*
int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx,
        const char *name, const char *value)
{
    if (!name)
        return 0;
    if (BIO_puts(rctx->mem, name) <= 0)
        return 0;
    if (value)
    {
        if (BIO_write(rctx->mem, ": ", 2) != 2)
            return 0;
        if (BIO_puts(rctx->mem, value) <= 0)
            return 0;
    }
    if (BIO_write(rctx->mem, "\r\n", 2) != 2)
        return 0;
    return 1;
}
*/

static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio, char *path,
				STACK_OF(CONF_VALUE) *headers,
				OCSP_REQUEST *req, int req_timeout)
	{
	int fd;
	int rv;
	int i;
	OCSP_REQ_CTX *ctx = NULL;
	OCSP_RESPONSE *rsp = NULL;
	fd_set confds;
	struct timeval tv;

	if (req_timeout != -1)
		BIO_set_nbio(cbio, 1);

	rv = BIO_do_connect(cbio);

	if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio)))
		{
		BIO_puts(err, "Error connecting BIO\n");
		return NULL;
		}

	if (BIO_get_fd(cbio, &fd) <= 0)
		{
		BIO_puts(err, "Can't get connection fd\n");
		goto err;
		}

	if (req_timeout != -1 && rv <= 0)
		{
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = req_timeout;
		rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		if (rv == 0)
			{
			BIO_puts(err, "Timeout on connect\n");
			return NULL;
			}
		}


	ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
	if (!ctx)
		return NULL;

        /*
	for (i = 0; i < sk_CONF_VALUE_num(headers); i++)
		{
		CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
		if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
			goto err;
		}
        */

	if (!OCSP_REQ_CTX_set1_req(ctx, req))
		goto err;

	for (;;)
		{
		rv = OCSP_sendreq_nbio(&rsp, ctx);
		if (rv != -1)
			break;
		if (req_timeout == -1)
			continue;
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = req_timeout;
		if (BIO_should_read(cbio))
			rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
		else if (BIO_should_write(cbio))
			rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		else
			{
			BIO_puts(err, "Unexpected retry condition\n");
			goto err;
			}
		if (rv == 0)
			{
			BIO_puts(err, "Timeout on request\n");
			break;
			}
		if (rv == -1)
			{
			BIO_puts(err, "Select error\n");
			break;
			}

		}
	err:
	if (ctx)
		OCSP_REQ_CTX_free(ctx);

	return rsp;
	}

OCSP_RESPONSE *process_responder(BIO *err, OCSP_REQUEST *req,
			char *host, char *path, char *port, int use_ssl,
			STACK_OF(CONF_VALUE) *headers,
			int req_timeout)
	{
	BIO *cbio = NULL;
	SSL_CTX *ctx = NULL;
	OCSP_RESPONSE *resp = NULL;
	cbio = BIO_new_connect(host);
	if (!cbio)
		{
		BIO_printf(err, "Error creating connect BIO\n");
		goto end;
		}
	if (port) BIO_set_conn_port(cbio, port);
	if (use_ssl == 1)
		{
		BIO *sbio;
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
		ctx = SSL_CTX_new(SSLv23_client_method());
#elif !defined(OPENSSL_NO_SSL3)
		ctx = SSL_CTX_new(SSLv3_client_method());
#elif !defined(OPENSSL_NO_SSL2)
		ctx = SSL_CTX_new(SSLv2_client_method());
#else
		BIO_printf(err, "SSL is disabled\n");
			goto end;
#endif
		if (ctx == NULL)
			{
			BIO_printf(err, "Error creating SSL context.\n");
			goto end;
			}
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		sbio = BIO_new_ssl(ctx, 1);
		cbio = BIO_push(sbio, cbio);
		}
	resp = query_responder(err, cbio, path, headers, req, req_timeout);
	if (!resp)
		BIO_printf(bio_err, "Error querying OCSP responsder\n");
	end:
	if (cbio)
		BIO_free_all(cbio);
	if (ctx)
		SSL_CTX_free(ctx);
	return resp;
	}
#endif


static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,const EVP_MD *cert_id_md, X509 *issuer,
        STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    X509_NAME *iname;
    ASN1_BIT_STRING *ikey;
    ASN1_INTEGER *sno;
    if(!issuer)
    {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if(!*req) *req = OCSP_REQUEST_new();
    if(!*req) goto err;
    iname = X509_get_subject_name(issuer);
    ikey = X509_get0_pubkey_bitstr(issuer);
    sno = s2i_ASN1_INTEGER(NULL, serial);
    if(!sno)
    {
        BIO_printf(bio_err, "Error converting serial number %s\n", serial);
        return 0;
    }
    id = OCSP_cert_id_new(cert_id_md, iname, ikey, sno);
    ASN1_INTEGER_free(sno);
    if(!id || !sk_OCSP_CERTID_push(ids, id)) goto err;
    if(!OCSP_request_add0_id(*req, id)) goto err;
    return 1;

err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}


static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md,X509 *issuer,
        STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    if(!issuer)
    {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if(!*req) *req = OCSP_REQUEST_new();
    if(!*req) goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if(!id || !sk_OCSP_CERTID_push(ids, id)) goto err;
    if(!OCSP_request_add0_id(*req, id)) goto err;
    return 1;

err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

/* Serialize an OCSP request which will be sent to the responder at
 * given URI to a memory BIO object, which is returned. */
static BIO *serialize_request(OCSP_REQUEST *req, const char *uri, const char *host, const char *port)
{
    BIO *bio;
    int len;

    len = i2d_OCSP_REQUEST(req, NULL);

    bio = BIO_new(BIO_s_mem());

    BIO_printf(bio, "POST %s HTTP/1.0\r\n"
            "Host: %s:%s\r\n"
            "Content-Type: application/ocsp-request\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            uri,
            host, port,
            len);

    if (i2d_OCSP_REQUEST_bio(bio, req) != 1) {
        BIO_free(bio);
        return NULL;
    }

    return bio;
}


static BIO *verify_ocsp_request_serialize(OCSP_REQUEST *req) {
    BIO *bio;
    bio = BIO_new(BIO_s_mem());

    if (i2d_OCSP_REQUEST_bio(bio, req) != 1) {
        BIO_free(bio);
        return NULL;
    }

    return bio;
}


OCSP_REQUEST *verify_ocsp_construct_ocsp_request(X509 *subject, X509 *issuer, int add_nonce, const char *digest_name, int verbose) {
    OCSP_REQUEST *req = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;
    const EVP_MD *cert_id_md = NULL;

    ids = sk_OCSP_CERTID_new_null();

    /* Select a digest or use SHA1 as the default */
    if (digest_name) {
        cert_id_md = EVP_get_digestbyname(digest_name);
    } else {
        cert_id_md = EVP_sha1();
    }

    /* No digest is failure */
    if (cert_id_md == NULL) {
        goto failure;
    }

    /* Create an OCSP REQUEST based on the certificates */
    if(!add_ocsp_cert(&req, subject, cert_id_md, issuer, ids))
        goto failure;

    /* Bad for caching to add this... */
    if (add_nonce)
        OCSP_request_add1_nonce(req, NULL, -1);

    /* print */
    if (verbose)
        OCSP_REQUEST_print(bio_err, req, 0);

    return req;

failure:
    return NULL;
}


const char *
verify_url_cleaner(const char *uri) {
    const char *p = NULL;

    if (!uri)
        return NULL;

    if ((p = strstr(uri, "https://"))) {
        p = &(p[strlen("https://")]);
    } else  if ((p = strstr(uri, "http://"))) {
        p = &(p[strlen("http://")]);
    } else  if ((p = strstr(uri, "ftp://"))) {
        p = &(p[strlen("ftp://")]);
    }

    printf("%s\n", p);

    return p;
}


char *
verify_base64_encode(const unsigned char *input, int length) {
    char *output_buf, *b64_buf;
    long output_len;
    BIO *b64_bio;
    BIO *magic_bio;

    b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    magic_bio = BIO_new(BIO_s_mem());
    magic_bio = BIO_push(b64_bio, magic_bio);

    BIO_write(magic_bio, input, length);
    BIO_flush(magic_bio);

    output_len = BIO_get_mem_data(magic_bio, &output_buf);
    b64_buf = malloc(output_len + 1);
    b64_buf[output_len] = '\0';

    memcpy(b64_buf, output_buf, output_len);

    BIO_free_all(magic_bio);
    return b64_buf;
}

char *
verify_base64_decode(unsigned char *input, int length) {
    BIO *b64, *bmem;

    char *buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

X509_STORE *
verify_ocsp_construct_x509_store(char *CAfile, char *CApath)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    if(!(store = X509_STORE_new()))
        goto end;
    lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;
    if (CAfile) {
        if(!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
            goto end;
        }
    }
    /* } else X509_LOOKUP_load_file(lookup,NULL,X509_FILETYPE_DEFAULT); */

    lookup = X509_STORE_add_lookup(store,X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        goto end;
    if (CApath) {
        if(!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM)) {
            goto end;
        }
    }
    /* } else X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT); */

    ERR_clear_error();
    return store;
end:
    X509_STORE_free(store);
    return NULL;
}


static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)
{
    int i;
    unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
    X509 *x;

    /* Easy if lookup by name */
    if (id->type == V_OCSP_RESPID_NAME)
        return X509_find_by_subject(certs, id->value.byName);

    /* Lookup by key hash */

    /* If key hash isn't SHA1 length then forget it */
    if (id->value.byKey->length != SHA_DIGEST_LENGTH) return NULL;
    keyhash = id->value.byKey->data;
    /* Calculate hash of each key and compare */
    for (i = 0; i < sk_X509_num(certs); i++)
    {
        x = sk_X509_value(certs, i);
        X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
        if(!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
            return x;
    }
    return NULL;
}

static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
        X509_STORE *st, unsigned long flags)
{
    X509 *signer;
    OCSP_RESPID *rid = bs->tbsResponseData->responderId;
    if ((signer = ocsp_find_signer_sk(certs, rid)))
    {
        *psigner = signer;
        return 2;
    }
    if(!(flags & OCSP_NOINTERN) &&
            (signer = ocsp_find_signer_sk(bs->certs, rid)))
    {
        *psigner = signer;
        return 1;
    }
    /* Maybe lookup from store if by subject name */

    *psigner = NULL;
    return 0;
}



int
verify_ocsp_process_response(OCSP_RESPONSE *resp,
                             OCSP_REQUEST *req, X509 *subject, X509 *issuer,
                             const char *cafile, const char *capath, int use_nonce) {
    int ocsp_response_stat = OCSP_RESPONSE_STATUS_INTERNALERROR;
    OCSP_BASICRESP *basic = NULL;
    X509_STORE *x509_store = NULL;
    unsigned long verify_flags = 0;
    X509 *signer = NULL;
    int ret;


    OCSP_RESPONSE_print(bio_err, resp, 0);


    ocsp_response_stat = OCSP_response_status(resp);
    printf("Response status: %s (%d)\n", OCSP_response_status_str(ocsp_response_stat), ocsp_response_stat);

    /* Extract the basic */
    basic = OCSP_response_get1_basic(resp);
    if (basic == NULL) {
        return -1;
    }

    /* When used, check it */
    if (use_nonce && OCSP_check_nonce(req, basic) <= 0) {
        return -1;
    }

    if (OCSP_resp_count(basic) > 1) {
        printf("Sorry, not supporting more than 1 responses per call\n");
    }

    /* Mini OCSP_basic_verify() */
    x509_store = verify_ocsp_construct_x509_store(cafile, capath);

    OCSP_RESPID *rid = basic->tbsResponseData->responderId;
    ret = ocsp_find_signer(&signer, basic, NULL, x509_store, 0);
    if (ret == 0) {
        printf("Signer not found\n");
    }

    EVP_PKEY *skey;
    skey = X509_get_pubkey(issuer); /* Signer */
    ret = OCSP_BASICRESP_verify(basic, skey, 0);

    printf("OCSP_BASICRESP_verify: %d, and %c\n", ret, skey ? 'y' : 'n');
    EVP_PKEY_free(skey);

    if (basic->certs) {
        printf("OCSP_BASICRESP certs count: %d\n", sk_X509_num(basic->certs));
    } else {
        printf("OCSP_BASICRESP certs are NULL\n");
    }
    /* Mini OCSP_basic_verify() */

    printf("OCSP_basic_verify(): %d\n", OCSP_basic_verify(basic, NULL, x509_store, OCSP_NOVERIFY));

    OCSP_CERTID *id;
    ASN1_GENERALIZEDTIME  *producedAt, *thisUpdate, *nextUpdate;
    int reason = 0, status = 0;
    const EVP_MD *cert_id_md = NULL;

    /* Select a digest or use SHA1 as the default */
    const char *digest_name = "sha1";

    if (digest_name) {
        cert_id_md = EVP_get_digestbyname(digest_name);
    } else {
        cert_id_md = EVP_sha1();
    }
    id = OCSP_cert_to_id(cert_id_md, subject, issuer);

    ret = OCSP_resp_find_status(basic, id, &status, &reason, &producedAt, &thisUpdate, &nextUpdate);
    if (ret == 0) {
        printf("Getting OCSP_resp_find_status() failed!\n");
    }
    printf("Thumbs up\n");

    ret = OCSP_check_validity(thisUpdate, nextUpdate, 300, 3600*24*2);
    if (ret == 0) {
        printf("Not valid\n");
    } else {
        printf("Timewise valid\n");
    }




    X509_STORE_CTX *ctx;
    int i;
    int init_res;

    init_res = X509_STORE_CTX_init(&ctx, x509_store, issuer, NULL);
    if(!init_res)
    {
        printf("Failed to initialize X509_STORE_CTX\n");
    }

    X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
    X509_STORE_CTX_set_trust(&ctx, X509_TRUST_OCSP_REQUEST);
    X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
    ret = X509_verify_cert(&ctx);

    printf("ret: %d\n", ret);
#if 0
    chain = X509_STORE_CTX_get1_chain(&ctx);
    X509_STORE_CTX_cleanup(&ctx);
    if (ret <= 0)
    {
        i = X509_STORE_CTX_get_error(&ctx);
        OCSPerr(OCSP_F_OCSP_BASIC_VERIFY,OCSP_R_CERTIFICATE_VERIFY_ERROR);
        ERR_add_error_data(2, "Verify error:",
                X509_verify_cert_error_string(i));
        goto end;
    }
#endif


#if 0
X509_subject_name_cmp(*a,*b);
/* Compare by sha1 hash */
int X509_cmp(const X509 *a, const X509 *b)
#endif

    X509_STORE_CTX *ocsp_verify_ctx;
    ocsp_verify_ctx = X509_STORE_CTX_new();
    if (ocsp_verify_ctx == NULL)
        return -1;

    if ( X509_STORE_CTX_init(ocsp_verify_ctx, x509_store, subject, NULL) != 1 )
    {
        printf("Could not initialize verification context.");
        return ERR_get_error();
    }

    int rc;

    STACK_OF(X509) *stack = NULL;
    sk_X509_new(stack);
    sk_X509_push(stack, issuer);

    printf("%d\n", sk_X509_num(stack));

    signer = ocsp_find_signer(&signer, basic, stack, x509_store, 0);
    if (signer)
        printf("Found signer\n");
    else
        printf("signer not found\n");


    verify_flags |= OCSP_TRUSTOTHER;
    verify_flags |= OCSP_NOVERIFY;
    verify_flags |= OCSP_NOSIGS;
    verify_flags |= OCSP_NOCHAIN;
    verify_flags |= OCSP_NOCHECKS;


    rc = OCSP_basic_verify(basic, NULL, x509_store, verify_flags);
    printf("OCSP_basic_verify() rc: %d\n", rc);

    return 0;
#if 0

    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        if (OCSP_check_nonce(request, basicResponse) != 1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01924)
                    "Bad OCSP responder answer (bad nonce)");
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }


    /* The last param. may be used when OCSP API is fully defined*/
    rc = OCSP_basic_verify(basic, data->cert_chain, x509_store, verify_flags);
    if (rc < 0)
        rc = OCSP_basic_verify(basic, NULL, store, 0);
    if (rc <= 0) {
        /*response verify failure*/
        result = CANL_OCSPRESULT_ERROR_VERIFYRESPONSE;
        goto end;
    }

    if (!OCSP_resp_find_status(basic, id, &status, &reason, &producedAt,
                &thisUpdate, &nextUpdate)){
        result = CANL_OCSPRESULT_ERROR_NOSTATUS;
        goto end;
    }
    if (!OCSP_check_validity(thisUpdate, nextUpdate,
                data->skew, data->maxage)) {
        result = CANL_OCSPRESULT_ERROR_INVTIME;
        goto end;
    }

    /* All done.  Set the return code based on the status from the response. */
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        result = CANL_OCSPRESULT_CERTIFICATE_REVOKED;
        /*TODO myproxy_log("OCSP status revoked!"); */
    } else {
        result = CANL_OCSPRESULT_CERTIFICATE_VALID;
        /*TODO myproxy_log("OCSP status valid"); */
    }

#endif
}

int
ocsp_magic(X509 *subject, X509 *issuer, const char *cafile, const char *capath) {
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;

    char *ocsp_url = "http://ocsp.tcs.terena.org";
    BIO *ocsp_request_serialized_bio = NULL;

    char *input_buf = NULL;
    char *output_buf = NULL;
    long input_len = 0;

    BIO *ocsp_response_bio = NULL;

    /* char *host = NULL, *port = NULL, *path = "/"; */
    /* int add_nonce = 1, noverify = 0, use_ssl = -1; */
    /* int req_timeout = -1; */

    /* Construct an OCSP Request */
    req = verify_ocsp_construct_ocsp_request(subject, issuer, 0, "sha1", 1);
    if (req) {
        printf("request constructed...\n");
    } else {
        printf("failed to create a request\n");
    }

    /* Parse OCSP URL */
    /* URI:http://ocsp.tcs.terena.org */

#if 0
    if (!OCSP_parse_url(args, &host, &port, &path, &use_ssl))
    {
        BIO_printf(bio_err, "Error parsing URL\n");
        return EXIT_CODE_BAD;
    }
#endif

    /* Serialized OCSP REQUEST */
    ocsp_request_serialized_bio = verify_ocsp_request_serialize(req);
    if (ocsp_request_serialized_bio == NULL) {
        printf("Unable to serialize the OCSP REQUEST object\n");
        return EXIT_CODE_BAD;
    }

    printf(".............................\n");

    /* base64 encode the OCSP request */
    input_len = BIO_get_mem_data(ocsp_request_serialized_bio, NULL);
    input_buf = malloc(input_len + 1);
    BIO_read(ocsp_request_serialized_bio, input_buf, input_len);
    input_buf[input_len] = '\0';

    output_buf = verify_base64_encode(input_buf, input_len);

    #define RFC5019_OCSP_BASE64_GET_MAX_BYTES 255
    /* if ((strlen(output_buf) + strlen(ocsp_url) + 1) > RFC5019_OCSP_BASE64_GET_MAX_BYTES) { */
    if (1) {
        printf("Must use POST\n");
        printf("input_len:  %d\n", input_len);
        ocsp_response_bio = verify_ocsp_http(ocsp_url, input_buf, input_len, 0);

        printf("%lu bytes retrieved\n", (long)BIO_get_mem_data(ocsp_response_bio, NULL));
    } else {
        printf("Can use GET: %s/%s\n", ocsp_url, output_buf);
        ocsp_response_bio = verify_ocsp_http(ocsp_url, output_buf, strlen(output_buf), 1);

        printf("%lu bytes retrieved\n", (long)BIO_get_mem_data(ocsp_response_bio, NULL));
    }

    if (ocsp_response_bio) {
        resp = d2i_OCSP_RESPONSE_bio(ocsp_response_bio, NULL);
        if (resp) {
            printf("Owwww yeah!\n");
            verify_ocsp_process_response(resp, req, subject, issuer, cafile, capath, 0);
        } else {
            printf("No!\n");
        }
    } else {
        return EXIT_CODE_BAD;
    }

    return EXIT_CODE_GOOD;
}


int main (int argc, char * argv[])
{
    X509 *cert = NULL;
    X509 *cert_ca = NULL;

    SSL_library_init();
    SSL_load_error_strings();

    const char *cafile = "/etc/grid-security/certificates/TERENAeSciencePersonalCA.pem";
    const char *capath = "/etc/grid-security/certificates/";

    if (bio_err == NULL) bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    cert = load_cert(bio_err, "/Users/okoeroo/.globus/terena/terena-cert.pem",
                     FORMAT_PEM, NULL, NULL, "certificate");
    if (cert == NULL) return EXIT_CODE_BAD;

    cert_ca = load_cert(bio_err, "/etc/grid-security/certificates/TERENAeSciencePersonalCA.pem",
                        FORMAT_PEM, NULL, NULL, "certificate");
    if (cert_ca == NULL) return EXIT_CODE_BAD;

    /* magic */
    return ocsp_magic(cert, cert_ca, cafile, capath);
}

/* *presp = d2i_OCSP_RESPONSE(NULL, &p, rctx->asn1_len); */

