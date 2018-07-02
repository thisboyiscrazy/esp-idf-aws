#include <string.h>
#include "freertos/FreeRTOS.h"
//#include "crypto/common.h"
//#include "crypto/sha256.h"

//#include "sodium.h"
//#include "sodium/crypto_hash_sha256.h"

#include "aws.h"

#define TAG "ESP-IDF AWS"


/*
 * aws_auth_v4_signing_key - generates AWS signing key
 * @key: secret key
 * @amz_date: YYYYMMDD (string null terminated)
 * @region: AWS region (string null terminated)
 * @service: AWS Service (string null terminated)
 * @key_out: Signing key in binary 
 */
int aws_auth_v4_signing_key(struct aws_request *r) {

    const char *request = "aws4_request";

    // AWS4 + key + null;
    const int PREFIXED_KEY_LEN = 4 + strlen(r->key_secret) + 1;
    unsigned char *prefix_key = (unsigned char*)malloc(PREFIXED_KEY_LEN);
    snprintf((char *)prefix_key,PREFIXED_KEY_LEN,"%s%s","AWS4",r->key_secret);

    //Sign Date
    hmac_sha256((unsigned char*)prefix_key,PREFIXED_KEY_LEN - 1,(unsigned char *)r->short_date,strlen(r->short_date),r->date_key);
    
    //Sign Region
    hmac_sha256(r->date_key,SHA256_MAC_LEN,(unsigned char*)r->region,strlen(r->region),r->region_key);
    
    //Sign Service
    hmac_sha256(r->region_key,SHA256_MAC_LEN,(unsigned char*)r->service,strlen(r->service),r->service_key);
    
    //Sign 
    hmac_sha256(r->service_key,SHA256_MAC_LEN,(unsigned char*)request,strlen(request),r->signing_key);

    vPortFree(prefix_key);

    const char *AWS_SCOPE = "%s/%s/%s/%s";

    int l = snprintf(NULL, 0, AWS_SCOPE, r->short_date, r->region, r->service, request) + 1;
    char *t = (char *)malloc(l);
    if(t == NULL) return NULL;
    snprintf(t, l, AWS_SCOPE, r->short_date, r->region, r->service, request);

    r->scope = t;

    return 1;
    
}

int aws_request_canonical(struct aws_request *r) {

    size_t l;
    void *t;

    const char *header_host_s = "host:%s";
    l = snprintf(NULL, 0, header_host_s, r->host) + 1;
    t = (char *)malloc(l);
    snprintf(t, l, header_host_s, r->host);
    r->header_host = (char*)t;

    const char *header_contact_s = "x-amz-content-sha256:%s";
    l = snprintf(NULL, 0, header_contact_s, r->content_sha) + 1;
    t = malloc(l);
    snprintf(t, l, header_contact_s, r->content_sha);
    r->header_content = (char*)t;

    const char *header_date_s = "x-amz-date:%s";
    l = snprintf(NULL, 0, header_date_s, r->full_date) + 1;
    t = malloc(l);
    snprintf(t, l, header_date_s, r->full_date);
    r->header_date = (char*)t;

    const char *AWS_CANONICAL_PRINTF = 
        "GET\n"
        "%s\n"
        "\n"
        "%s\n"
        "%s\n"
        "%s\n"
        "\n"
        "%s\n"
        "%s"
    ;

    l = snprintf(
        NULL,
        0,
        AWS_CANONICAL_PRINTF,
        r->path,
        r->header_host,
        r->header_content,
        r->header_date,
        r->headers,
        r->content_sha
    ) + 1;
    t = malloc(l);
    if(t == NULL) return NULL;
    snprintf(
        t,
        l,
        AWS_CANONICAL_PRINTF,
        r->path,
        r->header_host,
        r->header_content,
        r->header_date,
        r->headers,
        r->content_sha
    );

    r->canonical_request = t;
    r->canonical_request_l = l;

    crypto_hash_sha256(r->canonical_mac,(unsigned char*)r->canonical_request,r->canonical_request_l - 1);
    sodium_bin2hex(r->canonical_mac_hex, SHA256_MAC_HEX_LEN_STR, r->canonical_mac, SHA256_MAC_LEN);

    return 1;
}

int aws_request_string_to_sign(struct aws_request *r) {

    const char *AWS_STRING_TO_SIGN =
        "AWS4-HMAC-SHA256\n"
        "%s\n"
        "%s\n"
        "%s"
    ;

    int l = snprintf(NULL, 0, AWS_STRING_TO_SIGN, r->full_date, r->scope, r->canonical_mac_hex) + 1;
    char *t = (char *)malloc(l);
    if(t == NULL) return NULL;
    snprintf(t, l, AWS_STRING_TO_SIGN, r->full_date, r->scope, r->canonical_mac_hex);

    hmac_sha256(r->signing_key, SHA256_MAC_LEN, (unsigned char*)t, l - 1, r->string_to_sign_mac);

    sodium_bin2hex(r->string_to_sign_mac_hex, SHA256_MAC_HEX_LEN_STR, r->string_to_sign_mac, SHA256_MAC_LEN);

    r->string_to_sign = t;
    r->string_to_sign_l = l;

    return 1;
}

int aws_s3_get_auth_v4_header(struct aws_request *r) {

    aws_request_canonical(r);
    aws_request_string_to_sign(r);

    const char *AWS_S3_AUTH_HEADER = 
        "authorization:"
        "AWS4-HMAC-SHA256 "
        "Credential=%s/%s, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=%s"
    ;

    int l = snprintf(NULL, 0, AWS_S3_AUTH_HEADER, r->key_id, r->scope, r->string_to_sign_mac_hex) + 1;
    char *t = (char *)malloc(l);
    if(t == NULL) return NULL;
    snprintf((char*)t, l, AWS_S3_AUTH_HEADER, r->key_id, r->scope, r->string_to_sign_mac_hex);

    r->header_authorization = t;

    return 1;
}