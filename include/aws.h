#include "crypto/common.h"
#include "crypto/sha256.h"

#include "sodium.h"
#include "sodium/crypto_hash_sha256.h"
#include "esp_tls.h"

/*
 * aws_auth_v4_signing_key - generates AWS signing key
 * @key: secret key
 * @amz_date: YYYYMMDD (string null terminated)
 * @region: AWS region (string null terminated)
 * @service: AWS Service (string null terminated)
 * @key_out: Signing key in binary 
 */

#define AWS_EMPTY_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define SHA256_MAC_HEX_LEN SHA256_MAC_LEN * 2
#define SHA256_MAC_HEX_LEN_STR SHA256_MAC_HEX_LEN + 1

struct aws_request {
    const char *key_id;
    char *key_secret;
    time_t timenow;
    char *url;
    char short_date[9];
    char *region;
    char *service;
    unsigned char date_key[SHA256_MAC_LEN];
    unsigned char region_key[SHA256_MAC_LEN];
    unsigned char service_key[SHA256_MAC_LEN];
    unsigned char signing_key[SHA256_MAC_LEN];
    const char *scope;
    const char *method;
    const char *host;
    const char *path;
    char *content_sha;
    char full_date[17];
    char *headers;
    char *header_host;
    char *header_content;
    char *header_date;
    char *header_authorization;
    char *canonical_request;
    size_t canonical_request_l;
    unsigned char canonical_mac[SHA256_MAC_LEN];
    char canonical_mac_hex[SHA256_MAC_HEX_LEN_STR];
    char *string_to_sign;
    size_t string_to_sign_l;    
    unsigned char string_to_sign_mac[SHA256_MAC_LEN];
    char string_to_sign_mac_hex[SHA256_MAC_HEX_LEN_STR];
    esp_tls_cfg_t tls_cfg;
    unsigned char *s3_out;
    size_t s3_out_l;
};

int aws_auth_v4_signing_key(struct aws_request *request);
int aws_s3_get_auth_v4_header(struct aws_request *request);
