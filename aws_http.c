#include "esp_log.h"

#include "aws_http.h"

#define TAG "aws http"

#define GOOD_HEADER "HTTP/1.1 200"

struct esp_tls *http_tls_connect(struct aws_request *r) {

    const char *host_s = "https://%s%s";
    size_t l = snprintf(NULL, 0, host_s, r->host, r->path) + 1;
    r->url = (char *)malloc(l);
    snprintf(r->url, l, host_s, r->host, r->path);

    return  esp_tls_conn_http_new(r->url, &r->tls_cfg);
}

size_t http_create_request(struct aws_request *r, char * out, size_t len) {
    
    struct tm* tm_info = localtime(&r->timenow);
    
    r->service = "s3";
    r->content_sha = AWS_EMPTY_SHA256;
    r->headers = "host;x-amz-content-sha256;x-amz-date";

    snprintf(
        r->short_date,
        sizeof(r->short_date),
        "%04d%02d%02d",
        tm_info->tm_year + 1900,
        tm_info->tm_mon + 1,
        tm_info->tm_mday
    );
    snprintf(
        r->full_date,
        sizeof(r->full_date),
        "%04d%02d%02dT%02d%02d%02dZ",tm_info->tm_year + 1900,
        tm_info->tm_mon + 1,
        tm_info->tm_mday,
        tm_info->tm_hour,
        tm_info->tm_min,
        tm_info->tm_sec
    );
                
    aws_auth_v4_signing_key(r);
    aws_s3_get_auth_v4_header(r);
    size_t rtn = snprintf(
	    out,
	    len,
	        "GET %s HTTP/1.0\r\n"
            "user-agent:esp-idf/1.0 esp32\r\n"
	        "%s\r\n"
	        "%s\r\n"
            "%s\r\n"
	        "%s\r\n"
            "\r\n",
	    r->url,
	    r->header_host,
        r->header_date,
        r->header_content,
        r->header_authorization
    );

    return rtn;
}

bool http_tls_send_header(struct esp_tls *tls, struct aws_request *r) {

    char  *FTAG = TAG " " "http_tls_send_header";

    char request[600];

    int rtn = http_create_request(r,request,sizeof(request));

    if(rtn < 0) return false;

    size_t rlen = strlen(request);
    int ret;
    size_t written_bytes = 0;

    do {
        ret = esp_tls_conn_write(
            tls, 
            request + written_bytes, 
            rlen - written_bytes
        );

        if (ret >= 0) {
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ  && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(FTAG, "esp_tls_conn_write  returned 0x%x", ret);
            return false;
        }
    } while(written_bytes < rlen);

    return true;
}

bool http_tls_check_status(struct esp_tls *tls) {

    char  *FTAG = TAG " " "http_check_status";

    char buf[sizeof(GOOD_HEADER)];
    int received = 0;
    size_t rlen = sizeof(GOOD_HEADER) - 1;
    
    //Check code
    while(received < rlen) {
        int ret = esp_tls_conn_read(tls, (char *)(buf + received), rlen - received);
        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(FTAG, "esp_tls_conn_read  returned -0x%x", -ret);
            break;
        }
        if(ret == 0)
        {
            ESP_LOGI(FTAG, "connection closed");
            break;
        }
        received += ret;
    }

    if(received != rlen) return false;

    buf[received] = 0;            

    ESP_LOGI(FTAG, "header %s",buf);

    return (strcmp(buf,GOOD_HEADER) == 0);
}

bool http_tls_read_past_headers(struct esp_tls *tls, unsigned char *buf, size_t rlen, size_t *received) {

    char  *FTAG = TAG " " "http_read_past_header";

    *received = 0;
    bool body_found = false;

    while(*received < rlen) {
        int ret = esp_tls_conn_read(tls, (char *)(buf + *received), rlen - *received);
        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(FTAG, "esp_tls_conn_read  returned -0x%x", -ret);
            return false;
        }
        if(ret == 0)
        {
            ESP_LOGI(FTAG, "connection closed");
            break;
        }
        *received += ret;
        //Look For \r To find body
        int pos = 0;
        while (pos < *received && buf[pos] != '\r') { pos++; }
        memmove(buf, buf + pos, *received);
        *received -= pos;
        //Is buf[0-3] \r\n\r\n (body)
        if(buf[0] == '\r' && buf[1] == '\n' && buf[2] == '\r' && buf[3] == '\n') {
            ESP_LOGI(FTAG, "Body Found");
            memmove(buf, buf + 4, *received);
            *received -= 4;
            body_found = true;
            break;
        }
        //Is bud[0-1] \r\n\ (End OF Header Line)
        if(buf[0] == '\r' && buf[1] == '\n') {
            ESP_LOGI(FTAG, "End Of Header");
            memmove(buf, buf + 2, *received);
            *received -= 2;
        }
    }

    return body_found;
}