#include "s3.h"
#include "esp_log.h"

#define S3TAG "ESP-IDF AWS S3"

#define GOOD_HEADER "HTTP/1.1 200"

size_t aws_s3_create_request(struct aws_request *r, char * out, size_t len) {
    
    struct tm* tm_info = localtime(&r->timenow);

    const char *host_s = "https://%s%s";
    size_t l = snprintf(NULL, 0, host_s, r->host, r->path) + 1;
    r->url = (char *)malloc(l);
    snprintf(r->url, l, host_s, r->host, r->path);
    
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

size_t aws_s3_get(struct aws_request *r, void *out, size_t len) {

    char request[600];

    int rtn = aws_s3_create_request(r,request,sizeof(request));

    if(rtn < 0) return rtn;

    struct esp_tls *tls = esp_tls_conn_http_new(r->url, &r->tls_cfg);

    if(tls != NULL) {
        ESP_LOGI(S3TAG, "S3 Connection established...");
    } else {
        ESP_LOGE(S3TAG, "S3 Connection failed...");
        esp_tls_conn_delete(tls);    
        return -1;
    };

    int ret;
    size_t written_bytes = 0;

    do {
        ret = esp_tls_conn_write(
            tls, 
            request + written_bytes, 
            strlen(request) - written_bytes
        );

        if (ret >= 0) {
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ  && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(S3TAG, "esp_tls_conn_write  returned 0x%x", ret);
            esp_tls_conn_delete(tls);
            return -1;
        }
    } while(written_bytes < strlen(request));

    char buf[512];
    int received = 0;
    size_t rlen;
    rlen = sizeof(GOOD_HEADER) - 1;
    
    //Check code
    while(received < rlen) {
        int ret = esp_tls_conn_read(tls, (char *)(buf + received), rlen - received);
        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(S3TAG, "esp_tls_conn_read  returned -0x%x", -ret);
            break;
        }
        if(ret == 0)
        {
            ESP_LOGI(S3TAG, "connection closed");
            break;
        }
        received += ret;
    }

    if(received == rlen) {
        buf[received] = 0;            
        if(strcmp(buf,GOOD_HEADER) != 0) {
            ESP_LOGE(S3TAG, "HTTP BAD - %s",buf);
            esp_tls_conn_delete(tls);
            return -1;
        }
    }

    ESP_LOGI(S3TAG, "HTTP OK - %s",buf);

    received = 0;
    rlen = sizeof(buf);
    bool body_found = false;

    while(received < rlen) {
        int ret = esp_tls_conn_read(tls, (char *)(buf + received), rlen - received);
        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(S3TAG, "esp_tls_conn_read  returned -0x%x", -ret);
            esp_tls_conn_delete(tls);    
            return -1;
        }
        if(ret == 0)
        {
            ESP_LOGI(S3TAG, "connection closed");
            break;
        }
        received += ret;
        //Look For \r To find body
        int pos = 0;
        while (pos < received && buf[pos] != '\r') { pos++; }
        memmove(buf, buf + pos, received);
        received -= pos;
        //Is buf[0-3] \r\n\r\n (body)
        if(buf[0] == '\r' && buf[1] == '\n' && buf[2] == '\r' && buf[3] == '\n') {
            ESP_LOGI(S3TAG, "Body Found");
            memmove(buf, buf + 4, received);
            received -= 4;
            body_found = true;
            break;
        }
        //Is bud[0-1] \r\n\ (End OF Header Line)
        if(buf[0] == '\r' && buf[1] == '\n') {
            ESP_LOGI(S3TAG, "End Of Header");
            memmove(buf, buf + 2, received);
            received -= 2;
        }
    }

    if (!body_found) return -1;

    if(received > len) {
        memmove(out, buf, len);
        esp_tls_conn_delete(tls);
        return len;
    }

    memmove(out, buf, received);
    while(received < len) {
        int ret = esp_tls_conn_read(tls, (char *)(out + received), len - received);            
        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(S3TAG, "esp_tls_conn_read  returned -0x%x", -ret);
            esp_tls_conn_delete(tls);    
            return -1;
        }
        if(ret == 0)
        {
            ESP_LOGI(S3TAG, "connection closed");
            break;
        }
        received += ret;
    }

    esp_tls_conn_delete(tls);

    ESP_LOGI(S3TAG, "Received %d",received);
    return received;
}

