# AWS Compent for ESP-IDF

Current only support GET from S3 But I would like to add more.

example usage:

```c
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

char img[4000] = { NULL };

//Setup Structure
struct aws_request r = {
    .key_id = CONFIG_AWS_KEY_ID,
    .key_secret = CONFIG_AWS_SECRET,
    .region = "us-east-2",
    .host = WEB_SERVER,
    .path = FILE,
    .tls_cfg = {
        .cacert_pem_buf  = server_root_cert_pem_start,
        .cacert_pem_bytes = server_root_cert_pem_end - server_root_cert_pem_start,
    }
};

//Puts http body in img (upto sizeof(img)) returns number of bytes received
int received = aws_s3_get(&r, img, sizeof(img));
if(received < 0) {
    ESP_LOGE(TAG, "AWS S3 Error %d",received);    
}
```
