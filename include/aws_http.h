#include <string.h>
#include "esp_tls.h"

#include "aws.h"

struct esp_tls *http_tls_connect(struct aws_request *r);
bool http_tls_send_header(struct esp_tls *tls, struct aws_request *r);
bool http_tls_check_status(struct esp_tls *tls);
bool http_tls_read_past_headers(struct esp_tls *tls, unsigned char *buf, size_t rlen, size_t *received);