#include "esp_tls.h"
#include "apps/sntp/sntp.h"

#include "aws.h"

size_t aws_s3_create_request(struct aws_request *r, char * out, size_t len);
size_t aws_s3_get(struct aws_request *r, void *out, size_t len);
