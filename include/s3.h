#include "esp_tls.h"
#include "apps/sntp/sntp.h"

#include "aws.h"

size_t aws_s3_get(struct aws_request *r, void *out, size_t len);