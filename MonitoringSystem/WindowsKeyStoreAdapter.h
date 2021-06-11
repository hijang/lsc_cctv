#pragma once

#include <openssl/ssl.h>

bool loadCertificatesFromWCS(SSL_CTX* ctx);