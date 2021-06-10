#ifndef SSL_CONNECT_H
#define SSL_CONNECT_H

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <opencv2/core/core.hpp>
#include <iostream>

static const SSL_METHOD* ssl_method = SSLv23_server_method();

class SslConnect {
private:
	SSL* m_ssl;
	SSL_CTX* m_ctx;
	int listen_sd;
public:
	SslConnect();
	~SslConnect();

	bool loadCertification();
	static int verifyCertification(int preverify, X509_STORE_CTX* ctx);
	bool acceptConnection(int sd);
	int sslWriteFromImageToJpeg(cv::Mat Image);
};

#endif // SSL_CONNECT_H
