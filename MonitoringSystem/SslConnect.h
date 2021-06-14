#ifndef SSL_CONNECT_H
#define SSL_CONNECT_H

#include <openssl/ssl.h>
#include <openssl/err.h>

class SslConnect {
private:
	SSL* m_ssl;
	SSL_CTX* m_ctx;

	SSL_CTX* GetSslCtx(void);
	void LoadCertificates(const char* CertFile, const char* KeyFile);
	bool CheckPeerCertificate();
	bool VerifyCertificate();

public:
	SslConnect();
	~SslConnect();

	bool InitializeCtx();
	bool Connect(int fd);
	SSL* GetSSL();
};

#endif // SSL_CONNECT_H