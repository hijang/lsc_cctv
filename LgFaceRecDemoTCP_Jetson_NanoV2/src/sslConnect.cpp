#include <opencv2/highgui/highgui.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "sslConnect.h"

static  int init_values[2] = { cv::IMWRITE_JPEG_QUALITY,80 };
static  std::vector<int> param (&init_values[0], &init_values[0]+2);
static  std::vector<uchar> sendbuff;

SslConnect::SslConnect()
	: m_ssl(NULL)
	, m_ctx(NULL)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	m_ctx = SSL_CTX_new(ssl_method);
}

SslConnect::~SslConnect()
{
	if (m_ssl)
		SSL_free(m_ssl);
	if (m_ctx)
		SSL_CTX_free(m_ctx);
	printf("SslConnect is deleted! \n");
}

int SslConnect::verifyCertification(int preverify, X509_STORE_CTX* ctx)
{
    char    buf[256];
    X509   *cert;
    SSL    *ssl;
    int err, depth;

    cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);

    if (depth >= 2) {
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }

    if (!preverify) {
        printf("\n verify error:%d:%s:depth:%d:%s \n", err, X509_verify_cert_error_string(err), depth, buf);
    }

    if (!preverify && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        X509_NAME_oneline(X509_get_issuer_name(cert), buf, 256);
        printf("issuer= %s\n", buf);
    }

    return preverify;

}

bool SslConnect::loadCertification()
{
	// load CCTV certification

	if (SSL_CTX_use_certificate_file(m_ctx, "../key/server.crt", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	// load CCTV private.pem

	if (SSL_CTX_use_PrivateKey_file(m_ctx, "../key/server.key", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	if (!SSL_CTX_check_private_key(m_ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		return false;
	}

	// set local rootca cert
	
	if(!SSL_CTX_load_verify_locations(m_ctx,"/home/hedaesik/work/CppSocketTest/Certificates/rootca.crt", NULL) || 
           !SSL_CTX_set_default_verify_paths(m_ctx)) {
        	fprintf(stderr, "Can't load CA cert\n");
        	ERR_print_errors_fp(stderr);
        	return false;
    	}

	SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, SslConnect::verifyCertification);
	SSL_CTX_set_verify_depth(m_ctx,1);
	return true;
}

bool SslConnect::acceptConnection(int sd)
{
	X509                *client_cert = NULL;

	m_ssl = SSL_new(m_ctx);
	if (!m_ssl) {
        	printf("Fail to create ssl \n");
		return false;
	}

	if (!SSL_set_fd(m_ssl, sd)) {
        	printf("Verify Certification is failed \n");
		return false;
	}
	printf("Wait for ssl connect \n");
	if (SSL_accept(m_ssl) == -1)
		return false;

	client_cert = SSL_get_peer_certificate(m_ssl);

	if (client_cert == NULL) {
        	printf("Client does not send client's certificate \n");
		return false;
	} else {
		X509_free(client_cert);
	}

	if(SSL_get_verify_result(m_ssl) != X509_V_OK) {
        	printf("Verify client certification is failed \n");
		return false;
	} else {
        	printf("Verify client certification is success \n");
	}
	return true;
}
int SslConnect::sslWriteFromImageToJpeg(cv::Mat Image)
{
	int result=0;
	unsigned int imagesize;
	cv::imencode(".jpg", Image, sendbuff, param);
	imagesize=htonl(sendbuff.size());
	result = SSL_write(m_ssl, (unsigned char *)&imagesize, sizeof(imagesize));
	if (result < 0) {
		int errorNum = SSL_get_error(m_ssl, result);
		if (errorNum == SSL_ERROR_WANT_WRITE ||
		    errorNum == SSL_ERROR_WANT_READ ) {
			printf("send ssl data, buffer is blocking, errno: %d.\n", errorNum);
		} else {
			printf("send ssl data error, errno: %d.\n", errorNum);
		}
		return -1;
	} else if (result == 0) {
		int errorNum = SSL_get_error(m_ssl, result);
		if (errorNum == SSL_ERROR_ZERO_RETURN) {
			printf("send ssl data error, peer closed.\n");
		} else {
			printf("send ssl data error, errno: %d. \n", errorNum);
		}
	}
	result = SSL_write(m_ssl, (unsigned char *)sendbuff.data(), sendbuff.size());
	if (result < 0) {
		int errorNum = SSL_get_error(m_ssl, result);
		if (errorNum == SSL_ERROR_WANT_WRITE ||
		    errorNum == SSL_ERROR_WANT_READ ) {
			printf("send ssl data, buffer is blocking, errno: %d.\n", errorNum);
		} else {
			printf("send ssl data error, errno: %d.\n", errorNum);
		}
		return -1;
	} else if (result == 0) {
		int errorNum = SSL_get_error(m_ssl, result);
		if (errorNum == SSL_ERROR_ZERO_RETURN) {
			printf("send ssl data error, peer closed.\n");
		} else {
			printf("send ssl data error, errno: %d. \n", errorNum);
		}
	}
	printf("Send data(size:%lu) success \n", sendbuff.size());
	return result;
}
