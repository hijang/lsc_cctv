#include <stdio.h>
#include "SslConnect.h"

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

static const char* PATH_CERT_FILE = "..\\..\\Certificates\\client.crt";
static const char* PATH_PRIVATE_KEY_FILE = "..\\..\\Certificates\\client.key";
static const char* PATH_ROOTCA_FILE = "..\\..\\Certificates\\rootca.crt";


SslConnect::SslConnect() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* Load cryptos, et.al. */
    SSL_load_error_strings();            /* Bring in and register error messages */
}

SslConnect::~SslConnect() {
    if (m_ssl != NULL) {
        SSL_free(m_ssl);
        m_ssl = NULL;
    }
    if (m_ctx != NULL) {
        SSL_CTX_free(m_ctx);
        m_ctx = NULL;
    }
}

bool SslConnect::InitializeCtx()
{
    m_ctx = this->GetSslCtx();
    if (m_ctx == NULL) {
        return false;
    }
    this->LoadCertificates(PATH_CERT_FILE, PATH_PRIVATE_KEY_FILE);
    return true;
}

bool SslConnect::Connect(int fd)
{
    m_ssl = SSL_new(m_ctx);
    SSL_set_fd(m_ssl, fd);
    if (SSL_connect(m_ssl) == -1) {
        printf("Connection failed\n");
        return false;
    }

    if (!this->VerifyCertificate()) {
        printf("Verification failed\n");
        return false;
    }

    return true;
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* SslConnect::GetSslCtx(void)
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = SSLv23_client_method();        /* Create new client-method instance */
    ctx = SSL_CTX_new(method);            /* Create new context */
    if (ctx == NULL)
    {
        printf("ctx Error\n");
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void SslConnect::LoadCertificates(const char* certFile, const char* keyFile)
{
    //printf("Load certifcates. cert: %s / key: %s\n", certFile, keyFile);
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(m_ctx, certFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(m_ctx, keyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(m_ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

bool SslConnect::VerifyCertificate() {
    X509_STORE* store;
    X509* server_cert = SSL_get_peer_certificate(m_ssl);
    if (server_cert == NULL) {
        printf("Server does not have certificate.\n");
        return false;
    }

    //  Show server certificate info
    printf("Server certificate:\n");
    char* str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);

    //  Verify server certificate
    if (!(store = X509_STORE_new()))
        printf("error creating store...\n");

    X509_STORE_CTX* vrfy_ctx = X509_STORE_CTX_new();
    int ret = X509_STORE_load_locations(store, PATH_ROOTCA_FILE, NULL);
    if (ret != 1) {
        printf("Error loading CA\n");
        return false;
    }

    X509_STORE_CTX_init(vrfy_ctx, store, server_cert, NULL);

    bool verified = (X509_verify_cert(vrfy_ctx) > 0);
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);
    X509_free(server_cert);

    return verified;
}

SSL* SslConnect::GetSSL() {
    return m_ssl;
}
