#include <stdio.h>
#include "SslConnect.h"

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

static const char* PATH_CERT_FILE = "..\\..\\Certificates\\client.crt";
static const char* PATH_PRIVATE_KEY_FILE = "..\\..\\Certificates\\client.key";

static const char* root_ca = "-----BEGIN CERTIFICATE-----\n"
        "MIICODCCAd8CFGnngwBSCkZRYpt92Eo8R4SyB1h8MAoGCCqGSM49BAMCMIGdMQsw\n"
        "CQYDVQQGEwJLUjEOMAwGA1UECAwFU2VvdWwxEDAOBgNVBAcMB0dhbmduYW0xDDAK\n"
        "BgNVBAoMA0xHRTEWMBQGA1UECwwNU2VjU3BlY2lhbGlzdDElMCMGA1UEAwwcNHRl\n"
        "bnRpYWwgQ0EgUm9vdCBDZXJ0aWZpY2F0ZTEfMB0GCSqGSIb3DQEJARYQdGVobG9v\n"
        "QGdtYWlsLmNvbTAgFw0yMTA2MDUxNzEwNThaGA80NzU5MDUwMjE3MTA1OFowgZ0x\n"
        "CzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTZW91bDEQMA4GA1UEBwwHR2FuZ25hbTEM\n"
        "MAoGA1UECgwDTEdFMRYwFAYDVQQLDA1TZWNTcGVjaWFsaXN0MSUwIwYDVQQDDBw0\n"
        "dGVudGlhbCBDQSBSb290IENlcnRpZmljYXRlMR8wHQYJKoZIhvcNAQkBFhB0ZWhs\n"
        "b29AZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4O7qjNWPVgUF\n"
        "5CPbbe24bAGyV+AKKrrtbQ/eaYn90kpmtkL7o5br7GsZISW2SBbmBmYRH4Igg3/Y\n"
        "ftf4j0BCTDAKBggqhkjOPQQDAgNHADBEAiByX2OOGwkPgJm0hFm/Z5UjTvkLbPUK\n"
        "txYcyeSWQB/hzAIgez3HVhXUOKoAat9/hS86IG/bdubhggy4wOujM2ebfXM=\n"
        "-----END CERTIFICATE-----";

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
        printf("Connect failed\n");
        return false;
    }

    if (!CheckPeerCertificate()) {
        return false;
    }

    if (!this->VerifyCertificate()) {
        return false;
    }
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
    printf("Load certifcates. cert: %d / key: %s\n", certFile, keyFile);
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

bool SslConnect::CheckPeerCertificate() {
    X509* server_cert = SSL_get_peer_certificate(m_ssl);
    if (server_cert == NULL) {
        printf("Server does not have certificate.\n");
        return false;
    }
    printf("Client certificate:\n");

    char* str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);

    /* We could do all sorts of certificate verification stuff here before deallocating the certificate. */
    X509_free(server_cert);
    return true;
}

bool SslConnect::VerifyCertificate() {
    X509_STORE* store;
    X509* cert = NULL;
    BIO* bio = BIO_new_mem_buf(root_ca, -1);

    PEM_read_bio_X509(bio, &cert, 0, NULL);
    if (cert == NULL) {
        printf("PEM_read_bio_X509 failed...\n");
    }

    /* get a pointer to the X509 certificate store (which may be empty!) */
    store = SSL_CTX_get_cert_store((SSL_CTX*)m_ctx);

    /* add our certificate to this store */
    if (X509_STORE_add_cert(store, cert) == 0) {
        printf("error adding certificate\n");
    }

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, NULL);
    return X509_verify_cert(store_ctx);;
}

SSL* SslConnect::GetSSL() {
    return m_ssl;
}