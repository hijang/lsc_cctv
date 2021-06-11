//------------------------------------------------------------------------------------------------
// File: RecvImageTCP.cpp
// Project: LG Exec Ed Program
// Versions:
// 1.0 April 2017 - initial version
// This program receives a jpeg image via a TCP Stream and displays it. 
//----------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"

using namespace cv;
using namespace std;
//----------------------------------------------------------------
// main - This is the main program for the RecvImageUDP demo 
// program  contains the control loop
//-----------------------------------------------------------------

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

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

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void)
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* Load cryptos, et.al. */
    SSL_load_error_strings();            /* Bring in and register error messages */
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
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
    std::cout << "Load certifcates. cert: " << CertFile << "/ key: " << KeyFile << std::endl;
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

int VerifyCertificate(SSL_CTX* ctx) {
    X509_STORE* store;
    X509* cert = NULL;
    BIO* bio = BIO_new_mem_buf(root_ca, -1);

    PEM_read_bio_X509(bio, &cert, 0, NULL);
    if (cert == NULL) {
        printf("PEM_read_bio_X509 failed...\n");
    }

    /* get a pointer to the X509 certificate store (which may be empty!) */
    store = SSL_CTX_get_cert_store((SSL_CTX*)ctx);

    /* add our certificate to this store */
    if (X509_STORE_add_cert(store, cert) == 0) {
        printf("error adding certificate\n");
    }

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, NULL);
    return X509_verify_cert(store_ctx);;
}


int main(int argc, char* argv[])
{
    SSL_CTX* ctx;
    SSL* ssl;
    TTcpConnectedPort* TcpConnectedPort = NULL;
    bool retvalue;

    if (argc != 3)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    //  Initialize SSL context
    ctx = InitCTX();
    LoadCertificates(ctx, "..\\Certificates\\client.crt", "..\\Certificates\\client.key");
    ssl = SSL_new(ctx);

    if ((TcpConnectedPort = OpenTcpConnection(argv[1], argv[2])) == NULL)  // Open UDP Network port
    {
        printf("OpenTcpConnection\n");
        return(-1);
    }
    SSL_set_fd(ssl, TcpConnectedPort->ConnectedFd);
    if (SSL_connect(ssl) == -1) {
        printf("Connect failed\n");
        return(-1);
    }

    X509* server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert != NULL) {
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
    }
    else {
        printf("Server does not have certificate.\n");
        return -1;
    }

    int verified = VerifyCertificate(ctx);
    if (verified <= 0) {
        printf("Verify failed (%d)\n", verified);

        SSL_free(ssl);

        CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
        SSL_CTX_free(ctx);
        return -1;
    }

    namedWindow("Server", WINDOW_AUTOSIZE);// Create a window for display.

    Mat Image;
    do {
        retvalue = SslRecvImageAsJpeg(ssl, TcpConnectedPort, &Image);
        // TODO: Make me a function.

        if (retvalue) imshow("Server", Image); // If a valid image is received then display it
        else break;

    } while (waitKey(10) != 'q'); // loop until user hits quit

    printf(" Closing... \n");

    SSL_free(ssl);

    CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
    SSL_CTX_free(ctx);

    return 0;
}
//-----------------------------------------------------------------
// END main
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
