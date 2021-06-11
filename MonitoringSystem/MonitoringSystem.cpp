//------------------------------------------------------------------------------------------------
// File: RecvImageTCP.cpp
// Project: LG Exec Ed Program
// Versions:
// 1.0 April 2017 - initial version
// This program receives a jpeg image via a TCP Stream and displays it. 
//----------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <sstream>
#include <tchar.h>

#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"

#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")


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


// Use a Window system call to display a Windows specific error
std::string errMessage(int win32Err)
{
    std::stringstream errmsg;
    errmsg << " " << std::hex << win32Err << std::dec << ": ";
    return errmsg.str();
}



bool report(const char* label, SECURITY_STATUS retv)
{
    std::cout << label;
    if (ERROR_SUCCESS == retv)
        std::cout << " ok" << std::endl;
    else
        std::cout << " reported error = " << errMessage(retv) << std::endl;

    return (ERROR_SUCCESS == retv);
}


bool report(const char* label, bool retv)
{
    std::cout << label;
    if (retv)
        std::cout << " ok" << std::endl;
    else
        std::cout << " failed." << std::endl;

    return (retv);
}

void report(const char* label, BYTE keyBlob[], DWORD len)
{
    std::cout << label << std::hex << std::setfill('0');
    for (unsigned b = 0; b < len; b++)
        std::cout << std::setw(2) << (int)keyBlob[b] << " ";
    std::cout << std::dec << std::endl;
}

bool exportPrivateKeyBlob(NCRYPT_KEY_HANDLE	hKey, LPCWSTR ngBlobType, std::vector<unsigned char>& keyblob)
{
    DWORD policy = NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG | NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG | NCRYPT_ALLOW_EXPORT_FLAG;
    if (!report("NCryptSetProperty( allow plaintext export )", ::NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(DWORD), 0)))
        return false;

    const int buffsize = 4096;
    keyblob.resize(buffsize);
    DWORD keylen = buffsize;
    if (!report("NCryptExportKey", ::NCryptExportKey(hKey, NULL, ngBlobType, NULL, keyblob.data(), buffsize, &keylen, 0)))
        return false;

    keyblob.resize(keylen);

    return true;
}

using RSA_unique = std::unique_ptr<RSA, decltype(&RSA_free)>;

inline RSA_unique make_RSA_unique(RSA* p)
{
    return RSA_unique(p, &RSA_free);
}


using X509_unique = std::unique_ptr<X509, decltype(&X509_free)>;

inline X509_unique make_X509_unique(X509* p)
{
    return X509_unique(p, &X509_free);
}



RSA_unique extractPrivateKey(const PCCERT_CONTEXT context)
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key_handle{};
    DWORD key_spec = 0;
    BOOL free_key = false;
    if (!CryptAcquireCertificatePrivateKey(context, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, nullptr, &key_handle, &key_spec, &free_key))
        return make_RSA_unique(nullptr);

    std::vector<unsigned char> data;
    if (!exportPrivateKeyBlob(key_handle, BCRYPT_RSAFULLPRIVATE_BLOB, data))
    {
        if (free_key)
            NCryptFreeObject(key_handle);
        return make_RSA_unique(nullptr);
    }

    // https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/ns-bcrypt-_bcrypt_rsakey_blob
    auto const blob = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(data.data());

    RSA* rsa = nullptr;
    DWORD length = 0;
    if (blob->Magic == BCRYPT_RSAFULLPRIVATE_MAGIC)
    {
        rsa = RSA_new();

        // n is the modulus common to both public and private key
        auto const n = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp, blob->cbModulus, nullptr);
        // e is the public exponent
        auto const e = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB), blob->cbPublicExp, nullptr);
        // d is the private exponent
        auto const d = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus + blob->cbPrime1 + blob->cbPrime2 + blob->cbPrime1 + blob->cbPrime2 + blob->cbPrime1, blob->cbModulus, nullptr);

        RSA_set0_key(rsa, n, e, d);

        // p and q are the first and second factor of n
        auto const p = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus, blob->cbPrime1, nullptr);
        auto const q = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus + blob->cbPrime1, blob->cbPrime2, nullptr);

        RSA_set0_factors(rsa, p, q);

        // dmp1, dmq1 and iqmp are the exponents and coefficient for CRT calculations
        auto const dmp1 = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus + blob->cbPrime1 + blob->cbPrime2, blob->cbPrime1, nullptr);
        auto const dmq1 = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus + blob->cbPrime1 + blob->cbPrime2 + blob->cbPrime1, blob->cbPrime2, nullptr);
        auto const iqmp = BN_bin2bn(data.data() + sizeof(BCRYPT_RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus + blob->cbPrime1 + blob->cbPrime2 + blob->cbPrime1 + blob->cbPrime2, blob->cbPrime1, nullptr);

        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
    }

    if (free_key)
        NCryptFreeObject(key_handle);

    return make_RSA_unique(rsa);
}


bool setCtxCertificateAndPrivateKey(SSL_CTX* ctx, const PCCERT_CONTEXT context)
{
    const unsigned char* encodedCert = context->pbCertEncoded;
    const auto x509 = make_X509_unique(d2i_X509(nullptr, &encodedCert, context->cbCertEncoded));
    if (!x509)
        return false;

    if (!SSL_CTX_use_certificate(ctx, x509.get()))
        return false;

    const auto rsa = extractPrivateKey(context);
    if (!rsa)
        return false;

    return SSL_CTX_use_RSAPrivateKey(ctx, rsa.get()) == 1;
}


const std::string KEY_NAME = "4tential host PC";

bool loadCertificatesFromWCS(SSL_CTX* ctx)
{
    HCERTSTORE hStore = CertOpenSystemStore(NULL, L"my");

    if (hStore == nullptr)
        return false;

    // 4tential host PC 키를 검색하여 처리
    PCCERT_CONTEXT pContext = NULL;
    while (pContext = CertEnumCertificatesInStore(hStore, pContext))
    {
        char currentKeyName[200] = {};
        if (CertGetNameStringA(pContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, currentKeyName, 128) <= 1)
			continue;

		if (std::string(currentKeyName) != KEY_NAME)
			continue;

		if (setCtxCertificateAndPrivateKey(ctx, pContext))
		{
			/* verify private key */
			if (!SSL_CTX_check_private_key(ctx))
			{
				fprintf(stderr, "Private key does not match the public certificate\n");
				return false;
			}

			return true;
		}
		else
		{
			char keyName[200] = {};
			if (CertGetNameStringA(pContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, keyName, 128))
				std::cout << "\nCertificate for " << keyName << " was failed.\n";

			//uncomment the line below if you want to see the certificates as pop ups
			//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pContext, NULL, NULL, 0, NULL);
		}
    }
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
    if (!loadCertificatesFromWCS(ctx))
    {
        // Windows Certificate Store에 key가 없는 경우 
        //std::cerr << "certification could not be found.\n";
        //return -1;
        // FIXME: 개발용으로 아래의 코드를 쓰지만, 테스트 버전에서는 삭제되어야 한다.
        LoadCertificates(ctx, "..\\Certificates\\client.crt", "..\\Certificates\\client.key");
    }
    ssl = SSL_new(ctx);

    if ((TcpConnectedPort = OpenTcpConnection(argv[1], argv[2])) == NULL)  // Open TCP Network port
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
