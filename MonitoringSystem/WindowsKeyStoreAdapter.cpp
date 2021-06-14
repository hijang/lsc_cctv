#include "WindowsKeyStoreAdapter.h"

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")


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

    return false;
}
