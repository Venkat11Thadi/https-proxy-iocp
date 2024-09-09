#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace std;

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable : 4996)

#define BUFFER_SIZE 4096

EVP_PKEY* generatePrivateKey()
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx)
    {
        cerr << "[-]EVP_PKEY_CTX_new_id failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        cerr << "[-]EVP_PKEY_keygen_init failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
    {
        cerr << "[-]EVP_PKEY_CTX_set_rsa_keygen_bits failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        cerr << "[-]EVP_PKEY_keygen failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void configureContext(SSL_CTX* ctx, X509* cert, EVP_PKEY* pkey)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate(ctx, cert) <= 0)
    {
        cerr << "[-]Error using certificate" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    else if (verbose)
    {
        cout << "[+]Certificate used" << endl;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
    {
        cerr << "[-]Error using private key" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    else if (verbose)
    {
        cout << "[+]Private key used" << endl;
    }
}

ASN1_INTEGER* generate_serial()
{
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial)
    {
        cerr << "ASN1_INTEGER_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Generate a random 64-bit integer for the serial number
    uint64_t serial_number = 0;
    if (!RAND_bytes((unsigned char*)&serial_number, sizeof(serial_number)))
    {
        cerr << "RAND_bytes failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    // Convert the random number to ASN1_INTEGER
    if (!ASN1_INTEGER_set_uint64(serial, serial_number))
    {
        cerr << "ASN1_INTEGER_set_uint64 failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    return serial;
}

int ServerNameCallback(SSL* ssl, int* ad, LPPER_IO_DATA ioData)
{
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername)
    {
        if (verbose)
        {
            cout << "[=]SNI: " << servername << endl;
        }
        ioData->hostname = servername;

        // Generate key for new certificate
        ioData->pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        EVP_PKEY_assign_RSA(ioData->pkey, rsa);

        // Generate new certificate
        /*X509* cert = generate_certificate(servername, pkey, caCert, caKey);*/
        ioData->clientCert = create_certificate(caCert, caKey, ioData->pkey, ioData->targetCert, ioData->hostname);

        // Assign new certificate and private key to SSL context
        SSL_use_certificate(ssl, ioData->clientCert);
        SSL_use_PrivateKey(ssl, ioData->pkey);

    }
    else
    {
        cerr << "[-]No SNI" << endl;
    }
    return SSL_TLSEXT_ERR_OK;
}

vector<string> get_sans(X509* cert)
{
    vector<string> sans;
    STACK_OF(GENERAL_NAME)* names = NULL;

    names = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names == NULL)
    {
        return sans;
    }

    int num_names = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < num_names; i++)
    {
        GENERAL_NAME* gen_name = sk_GENERAL_NAME_value(names, i);
        if (gen_name->type == GEN_DNS)
        {
            char* dns_name = (char*)ASN1_STRING_get0_data(gen_name->d.dNSName);
            sans.push_back(string(dns_name));
        }
    }
    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    return sans;
}

string get_cn(X509* cert) {
    X509_NAME* subj = X509_get_subject_name(cert);
    char cn[256];
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
    return string(cn);
}

X509* create_certificate(X509* ca_cert, EVP_PKEY* ca_pkey, EVP_PKEY* pkey, X509* target_cert, string hostname)
{
    X509* cert = X509_new();
    if (!cert)
    {
        cerr << "X509_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    X509_set_version(cert, 2);

    ASN1_INTEGER* serial = generate_serial();
    X509_set_serialNumber(cert, serial);
    if (verbose)
    {
        cout << "[+]Serial assigned" << endl;
    }
    ASN1_INTEGER_free(serial);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);  // 1 year validity

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Proxy", -1, -1, 0);

    // Extract CN and SANs from target certificate
    string cn = get_cn(target_cert);
    vector<string> sans = get_sans(target_cert);

    // Set CN
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)hostname.c_str(), -1, -1, 0);
    //X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add SANs
    if (!sans.empty())
    {
        STACK_OF(GENERAL_NAME)* san_list = sk_GENERAL_NAME_new_null();
        for (const string& san : sans)
        {
            GENERAL_NAME* gen_name = GENERAL_NAME_new();
            ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
            ASN1_STRING_set(ia5, san.c_str(), san.size());
            gen_name->d.dNSName = ia5;
            gen_name->type = GEN_DNS;
            sk_GENERAL_NAME_push(san_list, gen_name);
        }

        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, san_list);
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
    }

    if (!X509_sign(cert, ca_pkey, EVP_sha256()))
    {
        cerr << "[-]Error signing certificate" << endl;
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        exit(EXIT_FAILURE);
    }

    return cert;
}