#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/applink.c>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable : 4996)

#define BUFFER_SIZE 4096
#define PORT        8080

bool verbose = true;
static int ID = 0;

typedef enum MODE 
{
    CLIENT,
    SERVER,
};

typedef enum _IO_OPERATION 
{
    CLIENT_ACCEPT,
    HTTP_S_RECV,
    HTTP_S_SEND,
    HTTP_C_RECV,
    HTTP_C_SEND,
    CLIENT_IO,
    SERVER_IO,
    IO,
    SSL_SERVER_IO,
    SSL_CLIENT_IO,
} IO_OPERATION, * PERIO_OPERATIONS;

typedef struct _PER_IO_DATA 
{
    WSAOVERLAPPED overlapped;
    DWORD key = ++ID;
    SOCKET clientSocket, serverSocket;
    WSABUF wsaClientSendBuf, wsaClientRecvBuf, wsaServerSendBuf, wsaServerRecvBuf;
    char cSendBuffer[BUFFER_SIZE], cRecvBuffer[BUFFER_SIZE], sSendBuffer[BUFFER_SIZE], sRecvBuffer[BUFFER_SIZE];
    DWORD bytesSend, bytesRecv;
    IO_OPERATION ioOperation;
    SSL* clientSSL, * targetSSL;
    X509* clientCert, * targetCert;
    SSL_CTX* clientCTX;
    string hostname;
    EVP_PKEY* pkey;
    BIO* srBio, * swBio, * crBio, * cwBio;
    BOOL bioCFlag = FALSE, bioSFlag = FALSE;
    BOOL clientRecvFlag = FALSE, serverRecvFlag = FALSE;
} PER_IO_DATA, * LPPER_IO_DATA;

HANDLE ProxyCompletionPort;
X509* caCert;
EVP_PKEY* caKey;

void initializeWinsock();
void initializeOpenSSL();
SOCKET createSocket(int port);
LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation);
EVP_PKEY* generatePrivateKey();
vector<string> get_sans(X509* cert);
string get_cn(X509* cert);
void SSL_CTX_keylog_callback_func(const SSL* ssl, const char* line);
X509* create_certificate(X509* ca_cert, EVP_PKEY* ca_pkey, EVP_PKEY* pkey, X509* target_cert, string hostname);
void configureContext(SSL_CTX* ctx, X509* cert, EVP_PKEY* pkey);
BOOL IOUtil(LPPER_IO_DATA ioData, MODE mode, int bytesTransferred);
BOOL BioUtil(LPPER_IO_DATA ioData, MODE mode);
string toHex(const char* data, size_t length);
static DWORD WINAPI WorkerThread(LPVOID lparameter);
void cleanupSSL();

int main()
{
    initializeWinsock();
    initializeOpenSSL();

    FILE* ca_cert_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.crt", "r");
    if (!ca_cert_file)
    {
        cerr << "[-]Error opening CA certificate file" << endl;
        exit(EXIT_FAILURE);
    }

    caCert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if (!caCert)
    {
        cerr << "[-]Error reading CA certificate" << endl;
        exit(EXIT_FAILURE);
    }

    FILE* ca_pkey_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.key", "r");
    if (!ca_pkey_file)
    {
        cerr << "[-]Error opening CA private key file" << endl;
        exit(EXIT_FAILURE);
    }

    caKey = PEM_read_PrivateKey(ca_pkey_file, NULL, NULL, NULL);
    fclose(ca_pkey_file);
    if (!caKey)
    {
        cerr << "[-]Error reading CA private key" << endl;
        exit(EXIT_FAILURE);
    }

    ProxyCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!ProxyCompletionPort)
    {
        cerr << "[-]Cannot create ProxyCompletionPort" << endl;
        WSACleanup();
        return 1;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++)
    {
        HANDLE pThread = CreateThread(NULL, 0, WorkerThread, ProxyCompletionPort, 0, NULL);
        if (pThread == NULL)
        {
            cerr << "[-]Failed to create worker thread" << endl;
            WSACleanup();
            return 1;
        }
        CloseHandle(pThread);
    }

    SOCKET proxySocket = createSocket(PORT);

    while (TRUE)
    {
        //cout << "[+]WSAAccept()" << endl;
        SOCKET clientSocket = WSAAccept(proxySocket, NULL, NULL, NULL, 0);
        if (clientSocket == INVALID_SOCKET)
        {
            cerr << "[-]WSAAccept failed - " << WSAGetLastError() << endl;
            continue;
        }
        else if (verbose)
        {
            cout << "[+]client accepted" << endl;
        }

        LPPER_IO_DATA clientData = UpdateIoCompletionPort(clientSocket, INVALID_SOCKET, CLIENT_ACCEPT);
        if (!clientData)
        {
            cerr << "[-]UpdateIoCompletionPort failed" << endl;
            closesocket(clientSocket);
            continue;
        }

        DWORD flags = 0;
        if (WSARecv(clientData->clientSocket, &clientData->wsaClientRecvBuf, 1, &clientData->bytesRecv, &flags, &clientData->overlapped, NULL) == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            if (error != WSA_IO_PENDING)
            {
                cerr << "[-]WSARecv failed - " << error << endl;
                closesocket(clientData->clientSocket);
                delete clientData;
                continue;
            }
        }
        else
        {
            cout << "[+]From client - " << clientData->bytesRecv << " bytes." << endl;
            clientData->bytesRecv = 0;
        }

    }

    closesocket(proxySocket);
    cleanupSSL();
    WSACleanup();

    return 0;
}

void initializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        cerr << "[-]WSAStartup failed - " << result << endl;
        exit(EXIT_FAILURE);
    }
    else if (verbose)
    {
        cout << "[+]Winsock initialized" << endl;
    }
}

void initializeOpenSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();
    if (verbose)
    {
        cout << "[+]OpenSSL initialized" << endl;
    }
}

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

SOCKET createSocket(int port)
{
    SOCKET socket;
    SOCKADDR_IN sockAddr;

    socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
    {
        cerr << "[-]WSASocket failed" << endl;
        exit(EXIT_FAILURE);
    }

    ZeroMemory(&sockAddr, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(port);
    sockAddr.sin_addr.s_addr = INADDR_ANY;

    int opt = 0;
    int size = sizeof(int);

    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, size) != SOCKET_ERROR)
    {
        //cout << "[+]setsockopt()" << endl;
    }

    if (bind(socket, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) != 0)
    {
        cerr << "[-]Unable to bind" << endl;
        closesocket(socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if (listen(socket, SOMAXCONN) != 0)
    {
        cerr << "[-]Unable to listen: " << WSAGetLastError() << endl;
        closesocket(socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    else if (verbose)
    {
        cout << "[+]Listening on port " << port << "..." << endl;
    }

    return socket;
}

LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation)
{
    LPPER_IO_DATA ioData = new PER_IO_DATA;

    memset(&ioData->overlapped, '\0', sizeof(WSAOVERLAPPED));
    ioData->clientSocket = socket;
    ioData->serverSocket = peerSocket;
    ioData->bytesRecv = 0;
    ioData->bytesSend = 0;
    ioData->ioOperation = ioOperation;

    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
    memset(ioData->cSendBuffer, '\0', BUFFER_SIZE);
    memset(ioData->sSendBuffer, '\0', BUFFER_SIZE);

    ioData->wsaClientRecvBuf.buf = ioData->cRecvBuffer;
    ioData->wsaClientRecvBuf.len = sizeof(ioData->cRecvBuffer);
    ioData->wsaClientSendBuf.buf = ioData->cSendBuffer;
    ioData->wsaClientSendBuf.len = sizeof(ioData->cSendBuffer);
    ioData->wsaServerRecvBuf.buf = ioData->sRecvBuffer;
    ioData->wsaServerRecvBuf.len = sizeof(ioData->sRecvBuffer);
    ioData->wsaServerSendBuf.buf = ioData->sSendBuffer;
    ioData->wsaServerSendBuf.len = sizeof(ioData->sSendBuffer);

    ioData->targetSSL = NULL;
    ioData->clientSSL = NULL;
    ioData->clientCert = NULL;
    ioData->targetCert = NULL;
    ioData->clientCTX = NULL;
    ioData->pkey = NULL;

    ioData->crBio = NULL;
    ioData->cwBio = NULL;
    ioData->srBio = NULL;
    ioData->swBio = NULL;

    if (CreateIoCompletionPort((HANDLE)socket, ProxyCompletionPort, (ULONG_PTR)ioData, 0) == NULL)
    {
        delete ioData;
        return NULL;
    }

    return ioData;
}

SOCKET connectToTarget(const string& hostname, int port)
{
    SOCKET sock;
    struct addrinfo hints, * res, * p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), port_str, &hints, &res) != 0)
    {
        cerr << "getaddrinfo" << endl;
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
        {
            cerr << "[-]Invalid socket" << endl;
            continue;
        }

        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR)
        {
            closesocket(sock);
            continue;
        }
        cout << "[+]Connected to target server: " << hostname << " on port - " << port_str << endl;

        break;
    }

    if (p == NULL)
    {
        cerr << "[-]Unable to connect to target server: " << hostname << endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    return sock;
}

bool parseConnectRequest(const string& request, string& hostname, int& port)
{
    size_t pos = request.find("CONNECT ");
    if (pos == string::npos)
        return false;
    pos += 8;
    size_t end = request.find(" ", pos);
    if (end == string::npos)
        return false;

    string hostport = request.substr(pos, end - pos);
    pos = hostport.find(":");
    if (pos == string::npos)
        return false;

    hostname = hostport.substr(0, pos);
    port = stoi(hostport.substr(pos + 1));
    return true;
}

string extractHost(const string& request)
{
    size_t pos = request.find("Host: ");
    if (pos == string::npos)
        return "";
    pos += 6;
    size_t end = request.find("\r\n", pos);
    return request.substr(pos, end - pos);
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

X509* generate_certificate(const char* server_name, EVP_PKEY* pkey, X509* ca_cert, EVP_PKEY* ca_pkey)
{
    X509* x509 = X509_new();
    if (!x509)
    {
        cerr << "Unable to create new X509 object" << endl;
        return nullptr;
    }

    // Set version to X509v3
    X509_set_version(x509, 2);

    // Set serial number
    ASN1_INTEGER* serial = generate_serial();
    X509_set_serialNumber(x509, serial);
    ASN1_INTEGER_free(serial);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year

    // Set public key
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"State", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)"City", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Organization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)server_name, -1, -1, 0);
    X509_set_issuer_name(x509, X509_get_subject_name(ca_cert));

    // Sign the certificate with the CA private key
    if (!X509_sign(x509, ca_pkey, EVP_sha256()))
    {
        cerr << "Unable to sign certificate" << endl;
        X509_free(x509);
        return nullptr;
    }

    if (verbose)
    {
        cout << "[+]Created certificate for proxy" << endl;
    }

    return x509;
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

void SSL_CTX_keylog_callback_func(const SSL* ssl, const char* line)
{
    FILE* fp;
    fp = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Wireshark Example\\key_logs\\key_log.log", "a");

    if (fp != NULL)
    {
        fprintf(fp, "%s\n", line);
        fclose(fp);
    }
    else
    {
        cout << "Failed to create log" << endl;
    }
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

void myInfoCallback(const SSL* ssl, int type, int ret) {
    switch (type) {
    case SSL_CB_HANDSHAKE_START:
        cout << "[=]Handshake started" << endl;
        break;
    case SSL_CB_HANDSHAKE_DONE:
        cout << "[=]Handshake completed" << endl;
        break;
    case SSL_CB_LOOP:
        cout << "[=]change inside loop" << endl;
        break;
    case SSL_CB_EXIT:
        cout << "[=]Exit out of handshake" << endl;
        break;
    case SSL_CB_ALERT:
        cout << "[=]Alert in handshake" << endl;
        break;
    default:
        //cout << "[=]Info callback - " << type << endl;
        break;
    }
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
    vector<string> sans = get_sans(target_cert);

    // Set CN
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)hostname.c_str(), -1, -1, 0);
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

string toHex (const char* data, size_t length)
{
    ostringstream oss;
    
    for (size_t i = 0; i < length; i+=16)
    {
        oss << setw(4) << setfill('0') << hex << i << " ";

        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < length)
            {
                oss << setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(data[i + j])) << " ";
            }
            else 
            {
                oss << "   ";
            }
        }

        oss << "\n";
    }

    return oss.str();
}

static DWORD WINAPI WorkerThread(LPVOID workerThreadContext)
{
    HANDLE completionPort = (HANDLE)workerThreadContext;
    LPPER_IO_DATA socketData = NULL;
    LPWSAOVERLAPPED overlapped = NULL;
    DWORD flags = 0;
    DWORD bytesTransferred = 0;

    while (TRUE)
    {
        BOOL result = GetQueuedCompletionStatus(completionPort, &bytesTransferred, (PDWORD_PTR)&socketData, (LPOVERLAPPED*)&overlapped, INFINITE);
        LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;

        if (!result)
        {
            cerr << "[-]GetQueuedCompletionStatus failed - " << GetLastError() << endl;
            return 0;
        }

        if (bytesTransferred == 0)
        {
            cerr << "[-]Connection closed" << endl;
            if (ioData)
            {
                closesocket(ioData->clientSocket);
                ioData->serverSocket = INVALID_SOCKET;
                delete ioData;
            }
            break;
        }

        switch (ioData->ioOperation)
        {

        case CLIENT_ACCEPT: {

            ioData->bytesRecv = bytesTransferred;

            int port = 0;
            string request(ioData->cRecvBuffer, ioData->bytesRecv);
            cout << request << endl;

            if (strncmp(ioData->cRecvBuffer, "CONNECT", 7) == 0)
            {
                ioData->ioOperation = SSL_SERVER_IO;
                string hostname;

                if (!parseConnectRequest(request, hostname, port))
                {
                    cerr << "[-]Invalid CONNECT request" << endl;
                    closesocket(ioData->clientSocket);
                    delete ioData;
                    break;
                }

                if (!hostname.empty())
                {
                    ioData->hostname = hostname;
                    ioData->serverSocket = connectToTarget(hostname, port);

                    if (ioData->serverSocket != INVALID_SOCKET)
                    {
                        if (CreateIoCompletionPort((HANDLE)ioData->serverSocket, ProxyCompletionPort, NULL, 0) == NULL)
                        {
                            cerr << "[-]CreateIoCompletionPort for server failed" << endl;
                            closesocket(ioData->serverSocket);
                            closesocket(ioData->clientSocket);
                            delete ioData;
                            break;
                        }
                        else if (verbose)
                        {
                            cout << "[+]Updated Io completion port" << endl;
                        }
                    }

                    ioData->crBio = BIO_new(BIO_s_mem());
                    ioData->cwBio = BIO_new(BIO_s_mem());
                    ioData->srBio = BIO_new(BIO_s_mem());
                    ioData->swBio = BIO_new(BIO_s_mem());
                    if (!ioData->crBio || !ioData->cwBio || !ioData->srBio || !ioData->swBio)
                    {
                        cout << "[-]BIO_new failed" << endl;
                        break;
                    }
                    else
                    {
                        // set the memory BIOs to non-blocking mode
                        BIO_set_nbio(ioData->crBio, 1);
                        BIO_set_nbio(ioData->cwBio, 1);
                        BIO_set_nbio(ioData->srBio, 1);
                        BIO_set_nbio(ioData->swBio, 1);
                    }

                    SSL_CTX* targetCTX = SSL_CTX_new(TLS_client_method());
                    ioData->targetSSL = SSL_new(targetCTX);
                    SSL_set_connect_state(ioData->targetSSL); // to act as CLIENT
                    SSL_CTX_set_verify(targetCTX, SSL_VERIFY_PEER, NULL);
                    SSL_set_bio(ioData->targetSSL, ioData->srBio, ioData->swBio);

                    char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    memcpy(ioData->wsaClientSendBuf.buf, response, sizeof(response));
                    ioData->wsaClientSendBuf.len = sizeof(response);
                    if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        if (error != WSA_IO_PENDING)
                        {
                            cerr << "[-]Failed to send response - " << error << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->targetSSL);
                            delete ioData;
                            break;
                        }
                    }
                    else
                    {
                        cout << "[+]Connection established with client. ID - " << ioData->key << endl;
                    }
                }
            }
            else
            {
                ioData->hostname = extractHost(request);
                if (sizeof(ioData->hostname) > 0)
                {
                    ioData->ioOperation = HTTP_S_RECV;
                    ioData->serverSocket = connectToTarget(ioData->hostname, 80);
                    if (ioData->serverSocket != INVALID_SOCKET)
                    {
                        if (CreateIoCompletionPort((HANDLE)ioData->serverSocket, ProxyCompletionPort, NULL, 0) == NULL)
                        {
                            cerr << "[-]CreateIoCompletionPort for server failed" << endl;
                            closesocket(ioData->serverSocket);
                            closesocket(ioData->clientSocket);
                            delete ioData;
                            break;
                        }
                        else if (verbose)
                        {
                            cout << "[+]Updated Io completion port" << endl;
                        }
                    }

                    memcpy(ioData->sSendBuffer, ioData->cRecvBuffer, bytesTransferred);
                    ioData->wsaServerSendBuf.len = bytesTransferred;

                    if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        if (error != WSA_IO_PENDING)
                        {
                            cerr << "[-]Failed to send response - " << error << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->targetSSL);
                            delete ioData;
                            break;
                        }
                    }
                    else
                    {
                        cout << "[+]WSASend() server - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
                    }
                }
            }

            break;
        }

        case HTTP_S_RECV: {

            ioData->ioOperation = HTTP_C_SEND;

            if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                //cout << "[-]WSARecv - " << error << endl;
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]Failed to send response - " << error << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->targetSSL);
                    delete ioData;
                    continue;
                }
            }
            else
            {
                cout << "[+]WSARecv() HTTP_S_RECV - " << ioData->bytesRecv << " bytes." << endl;
                //cout << ioData->sRecvBuffer << endl;
            }

            break;
        }

        case HTTP_C_SEND: {

            ioData->ioOperation = CLIENT_ACCEPT;

            memcpy(ioData->cSendBuffer, ioData->sRecvBuffer, bytesTransferred);
            ioData->wsaClientSendBuf.len = bytesTransferred;

            if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]Failed to send response - " << error << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->targetSSL);
                    delete ioData;
                    continue;
                }
            }
            else
            {
                cout << "[+]WSASend() HTTP_C_SEND - " << ioData->bytesSend << " bytes." << endl;
                //cout << ioData->cSendBuffer << endl;
            }

            break;
        }

        case HTTP_C_RECV: {

            ioData->ioOperation = CLIENT_ACCEPT;

            if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]Failed to send response - " << error << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->targetSSL);
                    delete ioData;
                    continue;
                }
            }
            else
            {
                cout << "[+]WSARecv() HTTP_C_RECV - " << ioData->bytesRecv << " bytes." << endl;
                //cout << ioData->cRecvBuffer << endl;
            }

            break;
        }

        case SSL_SERVER_IO: {

            if (ioData->sRecvBuffer[0])
            {

                int bio_write = BIO_write(ioData->srBio, ioData->sRecvBuffer, bytesTransferred);
                if (bio_write > 0)
                {
                    cout << "[+]BIO_write() server - " << bio_write << " bytes. ID - " << ioData->key << endl;
                }
                memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
            }

            // SSL handshake with server 
            if (!SSL_is_init_finished(ioData->targetSSL))
            {
                char Buf[BUFFER_SIZE] = {};
                int bio_read = 0, ret_server, status;

                ret_server = SSL_do_handshake(ioData->targetSSL);

                if (ret_server == 1)
                {
                    if (verbose)
                    {
                        cout << "[+]SSL handshake with server done" << endl;
                    }

                    // SSL handshake with client
                    ioData->ioOperation = SSL_CLIENT_IO;

                    // Extract certificate of Server
                    ioData->targetCert = SSL_get_peer_certificate(ioData->targetSSL);
                    if (!ioData->targetCert)
                    {
                        cout << "[-]Cert of server not extracted" << endl;
                        SSL_shutdown(ioData->targetSSL);
                        SSL_free(ioData->targetSSL);
                    }

                    ioData->clientCTX = SSL_CTX_new(TLS_server_method());
                    SSL_CTX_set_tlsext_servername_callback(ioData->clientCTX, ServerNameCallback);
                    SSL_CTX_set_tlsext_servername_arg(ioData->clientCTX, ioData);
                    SSL_CTX_set_info_callback(ioData->clientCTX, myInfoCallback);
                    SSL_CTX_set_keylog_callback(ioData->clientCTX, SSL_CTX_keylog_callback_func);
                    if (!ioData->clientCTX)
                    {
                        cerr << "[-]Failed to create client SSL CTX" << endl;
                    }

                    ioData->clientSSL = SSL_new(ioData->clientCTX);
                    SSL_set_accept_state(ioData->clientSSL); // to act as SERVER 
                    SSL_set_bio(ioData->clientSSL, ioData->crBio, ioData->cwBio);

                    if (!SSL_is_init_finished(ioData->clientSSL))
                    {
                        int ret_client = SSL_do_handshake(ioData->clientSSL);

                        if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            DWORD error = WSAGetLastError();
                            if (error != WSA_IO_PENDING)
                            {
                                cout << "[-]WSARecv() failed - " << error << endl;
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                SSL_free(ioData->clientSSL);
                                SSL_free(ioData->targetSSL);
                                SSL_CTX_free(ioData->clientCTX);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            cout << "[+]WSARecv() client - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                        }

                    }

                    break;
                }

                status = SSL_get_error(ioData->targetSSL, ret_server);

                cout << "[=]SSL_get_error() - " << status << " ID - " << ioData->key << endl;

                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
                {
                    bio_read = BIO_read(ioData->swBio, Buf, BUFFER_SIZE);

                    if (bio_read > 0)
                    {
                        if (verbose)
                        {
                            cout << "[+]BIO_read() server - " << bio_read << " bytes. ID - " << ioData->key << endl;
                        }

                        memcpy(ioData->wsaServerSendBuf.buf, Buf, bio_read);
                        ioData->wsaServerSendBuf.len = bio_read;

                        if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            //cout << "[-]WSASend error - " << error << endl;
                            if (error != WSA_IO_PENDING)
                            {
                                cerr << "[-]WSASend error - " << error << endl;
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                SSL_free(ioData->targetSSL);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            cout << "[+]WSASend() server - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
                        }
                    }
                    else
                    {
                        ioData->bytesRecv = 0;
                        ioData->wsaServerRecvBuf.len = BUFFER_SIZE;

                        if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            //cout << "[-]WSARecv error - " << error << endl;
                            if (error != WSA_IO_PENDING)
                            {
                                cerr << "[-]WSARecv error - " << error << endl;
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                SSL_free(ioData->targetSSL);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            cout << "[+]WSARecv() server - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                        }
                    }

                }
                else if (status == SSL_ERROR_SSL)
                {
                    cout << "[-]SSL_get_error() - " << ERR_error_string(ERR_get_error(), NULL) << endl;
                }
                else
                {
                    cout << "[-]SSL_get_error() - " << status << endl;
                }

            }
            else if (verbose)
            {
                cout << "[+]SSL handshake with server done - 2" << endl;
            }

            break;
        }

        case SSL_CLIENT_IO: {

            // SSL handshake with client
            if (ioData->cRecvBuffer[0])
            {
                int bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);
                if (bio_write > 0 && verbose) {
                    cout << "[+]BIO_write() client - " << bio_write << " bytes. ID - " << ioData->key << endl;
                }
                else
                {
                    cout << "[-]BIO_write() client" << endl;
                }
                memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
            }

            if (!SSL_is_init_finished(ioData->clientSSL))
            {
                char Buf[BUFFER_SIZE] = {};
                int bio_read = 0, ret_client, status;

                ret_client = SSL_do_handshake(ioData->clientSSL);

                if (ret_client == 1) {
                    /*if (verbose)
                    {
                        cout << "[+]SSL handshake with client done" << endl;
                    }*/

                    ioData->ioOperation = IO;
                    ioData->clientRecvFlag = TRUE;

                    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                    if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        if (WSAGetLastError() != WSA_IO_PENDING)
                        {
                            cerr << "[-]WSARecv() failed" << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->clientSSL);
                            SSL_free(ioData->targetSSL);
                            SSL_CTX_free(ioData->clientCTX);
                            delete ioData;
                            break;
                        }
                    }
                    else
                    {
                        cout << "[+]WSARecv() client - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                    }

                    break;
                }

                status = SSL_get_error(ioData->clientSSL, ret_client);

                cout << "[=]SSL_get_error() - " << status << " ID - " << ioData->key << endl;

                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
                {
                    bio_read = BIO_read(ioData->cwBio, Buf, BUFFER_SIZE);

                    if (bio_read > 0)
                    {
                        if (verbose)
                        {
                            cout << "[+]BIO_read() client - " << bio_read << " bytes. ID - " << ioData->key << endl;
                        }

                        memcpy(ioData->wsaClientSendBuf.buf, Buf, bio_read);
                        ioData->wsaClientSendBuf.len = bio_read;

                        if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            //cout << "[-]WSASend() error - " << error << endl;
                            if (error != WSA_IO_PENDING)
                            {
                                cerr << "[-]WSASend() error - " << error << endl;
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                SSL_free(ioData->clientSSL);
                                SSL_free(ioData->targetSSL);
                                SSL_CTX_free(ioData->clientCTX);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            cout << "[+]WSASend() client - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
                        }
                    }
                    else
                    {

                        ioData->bytesRecv = 0;
                        ioData->wsaClientRecvBuf.len = BUFFER_SIZE;

                        if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            //cout << "[-]WSARecv() error - " << error << endl;
                            if (error != WSA_IO_PENDING)
                            {
                                cerr << "[-]WSARecv() error - " << error << endl;
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                SSL_free(ioData->clientSSL);
                                SSL_free(ioData->targetSSL);
                                SSL_CTX_free(ioData->clientCTX);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            cout << "[+]WSARecv() client - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                        }

                    }

                }
                else if (status == SSL_ERROR_SSL)
                {
                    cout << "[-]SSL_get_error() - " << ERR_error_string(ERR_get_error(), NULL) << endl;
                }
                else
                {
                    cout << "[-]SSL_get_error() - " << status << endl;
                }

            }
            else
            {
                cout << "[+]SSL handshake with client done - 2" << endl;
            }

            break;
        }

        case IO: {

            int bioRead = 0, bioWrite = 0, sslRead = 0, sslWrite = 0;

            if (strlen(ioData->cRecvBuffer) > 0 && !ioData->bioCFlag)
            {
                if (!IOUtil(ioData, CLIENT, bytesTransferred))
                    break;
            }

            else if (strlen(ioData->sRecvBuffer) > 0 && !ioData->bioSFlag)
            {
                if (!IOUtil(ioData, SERVER, bytesTransferred))
                    break;
            }

            if (ioData->bioCFlag)
            {
                if (!BioUtil(ioData, CLIENT))
                    break;
            }

            if (ioData->bioSFlag)
            {
                if (!BioUtil(ioData, SERVER))
                    break;
            }

            if (strlen(ioData->cRecvBuffer) == 0 && !ioData->bioCFlag && !ioData->clientRecvFlag)
            {
                ioData->bioCFlag = FALSE;
                ioData->clientRecvFlag = TRUE;
                memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    cout << "[-]WSARecv() client IO (out) - " << error << " ID - " << ioData->key << endl;
                    if (error != WSA_IO_PENDING)
                    {
                        cerr << "[-]WSARecv() client IO (out) - " << error << " ID - " << ioData->key << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        delete ioData;
                        break;
                    }
                }
                else
                {
                    cout << "[+]WSARecv() client IO (out) - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                }
                
                break;
            }

            if (strlen(ioData->sRecvBuffer) == 0 && !ioData->bioSFlag && !ioData->serverRecvFlag)
            {
                ioData->bioSFlag = FALSE;
                ioData->serverRecvFlag = TRUE;
                memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

                if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    cout << "[-]WSARecv() server IO (out) - " << error << " ID - " << ioData->key << endl;
                    if (error != WSA_IO_PENDING)
                    {
                        cerr << "[-]WSARecv() server IO (out) - " << error << " ID - " << ioData->key << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        delete ioData;
                        break;
                    }
                }
                else
                {
                    cout << "[+]WSARecv() server IO (out) - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                }
                
                break;
            }

            break;
        }

        default:
            break;

        }

    }

    return 0;
}

BOOL IOUtil(LPPER_IO_DATA ioData, MODE mode, int bytesTransferred) 
{
    int bioWrite = 0, bioRead = 0, sslWrite = 0, sslRead = 0, error, ret;
    DWORD flags = 0;

    if (mode == CLIENT)
    {
        //cout << "[+]Bytestransferred client - " << bytesTransferred << " ID - " << ioData->key << endl;
        bioWrite = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);

        if (bioWrite > 0)
        {
            ioData->clientRecvFlag = FALSE;
            
            //cout << "[+]BIO_write() client - " << bioWrite << " bytes. ID - " << ioData->key << endl << toHex(ioData->cRecvBuffer, bioWrite) << endl;
            memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

            sslRead = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE);
            
            if (sslRead <= 0)
            {
                error = SSL_get_error(ioData->clientSSL, sslRead);
                cout << "[=]SSL_read error - " << error << " ID - " << ioData->key << endl;

                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                {
                    ioData->bytesRecv = 0;
                    ioData->clientRecvFlag = TRUE;
                    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE); 

                    if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        cout << "[-]WSARecv() client IO - " << error << " ID - " << ioData->key << endl;
                        if (error != WSA_IO_PENDING)
                        { 
                            cerr << "[-]WSARecv() client IO - " << error << " ID - " << ioData->key  << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->clientSSL);
                            SSL_free(ioData->targetSSL);
                            SSL_CTX_free(ioData->clientCTX);
                            delete ioData;
                            return FALSE;
                        }
                    }
                    else
                    {
                        cout << "[+]WSARecv() client IO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                    }
                    return FALSE;
                }
                else if (error == SSL_ERROR_SSL)
                {
                    cout << "[-]SSL_get_error() CLIENT_IO - " << ERR_error_string(ERR_get_error(), NULL) << " ID - " << ioData->key << endl;
                    return FALSE;
                }
                else
                {
                    cout << "[+]SSL_get_error() - " << error << endl;
                    return FALSE;
                }
            }
            else
            {
                if (verbose)
                {
                    cout << "[+]SSL_read() client - " << sslRead << " bytes. ID - " << ioData->key << endl;
                }
                cout << ioData->cRecvBuffer << endl;
                sslWrite = SSL_write(ioData->targetSSL, ioData->cRecvBuffer, sslRead);
                if (sslWrite > 0)
                {
                    if (verbose)
                    {
                        cout << "[+]SSL_write() server - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                    }
                    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
                }
                else
                {
                    ret = SSL_get_error(ioData->targetSSL, sslWrite);
                    cout << "[-]SSL_write() - " << ret << endl;
                }
                while ((sslRead = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE)) > 0)
                {
                    if (verbose)
                    {
                        cout << "[+]SSL_read() client - " << sslRead << " bytes. ID - " << ioData->key << endl;
                    }
                    cout << ioData->cRecvBuffer << endl;
                    sslWrite = SSL_write(ioData->targetSSL, ioData->cRecvBuffer, sslRead);
                    if (sslWrite > 0)
                    {
                        if (verbose)
                        {
                            cout << "[+]SSL_write() - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                        }
                        memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
                    }
                    else
                    {
                        ret = SSL_get_error(ioData->targetSSL, sslWrite);
                        cout << "[-]SSL_write() server - " << ret << endl;
                    }
                }
                ioData->bioCFlag = TRUE;
                return TRUE;
            }
        }
        else
        {
            cout << "[-]BIO_write() client failed" << endl;
        }
    }
    else if (mode == SERVER)
    {
        //cout << "[+]Bytestransferred server - " << bytesTransferred << " ID - " << ioData->key << endl;
        bioWrite = BIO_write(ioData->srBio, ioData->sRecvBuffer, bytesTransferred);
        if (bioWrite > 0)
        {
            ioData->serverRecvFlag = FALSE;
            
            //cout << "[+]BIO_write() server - " << bioWrite << " bytes. ID - " << ioData->key << endl << toHex(ioData->sRecvBuffer, bioWrite) << endl;
            memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

            sslRead = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE);

            if (sslRead <= 0)
            {
                error = SSL_get_error(ioData->targetSSL, sslRead);
                cout << "[=]SSL_read error - " << error << " ID - " << ioData->key << endl;

                if ((error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE))
                {
                    ioData->bytesRecv = 0;
                    ioData->serverRecvFlag = TRUE;
                    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

                    if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        cout << "[-]WSARecv() server IO - " << error << " ID - " << ioData->key << endl;
                        if (error != WSA_IO_PENDING)
                        {
                            cerr << "[-]WSARecv() server IO - " << error << " ID - " << ioData->key << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->clientSSL);
                            SSL_free(ioData->targetSSL);
                            SSL_CTX_free(ioData->clientCTX);
                            delete ioData;
                            return FALSE;
                        }
                    }
                    else
                    {
                        cout << "[+]WSARecv() server IO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                    }
                    return FALSE;
                }
                else if (error == SSL_ERROR_SSL)
                {
                    cout << "[-]SSL_get_error() SERVER_IO - " << ERR_error_string(ERR_get_error(), NULL) << " ID - " << ioData->key << endl;
                    return FALSE;
                }
                else
                {
                    cout << "[+]SSL_get_error() - " << error << endl;
                    return FALSE;
                }
            }
            else
            {
                if (verbose)
                {
                    cout << "[+]SSL_read() server - " << sslRead << " bytes. ID - " << ioData->key << endl;
                }
                cout << ioData->sRecvBuffer << endl;
                sslWrite = SSL_write(ioData->clientSSL, ioData->sRecvBuffer, sslRead);
                if (sslWrite > 0)
                {
                    if (verbose)
                    {
                        cout << "[+]SSL_write() client - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                    }
                    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
                }
                else
                {
                    error = SSL_get_error(ioData->clientSSL, sslWrite);
                    cout << "[-]SSL_write() - " << error << endl;
                }
                while ((sslRead = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE)) > 0)
                {
                    if (verbose)
                    {
                        cout << "[+]SSL_read() server - " << sslRead << " bytes. ID - " << ioData->key << endl;
                    }
                    cout << ioData->sRecvBuffer << endl;
                    sslWrite = SSL_write(ioData->clientSSL, ioData->sRecvBuffer, sslRead);
                    if (sslWrite > 0)
                    {
                        if (verbose)
                        {
                            cout << "[+]SSL_write() client - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                        }
                        memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
                    }
                    else
                    {
                        error = SSL_get_error(ioData->clientSSL, sslWrite);
                        cout << "[-]SSL_write() - " << error << endl;
                    }
                }
                ioData->bioSFlag = TRUE;
                return TRUE;
            }
        }
        else
        {
            cout << "[-]BIO_write() server failed" << endl;
        }
    }
    return TRUE;
}

BOOL BioUtil(LPPER_IO_DATA ioData, MODE mode)
{
    int bioRead = 0, bioWrite = 0, sslRead = 0, sslWrite = 0, error;
    DWORD flags = 0;

    if (mode == CLIENT)
    {
        memset(ioData->sSendBuffer, '\0', BUFFER_SIZE);
        bioRead = BIO_read(ioData->swBio, ioData->sSendBuffer, BUFFER_SIZE);
        if (bioRead > 0)
        {
            if (verbose)
            {
                cout << "[+]BIO_read() server - " << bioRead << " bytes. ID - " << ioData->key << endl;
            }
            ioData->wsaServerSendBuf.len = bioRead;

            if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                error = WSAGetLastError();
                cout << "[-]WSASend() error - " << error << " ID - " << ioData->key << endl;
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]WSASend() failed - " << error << " ID - " << ioData->key << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->clientSSL);
                    SSL_free(ioData->targetSSL);
                    SSL_CTX_free(ioData->clientCTX);
                    delete ioData;
                    return FALSE;
                }
            }
            else
            {
                cout << "[+]WSASend() server - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
            }
            return FALSE;
        }
        else if (ioData->serverRecvFlag)
        {
            ioData->bioCFlag = FALSE;
            return FALSE;
        }
        else
        {
            ioData->bioCFlag = FALSE;
            ioData->serverRecvFlag = TRUE;
            memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

            if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                error = WSAGetLastError();
                cout << "[-]WSARecv() server BIO - " << error << " ID - " << ioData->key << endl;
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]WSARecv() server BIO - " << error << " ID - " << ioData->key << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->clientSSL);
                    SSL_free(ioData->targetSSL);
                    SSL_CTX_free(ioData->clientCTX);
                    delete ioData;
                    return FALSE;
                }
            }
            else
            {
                cout << "[+]WSARecv() server BIO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
            }
            return FALSE;
        }
        
    }
    else if (mode == SERVER)
    {
        memset(ioData->cSendBuffer, '\0', BUFFER_SIZE);
        bioRead = BIO_read(ioData->cwBio, ioData->cSendBuffer, BUFFER_SIZE);
        if (bioRead > 0)
        {
            if (verbose)
            {
                cout << "[+]BIO_read() client - " << bioRead << " bytes. ID - " << ioData->key << endl;
            }

            ioData->wsaClientSendBuf.len = bioRead;

            if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                cout << "[-]WSASend() client - " << error << " ID - " << ioData->key << endl;
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]WSASend() client - " << error << " ID - " << ioData->key << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->clientSSL);
                    SSL_free(ioData->targetSSL);
                    SSL_CTX_free(ioData->clientCTX);
                    delete ioData;
                    return FALSE;
                }
            }
            else
            {
                cout << "[+]WSASend() client - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
            }
        }
        else if (ioData->clientRecvFlag)
        {
            ioData->bioSFlag = FALSE;
            return FALSE;
        }
        else
        {
            ioData->bioSFlag = FALSE;
            ioData->clientRecvFlag = TRUE;
            memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

            if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                cout << "[-]WSARecv() client BIO - " << error << " ID - " << ioData->key << endl;
                if (error != WSA_IO_PENDING)
                {
                    cerr << "[-]WSARecv() client BIO - " << error << " ID - " << ioData->key << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->clientSSL);
                    SSL_free(ioData->targetSSL);
                    SSL_CTX_free(ioData->clientCTX);
                    delete ioData;
                    return FALSE;
                }
            }
            else
            {
                cout << "[+]WSARecv() client BIO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
            }

            return FALSE;
        }
        
    }
    
    return TRUE;
}

void cleanupSSL() 
{
    EVP_PKEY_free(caKey);
    X509_free(caCert);
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    if (verbose)
    {
        cout << "[+]OpenSSL cleaned up" << endl;
    }
}