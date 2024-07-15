#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <assert.h>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <openssl/rand.h>

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable : 4996)

#define BUFFER_SIZE 4096
#define PORT        8080

typedef enum _IO_OPERATION {
    CLIENT_ACCEPT,
    CLIENT_IO_READ,
    CLIENT_IO_WRITE,
    SERVER_IO_READ,
    SERVER_IO_WRITE,
    SSL_SERVER_IO_WRITE,
    SSL_SERVER_IO_READ,
    SSL_CLIENT_IO_WRITE,
    SSL_CLIENT_IO_READ,
} IO_OPERATION, * PERIO_OPERATIONS;

typedef struct _PER_IO_DATA {
    WSAOVERLAPPED overlapped;
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
} PER_IO_DATA, * LPPER_IO_DATA;

HANDLE ProxyCompletionPort;
X509* caCert;
EVP_PKEY* caKey;
DWORD flags = 0;

void initializeWinsock();
void initializeOpenSSL();
SOCKET createSocket(int port);
LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation);
SSL_CTX* createServerContext();
SSL_CTX* createClientContext();
EVP_PKEY* generatePrivateKey();
vector<string> get_sans(X509* cert);
string get_cn(X509* cert);
X509* create_certificate(X509* ca_cert, EVP_PKEY* ca_pkey, EVP_PKEY* pkey, X509* target_cert);
int ServerNameCallback(SSL* ssl, int* ad, void* arg);
void configureContext(SSL_CTX* ctx, X509* cert, EVP_PKEY* pkey);
static DWORD WINAPI WorkerThread(LPVOID lparameter);
void cleanupSSL();

int main() {
    initializeWinsock();
    initializeOpenSSL();

    FILE* ca_cert_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.crt", "r");
    if (!ca_cert_file) {
        cerr << "[-]Error opening CA certificate file" << endl;
        exit(EXIT_FAILURE);
    }
    caCert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if (!caCert) {
        cerr << "[-]Error reading CA certificate" << endl;
        exit(EXIT_FAILURE);
    }

    FILE* ca_pkey_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.key", "r");
    if (!ca_pkey_file) {
        cerr << "[-]Error opening CA private key file" << endl;
        exit(EXIT_FAILURE);
    }
    caKey = PEM_read_PrivateKey(ca_pkey_file, NULL, NULL, NULL);
    fclose(ca_pkey_file);
    if (!caKey) {
        cerr << "[-]Error reading CA private key" << endl;
        exit(EXIT_FAILURE);
    }

    ProxyCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!ProxyCompletionPort) {
        cerr << "[-]Cannot create ProxyCompletionPort" << endl;
        WSACleanup();
        return 1;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++) {
        HANDLE pThread = CreateThread(NULL, 0, WorkerThread, ProxyCompletionPort, 0, NULL);
        if (pThread == NULL) {
            cerr << "[-]Failed to create worker thread" << endl;
            WSACleanup();
            return 1;
        }
        CloseHandle(pThread);
    }

    SOCKET proxySocket = createSocket(PORT);

    while (TRUE) {
        SOCKADDR_IN sockAddr;
        int addrLen = sizeof(sockAddr);

        SOCKET clientSocket = WSAAccept(proxySocket, (SOCKADDR*)&sockAddr, &addrLen, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "[-]WSAAccept failed - " << WSAGetLastError() << endl;
            continue;
        }
        cout << "[+]client accepted" << endl;

        LPPER_IO_DATA clientData = UpdateIoCompletionPort(clientSocket, INVALID_SOCKET, CLIENT_ACCEPT);
        if (!clientData) {
            cerr << "[-]UpdateIoCompletionPort failed" << endl;
            closesocket(clientSocket);
            continue;
        }

        DWORD bufSize = 0;
        if (WSARecv(clientData->clientSocket, &clientData->wsaClientRecvBuf, 1, &clientData->bytesRecv, &flags, &clientData->overlapped, NULL) == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSA_IO_PENDING) {
                cerr << "[-]WSARecv failed - " << error << endl;
                closesocket(clientData->clientSocket);
                delete clientData;
            }
        }
        else {
            cout << "[+]From client - " << clientData->bytesRecv << " bytes." << endl;
        }

    }

    closesocket(proxySocket);
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    cleanupSSL();
    WSACleanup();

    return 0;
}

void initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        cerr << "[-]WSAStartup failed - " << result << endl;
        exit(EXIT_FAILURE);
    }
    cout << "[+]Winsock initialized" << endl;
}

void initializeOpenSSL() {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_ssl_algorithms();
    cout << "[+]OpenSSL initialized" << endl;
}

SSL_CTX* createServerContext() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "[-]Unable to create SSL context" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "[+]Server context created" << endl;

    return ctx;
}

SSL_CTX* createClientContext() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "[-]Unable to create SSL context" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "[+]Client context created" << endl;

    return ctx;
}

EVP_PKEY* generatePrivateKey() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        cerr << "[-]EVP_PKEY_CTX_new_id failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        cerr << "[-]EVP_PKEY_keygen_init failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        cerr << "[-]EVP_PKEY_CTX_set_rsa_keygen_bits failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        cerr << "[-]EVP_PKEY_keygen failed" << endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void configureContext(SSL_CTX* ctx, X509* cert, EVP_PKEY* pkey) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        cerr << "[-]Error using certificate" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "[+]Certificate used" << endl;

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        cerr << "[-]Error using private key" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    cout << "[+]Private key used" << endl;
}

SOCKET createSocket(int port) {
    SOCKET socket;
    SOCKADDR_IN sockAddr;

    socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET) {
        cerr << "[-]WSASocket failed" << endl;
        exit(EXIT_FAILURE);
    }

    ZeroMemory(&sockAddr, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(port);
    sockAddr.sin_addr.s_addr = INADDR_ANY;

    int opt = 0;
    int size = sizeof(int);

    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, size) != SOCKET_ERROR) {
        cout << "[+]setsockopt()" << endl;
    }

    if (bind(socket, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) != 0) {
        cerr << "[-]Unable to bind" << endl;
        closesocket(socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if (listen(socket, SOMAXCONN) != 0) {
        cerr << "[-]Unable to listen: " << WSAGetLastError() << endl;
        closesocket(socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    cout << "[+]Listening on port " << port << "..." << endl;

    return socket;
}

LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation) {
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
    ioData->hostname = "";
    ioData->pkey = NULL;
    ioData->crBio = NULL;
    ioData->cwBio = NULL;
    ioData->srBio = NULL;
    ioData->swBio = NULL;

    if (CreateIoCompletionPort((HANDLE)socket, ProxyCompletionPort, (ULONG_PTR)ioData, 0) == NULL) {
        delete ioData;
        return NULL;
    }

    return ioData;
}

SOCKET connectToTarget(const string& hostname, int port) {
    SOCKET sock;
    struct addrinfo hints, * res, * p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), port_str, &hints, &res) != 0) {
        cerr << "getaddrinfo" << endl;
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET) {
            cerr << "[-]Invalid socket" << endl;
            continue;
        }

        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }
        cout << "[+]Connected to target server: " << hostname << endl;

        break;
    }

    if (p == NULL) {
        cerr << "[-]Unable to connect to target server: " << hostname << endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    return sock;
}

bool parseConnectRequest(const string& request, string& hostname, int& port) {
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

string extractHost(const string& request) {
    size_t pos = request.find("Host: ");
    if (pos == string::npos)
        return "";
    pos += 6;
    size_t end = request.find("\r\n", pos);
    return request.substr(pos, end - pos);
}

ASN1_INTEGER* generate_serial() {
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial) {
        cerr << "ASN1_INTEGER_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Generate a random 64-bit integer for the serial number
    uint64_t serial_number = 0;
    if (!RAND_bytes((unsigned char*)&serial_number, sizeof(serial_number))) {
        cerr << "RAND_bytes failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    // Convert the random number to ASN1_INTEGER
    if (!ASN1_INTEGER_set_uint64(serial, serial_number)) {
        cerr << "ASN1_INTEGER_set_uint64 failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    return serial;
}

X509* generate_certificate(const char* server_name, EVP_PKEY* pkey, X509* ca_cert, EVP_PKEY* ca_pkey) {
    X509* x509 = X509_new();
    if (!x509) {
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
    if (!X509_sign(x509, ca_pkey, EVP_sha256())) {
        cerr << "Unable to sign certificate" << endl;
        X509_free(x509);
        return nullptr;
    }

    cout << "[+]Created certificate for proxy" << endl;

    return x509;
}

int ServerNameCallback(SSL* ssl, int* ad, void* arg) {
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        cout << "SNI: " << servername << endl;

        // Generate key for new certificate
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        EVP_PKEY_assign_RSA(pkey, rsa);

        // Generate new certificate
        X509* cert = generate_certificate(servername, pkey, caCert, caKey);

        // Assign new certificate and private key to SSL context
        SSL_use_certificate(ssl, cert);
        SSL_use_PrivateKey(ssl, pkey);

        // Clean up
        X509_free(cert);
        EVP_PKEY_free(pkey);

    }
    else {
        cerr << "No SNI" << endl;
    }
    return SSL_TLSEXT_ERR_OK;
}

vector<string> get_sans(X509* cert) {
    vector<string> sans;
    STACK_OF(GENERAL_NAME)* names = NULL;

    names = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        return sans;
    }

    int num_names = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < num_names; i++) {
        GENERAL_NAME* gen_name = sk_GENERAL_NAME_value(names, i);
        if (gen_name->type == GEN_DNS) {
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

X509* create_certificate(X509* ca_cert, EVP_PKEY* ca_pkey, EVP_PKEY* pkey, X509* target_cert) {
    X509* cert = X509_new();
    if (!cert) {
        cerr << "X509_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    X509_set_version(cert, 2);

    ASN1_INTEGER* serial = generate_serial();
    X509_set_serialNumber(cert, serial);
    cout << "[+]Serial assigned" << endl;
    ASN1_INTEGER_free(serial);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);  // 1 year validity

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Proxy Inc.", -1, -1, 0);

    // Extract CN and SANs from target certificate
    string cn = get_cn(target_cert);
    vector<string> sans = get_sans(target_cert);

    // Set CN
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add SANs
    if (!sans.empty()) {
        STACK_OF(GENERAL_NAME)* san_list = sk_GENERAL_NAME_new_null();
        for (const string& san : sans) {
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

    if (!X509_sign(cert, ca_pkey, EVP_sha256())) {
        cerr << "Error signing certificate" << endl;
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        exit(EXIT_FAILURE);
    }

    return cert;
}

static DWORD WINAPI WorkerThread(LPVOID lparameter) {
    HANDLE CompletionPort = (HANDLE)lparameter;
    DWORD bytesTransferred = 0;
    LPPER_IO_DATA socketData = NULL;
    LPWSAOVERLAPPED overlapped = NULL;

    while (TRUE) {
        BOOL result = GetQueuedCompletionStatus(CompletionPort, &bytesTransferred, (PDWORD_PTR)&socketData, (LPOVERLAPPED*)&overlapped, INFINITE);
        LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;

        if (!result || bytesTransferred == 0) {
            cerr << "GetQueuedCompletionStatus failed or connection closed" << endl;
            if (ioData) {
                closesocket(ioData->clientSocket);
                if (ioData->serverSocket != INVALID_SOCKET) {
                    closesocket(ioData->serverSocket);
                }
                delete ioData;
            }
            continue;
        }

        switch (ioData->ioOperation) {

        case CLIENT_ACCEPT: {

            ioData->bytesRecv = bytesTransferred;
            ioData->ioOperation = SSL_SERVER_IO_WRITE;
            //cout << ioData->cRecvBuffer << endl;
            string request(ioData->cRecvBuffer, ioData->bytesRecv);
            string hostname;
            int port;
            if (!parseConnectRequest(request, hostname, port)) {
                cerr << "[-]Invalid CONNECT request" << endl;
                closesocket(ioData->clientSocket);
                delete ioData;
                break;
            }
            else {
                cout << "[+]CONNECT request parsed. Hostname - " << hostname << endl;
            }

            if (!hostname.empty()) {
                ioData->hostname = hostname;
                SOCKET serverSocket = connectToTarget(hostname, port);

                if (serverSocket != INVALID_SOCKET) {
                    ioData->serverSocket = serverSocket;
                    if (CreateIoCompletionPort((HANDLE)serverSocket, ProxyCompletionPort, NULL, 0) == NULL) {
                        cerr << "[-]CreateIoCompletionPort for server failed" << endl;
                        closesocket(ioData->serverSocket);
                        closesocket(ioData->clientSocket);
                        delete ioData;
                        continue;
                    }
                    else {
                        cout << "[+]Updated Io completion port" << endl;
                    }
                }

                ioData->crBio = BIO_new(BIO_s_mem());
                ioData->cwBio = BIO_new(BIO_s_mem());
                ioData->srBio = BIO_new(BIO_s_mem());
                ioData->swBio = BIO_new(BIO_s_mem());
                if (!ioData->crBio || !ioData->cwBio || !ioData->srBio || !ioData->swBio) {
                    cout << "[-]BIO_new failed" << endl;
                    return 1;
                }
                else {
                    BIO_set_nbio(ioData->crBio, 1);
                    BIO_set_nbio(ioData->cwBio, 1);
                    BIO_set_nbio(ioData->srBio, 1);
                    BIO_set_nbio(ioData->swBio, 1);
                }

                SSL_CTX* targetCTX = SSL_CTX_new(TLS_client_method());
                ioData->targetSSL = SSL_new(targetCTX);
                SSL_set_connect_state(ioData->targetSSL);
                SSL_CTX_set_verify(targetCTX, SSL_VERIFY_NONE, NULL);

                SSL_set_bio(ioData->targetSSL, ioData->srBio, ioData->swBio);

                char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
                memcpy(ioData->cSendBuffer, response, sizeof(response));
                ioData->wsaClientSendBuf.len = sizeof(response);
                if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                    int error = WSAGetLastError();
                    if (error != WSA_IO_PENDING) {
                        cerr << "[-]Failed to send response - " << error << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        SSL_free(ioData->targetSSL);
                        delete ioData;
                        continue;
                    }
                }
                else {
                    cout << "[+]Connection established with client" << endl;
                    ioData->wsaClientSendBuf.buf = ioData->cSendBuffer;
                }
            }
            break;
        }

        case SSL_SERVER_IO_WRITE: {

            cout << "SSL_SERVER_IO_WRITE" << endl;

            ioData->ioOperation = SSL_SERVER_IO_READ;
            //cout << "1 - " << bytesTransferred << endl;

            if (SSL_do_handshake(ioData->targetSSL) == 1) {

                DWORD bio_write = 0;
                ioData->ioOperation = SSL_CLIENT_IO_WRITE;
                cout << "[+]SSL handshake done with server" << endl;

                ioData->targetCert = SSL_get_peer_certificate(ioData->targetSSL);
                if (!ioData->targetCert) {
                    cout << "[-]Cert of server not extracted" << endl;
                }

                // SSL handshake with client
                ioData->clientCTX = SSL_CTX_new(TLS_server_method());
                SSL_CTX_set_tlsext_servername_callback(ioData->clientCTX, ServerNameCallback);

                EVP_PKEY* pkey = generatePrivateKey();
                ioData->clientCert = create_certificate(caCert, caKey, pkey, ioData->targetCert);
                configureContext(ioData->clientCTX, ioData->clientCert, pkey);

                /*X509* cert = generate_certificate(ioData->hostname.c_str(), pkey, caCert, caKey);
                configureContext(ioData->clientCTX, cert, pkey);*/

                ioData->clientSSL = SSL_new(ioData->clientCTX);
                SSL_set_accept_state(ioData->clientSSL); /* to act as SERVER */

                SSL_set_bio(ioData->clientSSL, ioData->crBio, ioData->cwBio);

                DWORD r = SSL_do_handshake(ioData->clientSSL);

                if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                    DWORD error = WSAGetLastError();
                    if (error != WSA_IO_PENDING) {
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
                else {
                    cout << "[+]WSARecv() client - " << ioData->bytesRecv << " bytes." << endl;
                    bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, ioData->bytesRecv);
                    if (bio_write > 0) {
                        cout << "[+]BIO_write() client - " << bio_write << " bytes." << endl;
                    }
                    else {
                        cout << "[-]BIO_write() client failed" << endl;
                    }
                }
            }

            // SSL handshake with server
            if (!SSL_is_init_finished(ioData->targetSSL)) {

                char Buf[BUFFER_SIZE] = {};
                int bio_read = 0, bio_write = 0;

                DWORD r = SSL_do_handshake(ioData->targetSSL);
                r = SSL_get_error(ioData->targetSSL, r);

                if (r == SSL_ERROR_WANT_READ) {

                    bio_read = BIO_read(ioData->swBio, Buf, BUFFER_SIZE);

                    cout << "[+]BIO_read() server - " << bio_read << " bytes." << endl;

                    if (bio_read > 0) {

                        memcpy(ioData->wsaServerSendBuf.buf, Buf, bio_read);
                        ioData->wsaServerSendBuf.len = bio_read;

                        if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                            int error = WSAGetLastError();
                            if (error != WSA_IO_PENDING) {
                                cerr << "[-]WSASend error - " << error << endl;
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                SSL_free(ioData->targetSSL);
                                delete ioData;
                                break;
                            }
                        }
                        else {
                            cout << "[+]WSASend() server - " << ioData->bytesSend << " bytes." << endl;
                        }
                    }

                }

            }

            break;
        }

        case SSL_SERVER_IO_READ: {

            cout << "SSL_SERVER_IO_READ" << endl;

            ioData->ioOperation = SSL_SERVER_IO_WRITE;
            cout << "2 - " << bytesTransferred << endl;

            if (!SSL_is_init_finished(ioData->targetSSL))
            {
                DWORD bio_write = 0;
                ioData->wsaServerRecvBuf.len = BUFFER_SIZE;

                if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                    int error = WSAGetLastError();
                    cout << "[-]WSARecv error - " << error << endl;
                    if (error != WSA_IO_PENDING) {
                        cerr << "[-]WSARecv error - " << error << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        SSL_free(ioData->targetSSL);
                        delete ioData;
                        break;
                    }
                }
                else {
                    cout << "[+]WSARecv() server - " << ioData->bytesRecv << " bytes." << endl;
                    bio_write = BIO_write(ioData->srBio, ioData->sRecvBuffer, ioData->bytesRecv);
                    if (bio_write > 0) {
                        cout << "[+]BIO_write() server - " << bio_write << " bytes." << endl;
                    }

                }
            }

            break;
        }

        case SSL_CLIENT_IO_READ: {

            cout << "SSL_CLIENT_IO_READ" << endl;

            ioData->ioOperation = SSL_CLIENT_IO_WRITE;
            DWORD error, bio_write = 0;
            char Buf[BUFFER_SIZE] = {};

            if (SSL_do_handshake(ioData->clientSSL) == 1) {
                ioData->ioOperation = CLIENT_IO_READ;
                cout << "[+]SSL handshake done with client" << endl;
                break;
            }

            ioData->wsaClientRecvBuf.len = BUFFER_SIZE;

            if (!SSL_is_init_finished(ioData->clientSSL)) {
                if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) != SOCKET_ERROR) {
                    error = WSAGetLastError();
                    if (error != WSA_IO_PENDING) {
                        cerr << "[-]WSARecv error - " << error << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        SSL_free(ioData->clientSSL);
                        SSL_free(ioData->targetSSL);
                        SSL_CTX_free(ioData->clientCTX);
                        delete ioData;
                        break;
                    }
                }
                else {
                    cout << "[+]WSARecv() client - " << ioData->bytesRecv << " bytes." << endl;
                    bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, ioData->bytesRecv);
                    if (bio_write > 0) {

                        cout << "[+]BIO_write() client - " << bio_write << " bytes." << endl;

                    }
                    else if (bio_write <= 0) {

                        if (!BIO_should_retry(ioData->crBio)) {

                            cerr << "[-]BIO_write() failed with error" << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->clientSSL);
                            SSL_free(ioData->targetSSL);
                            SSL_CTX_free(ioData->clientCTX);
                            delete ioData;
                            ioData = NULL;
                            continue;

                        }

                    }
                }
            }

            break;
        }

        case SSL_CLIENT_IO_WRITE: {

            cout << "SSL_CLIENT_IO_WRITE" << endl;

            ioData->ioOperation = SSL_CLIENT_IO_READ;

            if (SSL_do_handshake(ioData->clientSSL) == 1) {
                ioData->ioOperation = CLIENT_IO_READ;
                cout << "[+]SSL handshake done with client" << endl;
                break;
            }

            if (!SSL_is_init_finished(ioData->clientSSL))
            {
                DWORD bio_read = 0, error;
                char Buf[BUFFER_SIZE] = {};

                bio_read = BIO_read(ioData->cwBio, Buf, BUFFER_SIZE);

                if (bio_read > 0) {

                    cout << "[+]BIO_read() client - " << bio_read << " bytes." << endl;

                    memcpy(ioData->cSendBuffer, Buf, bio_read);
                    ioData->wsaClientSendBuf.len = bio_read;

                    if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                        error = WSAGetLastError();
                        if (error != WSA_IO_PENDING) {
                            cout << "[-]WSASend() error - " << error << endl;
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            SSL_free(ioData->clientSSL);
                            SSL_free(ioData->targetSSL);
                            SSL_CTX_free(ioData->clientCTX);
                            delete ioData;
                        }
                    }
                    else {
                        cout << "[+]WSASend() client - " << ioData->bytesSend << " bytes." << endl;
                        if (SSL_do_handshake(ioData->clientSSL) == 1) {
                            cout << "[+]SSL handshake done with client" << endl;
                            break;
                        }
                    }
                }
                else if (bio_read <= 0) {

                    if (!BIO_should_retry(ioData->cwBio)) {

                        cerr << "[-]BIO_read() failed with error" << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        SSL_free(ioData->clientSSL);
                        SSL_free(ioData->targetSSL);
                        SSL_CTX_free(ioData->clientCTX);
                        delete ioData;
                        break;

                    }

                }
            }
            break;
        }

        case CLIENT_IO_READ: {

            cout << "CLIENT_IO_READ" << endl;

            ioData->ioOperation = SERVER_IO_WRITE;
            ioData->wsaClientRecvBuf.len = BUFFER_SIZE;
            int sslRead, bioWrite;

            if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    cerr << "[-]WSARecv() failed" << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->clientSSL);
                    SSL_free(ioData->targetSSL);
                    SSL_CTX_free(ioData->clientCTX);
                    delete ioData;
                    continue;
                }
            }
            else {
                cout << "[+]WSARecv() - " << ioData->bytesRecv << " bytes." << endl;
                sslRead = SSL_read(ioData->clientSSL, ioData->wsaClientRecvBuf.buf, BUFFER_SIZE);
                if (sslRead > 0) {
                    cout << "[+]SSL_read() - " << sslRead << endl;
                    bioWrite = BIO_write(ioData->srBio, ioData->wsaClientRecvBuf.buf, sslRead);
                }
            }

            break;
        }

        case SERVER_IO_WRITE: {

            cout << "SERVER_IO_WRITE" << endl;

            ioData->ioOperation = SERVER_IO_READ;
            ioData->wsaServerSendBuf.len = bytesTransferred;
            int bioRead, sslWrite;
            bioRead = BIO_read(ioData->swBio, ioData->wsaServerSendBuf.buf, ioData->wsaServerSendBuf.len);
            sslWrite = SSL_write(ioData->targetSSL, ioData->wsaServerSendBuf.buf, bioRead);

            if (sslWrite > 0) {
                ioData->wsaServerSendBuf.len = sslWrite;

                if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSA_IO_PENDING) {
                        cerr << "[-]WSASend failed" << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        SSL_free(ioData->clientSSL);
                        SSL_free(ioData->targetSSL);
                        SSL_CTX_free(ioData->clientCTX);
                        delete ioData;
                        ioData = NULL;
                        continue;
                    }
                }
                else {
                    cout << "[+]WSASend - " << ioData->bytesSend << endl;
                }
            }

            break;
        }

        case SERVER_IO_READ: {

            ioData->ioOperation = CLIENT_IO_WRITE;
            ioData->wsaServerRecvBuf.len = BUFFER_SIZE;
            int ssl_read, bio_write;

            if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    cerr << "[-]WSARecv failed" << endl;
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    SSL_free(ioData->clientSSL);
                    SSL_free(ioData->targetSSL);
                    SSL_CTX_free(ioData->clientCTX);
                    delete ioData;
                    ioData = NULL;
                    continue;
                }
            }
            else {
                cout << "[+]WSARecv - " << ioData->bytesRecv << endl;
                ssl_read = SSL_read(ioData->targetSSL, ioData->wsaServerRecvBuf.buf, BUFFER_SIZE);
                if (ssl_read > 0) {
                    cout << "[+]SSL_read - " << ssl_read << endl;
                    bio_write = BIO_write(ioData->srBio, ioData->wsaServerRecvBuf.buf, ssl_read);
                }
            }

            break;
        }

        case CLIENT_IO_WRITE: {

            ioData->ioOperation = CLIENT_IO_READ;
            ioData->wsaClientSendBuf.len = bytesTransferred;
            int bioRead, sslWrite;
            bioRead = BIO_read(ioData->cwBio, ioData->wsaClientSendBuf.buf, ioData->wsaClientSendBuf.len);
            sslWrite = SSL_write(ioData->clientSSL, ioData->wsaClientSendBuf.buf, bioRead);

            if (sslWrite > 0) {
                ioData->wsaClientSendBuf.len = sslWrite;

                if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSA_IO_PENDING) {
                        cerr << "[-]WSASend failed" << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        SSL_free(ioData->clientSSL);
                        SSL_free(ioData->targetSSL);
                        SSL_CTX_free(ioData->clientCTX);
                        delete ioData;
                        ioData = NULL;
                        continue;
                    }
                }
                else {
                    cout << "[+]WSASend - " << ioData->bytesSend << endl;
                }
            }

            break;
        }

        default:
            break;


        }

        /*if (ioData) {
            BIO_free(ioData->crBio);
            BIO_free(ioData->cwBio);
            BIO_free(ioData->srBio);
            BIO_free(ioData->swBio);
        }*/

    }


    return 0;
}


void cleanupSSL() {
    EVP_cleanup();
    cout << "[+]OpenSSL cleaned up" << endl;
}
