#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
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
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include "Util.h"
#include "SslUtil.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

// to set the default logger file
// *create an empty text file and add the path in basic_logger_mt() function*
void replace_default_logger_example()
{
    auto new_logger = spdlog::basic_logger_mt("new_default_logger", "C:\\Users\\user\\OneDrive\\Desktop\\output_logs.txt", true);
    spdlog::set_default_logger(new_logger);
    spdlog::flush_every(std::chrono::seconds(3));
}

using namespace std;

#pragma warning(disable : 4996)

#define SERVICE_NAME TEXT("Example Service")
SERVICE_STATUS ServiceStatus = {0};
SERVICE_STATUS_HANDLE hServiceStatusHandle = NULL;
HANDLE hServiceEvent = NULL;

#define BUFFER_SIZE 4096
#define PORT 8080

HANDLE ProxyCompletionPort;
X509 *caCert;
EVP_PKEY *caKey;
SOCKET proxySocket;

BOOL verbose = TRUE;
static INT ID = 0;

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
} IO_OPERATION,
    *PERIO_OPERATIONS;

enum MODE
{
    CLIENT,
    SERVER,
};

// struct to store IOCP data
typedef struct _PER_IO_DATA
{
    WSAOVERLAPPED overlapped;
    DWORD key = ++ID;
    SOCKET clientSocket, serverSocket;
    WSABUF wsaClientSendBuf, wsaClientRecvBuf, wsaServerSendBuf, wsaServerRecvBuf;
    char cSendBuffer[BUFFER_SIZE], cRecvBuffer[BUFFER_SIZE], sSendBuffer[BUFFER_SIZE], sRecvBuffer[BUFFER_SIZE];
    DWORD bytesSend, bytesRecv;
    IO_OPERATION ioOperation;
    SSL *clientSSL, *targetSSL;
    X509 *clientCert, *targetCert;
    SSL_CTX *clientCTX;
    string hostname;
    EVP_PKEY *pkey;
    BIO *srBio, *swBio, *crBio, *cwBio;
    BOOL bioCFlag = FALSE, bioSFlag = FALSE;
    BOOL clientRecvFlag = FALSE, serverRecvFlag = FALSE;
    BOOL clientSendFlag = FALSE, serverSendFlag = FALSE;
} PER_IO_DATA, *LPPER_IO_DATA;

LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, SOCKET peerSocket, IO_OPERATION ioOperation);
static DWORD WINAPI WorkerThread(LPVOID lparameter);
VOID StartProxyServer(VOID);
VOID cleanupSSL(VOID);

VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpArgv); // service main function
VOID WINAPI ServiceControlHandler(DWORD dwControl);   // service control handler
VOID ServiceReportStatus(
    DWORD dwCurrentState,
    DWORD dwWin32ExitCode,
    DWORD dwWaitHint);
VOID ServiceInit(DWORD dwArgc, LPSTR *lpArgv);
VOID ServiceInstall(VOID);
VOID ServiceDelete(VOID);
VOID ServiceStart(VOID);
VOID ServiceStop(VOID);

int main(int argc, CHAR *argv[])
{
    BOOL bStServiceCtrlDispatcher = FALSE;

    if (lstrcmpiA(argv[1], "install") == 0)
    {
        ServiceInstall();
        cout << "Installation success" << endl;
    }
    else if (lstrcmpiA(argv[1], "start") == 0)
    {
        ServiceStart();
        cout << "start success" << endl;
    }
    else if (lstrcmpiA(argv[1], "stop") == 0)
    {
        ServiceStop();
        cout << "stop success" << endl;
    }
    else if (lstrcmpiA(argv[1], "delete") == 0)
    {
        ServiceDelete();
        cout << "delete success" << endl;
    }
    else
    {
        SERVICE_TABLE_ENTRY DispatchTable[] =
            {
                {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
                {NULL, NULL}};

        bStServiceCtrlDispatcher = StartServiceCtrlDispatcher(DispatchTable);
        if (FALSE == bStServiceCtrlDispatcher)
        {
            cout << "bStServiceCtrlDispatcher failed " << GetLastError() << endl;
        }
        else
        {
            cout << "bStServiceCtrlDispatcher success" << endl;
        }
    }

    system("PAUSE");
    return 0;
}

// main logic starts here -->
VOID StartProxyServer()
{
    initializeWinsock();
    initializeOpenSSL();
    replace_default_logger_example();

    // we need to create a rootCA certificate and install it in our local device. refer https://superuser.com/questions/126121/how-to-create-my-own-certificate-chain.
    FILE *ca_cert_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.crt", "r");
    if (!ca_cert_file)
    {
        spdlog::info("[-]Error opening CA certificate file");
        exit(EXIT_FAILURE);
    }

    caCert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if (!caCert)
    {
        spdlog::info("[-]Error reading CA certificate");
        exit(EXIT_FAILURE);
    }

    // private key for CA
    FILE *ca_pkey_file = fopen("C:\\Users\\user\\OneDrive\\Desktop\\Certs\\rootCA.key", "r");
    if (!ca_pkey_file)
    {
        spdlog::info("[-]Error opening CA certificate file");
        exit(EXIT_FAILURE);
    }

    caKey = PEM_read_PrivateKey(ca_pkey_file, NULL, NULL, NULL);
    fclose(ca_pkey_file);
    if (!caKey)
    {
        spdlog::info("[-]Error reading CA private key");
        exit(EXIT_FAILURE);
    }

    ProxyCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!ProxyCompletionPort)
    {
        spdlog::info("[-]Cannot create ProxyCompletionPort");
        WSACleanup();
        return;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++)
    {
        HANDLE pThread = CreateThread(NULL, 0, WorkerThread, ProxyCompletionPort, 0, NULL);
        if (pThread == NULL)
        {
            spdlog::info("[-]Failed to create worker thread");
            WSACleanup();
            return;
        }
        CloseHandle(pThread);
    }

    proxySocket = createSocket(PORT);

    while (TRUE)
    {
        SOCKET clientSocket = WSAAccept(proxySocket, NULL, NULL, NULL, 0);
        if (clientSocket == INVALID_SOCKET)
        {
            spdlog::info("[-]WSAAccept failed - {}", WSAGetLastError());
            continue;
        }
        else if (verbose)
        {
            spdlog::info("[+]client accepted");
        }

        struct sockaddr_in peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);

        if (getpeername(clientSocket, (struct sockaddr *)&peer_addr, &peer_addr_len) == -1)
        {
            spdlog::info("[-]getpeername failed");
        }
        else
        {
            char peer_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, INET_ADDRSTRLEN);

            spdlog::info("[+]Connected client's Port: {}", ntohs(peer_addr.sin_port));
        }

        LPPER_IO_DATA clientData = UpdateIoCompletionPort(clientSocket, INVALID_SOCKET, CLIENT_ACCEPT);
        if (!clientData)
        {
            spdlog::info("[-]UpdateIoCompletionPort failed");
            closesocket(clientSocket);
            continue;
        }
        else
        {
            spdlog::info("[+]UpdateIoCompletionPort done");
        }

        DWORD flags = 0;
        if (WSARecv(clientData->clientSocket, &clientData->wsaClientRecvBuf, 1, &clientData->bytesRecv, &flags, &clientData->overlapped, NULL) == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            spdlog::info("[-]WSARecv() pending");
            if (error != WSA_IO_PENDING)
            {
                spdlog::info("[-]WSARecv failed - {}", error);
                closesocket(clientData->clientSocket);
                delete clientData;
                continue;
            }
        }
        else
        {
            spdlog::info("[+]From client - {} bytes.", clientData->bytesRecv);
            cout << clientData->cRecvBuffer << endl;
            clientData->bytesRecv = 0;
        }
    }

    closesocket(proxySocket);
    cleanupSSL();
    WSACleanup();

    return;
}

// initialize the IOCP struct with server and client sockets
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

// adding SNI functionality to retrieve the host name from client hello
int ServerNameCallback(SSL *ssl, int *ad, LPPER_IO_DATA ioData)
{
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername)
    {
        if (verbose)
        {
            spdlog::info("[=]SNI: {}", servername);
        }
        ioData->hostname = servername;

        // Generate key for new certificate
        ioData->pkey = EVP_PKEY_new();
        RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        EVP_PKEY_assign_RSA(ioData->pkey, rsa);

        // Generate new certificate
        ioData->clientCert = create_certificate(caCert, caKey, ioData->pkey, ioData->targetCert, ioData->hostname);

        // Assign new certificate and private key to SSL context
        SSL_use_certificate(ssl, ioData->clientCert);
        SSL_use_PrivateKey(ssl, ioData->pkey);
    }
    else
    {
        spdlog::info("[-]No SNI");
    }
    return SSL_TLSEXT_ERR_OK;
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
        BOOL result = GetQueuedCompletionStatus(completionPort,
                                                &bytesTransferred,
                                                (PDWORD_PTR)&socketData,
                                                (LPOVERLAPPED *)&overlapped,
                                                INFINITE);

        LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;

        if (!result)
        {
            spdlog::info("[-]GetQueuedCompletionStatus failed - {}", GetLastError());
        }

        if (ioData == NULL)
        {
            spdlog::info("[-]IO_DATA NULL");
            cout << "[-]IO_DATA NULL" << endl;
            return 0;
        }

        if (!result || bytesTransferred == 0)
        {
            spdlog::info("[-]Connection closed. ID - {}", ioData->key);
            if (ioData)
            {
                closesocket(ioData->clientSocket);
                ioData->serverSocket = INVALID_SOCKET;
                delete ioData;
            }
            return 0;
        }

        switch (ioData->ioOperation)
        {
            /*
            Client accept ->
            for HTTP connections -  simple send-recv cycles.
            for HTTPS connections - parse request and create new SSL object for connections
            */

        case CLIENT_ACCEPT:
        {

            ioData->bytesRecv = bytesTransferred;

            int port = 0;
            string request(ioData->cRecvBuffer, ioData->bytesRecv);

            if (strncmp(ioData->cRecvBuffer, "CONNECT", 7) == 0)
            {
                ioData->ioOperation = SSL_SERVER_IO;
                string hostname;

                if (!parseConnectRequest(request, hostname, port))
                {
                    spdlog::info("[-]Invalid CONNECT request");
                    closesocket(ioData->clientSocket);
                    delete ioData;
                    break;
                }

                if (!hostname.empty())
                {
                    ioData->hostname = hostname;
                    ioData->serverSocket = connectToTarget(hostname, port);
                    spdlog::info("[+]Connected to server - {}, on port - {}. ID - {}", hostname, port, ioData->key);

                    if (ioData->serverSocket != INVALID_SOCKET)
                    {
                        if (CreateIoCompletionPort((HANDLE)ioData->serverSocket, ProxyCompletionPort, NULL, 0) == NULL)
                        {
                            spdlog::info("[-]CreateIoCompletionPort for server failed");
                            closesocket(ioData->serverSocket);
                            ioData->serverSocket = INVALID_SOCKET;
                            closesocket(ioData->clientSocket);
                            ioData->clientSocket = INVALID_SOCKET;
                            delete ioData;
                            break;
                        }
                        else if (verbose)
                        {
                            spdlog::info("[+]Updated Io completion port. ID - {}", ioData->key);
                        }
                    }

                    // using BIO memory buffers to transfer data between sockets
                    ioData->crBio = BIO_new(BIO_s_mem());
                    ioData->cwBio = BIO_new(BIO_s_mem());
                    ioData->srBio = BIO_new(BIO_s_mem());
                    ioData->swBio = BIO_new(BIO_s_mem());
                    if (!ioData->crBio || !ioData->cwBio || !ioData->srBio || !ioData->swBio)
                    {
                        spdlog::info("[-]BIO_new failed. ID - ", ioData->key);
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

                    SSL_CTX *targetCTX = SSL_CTX_new(TLS_client_method());
                    ioData->targetSSL = SSL_new(targetCTX);
                    if (!SSL_set_tlsext_host_name(ioData->targetSSL, ioData->hostname.c_str()))
                    {
                        spdlog::info("[-]SSL_set_tlsext_host_name() failed. ID - {}", ioData->key);
                        ERR_print_errors_fp(stderr);
                        break;
                    }
                    // to act as CLIENT
                    SSL_set_connect_state(ioData->targetSSL);
                    SSL_CTX_set_verify(targetCTX, SSL_VERIFY_NONE, NULL); // no verifications required
                    SSL_set_bio(ioData->targetSSL, ioData->srBio, ioData->swBio);

                    char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    memcpy(ioData->wsaClientSendBuf.buf, response, sizeof(response));
                    ioData->wsaClientSendBuf.len = sizeof(response);
                    if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        spdlog::info("[-]WSASend() failed. ID - {}", ioData->key);
                        if (error != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]Failed to send response - {}. ID - {}", error, ioData->key);
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            delete ioData;
                            break;
                        }
                    }
                    else
                    {
                        spdlog::info("[+]Connection established with client. ID - {}", ioData->key);
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
                            spdlog::info("[-]CreateIoCompletionPort for server failed. ID - {}", ioData->key);
                            closesocket(ioData->serverSocket);
                            closesocket(ioData->clientSocket);
                            delete ioData;
                            break;
                        }
                        else if (verbose)
                        {
                            spdlog::info("[+]Updated Io completion port. ID - {}", ioData->key);
                        }
                    }

                    memcpy(ioData->sSendBuffer, ioData->cRecvBuffer, bytesTransferred);
                    ioData->wsaServerSendBuf.len = bytesTransferred;

                    if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        spdlog::info("[-]WSASend() IO pending. ID - {}", ioData->key);
                        if (error != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]Failed to send response - {}. ID - {}", error, ioData->key);
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            delete ioData;
                            break;
                        }
                    }
                    else
                    {
                        spdlog::info("[+]WSASend() server - {} bytes. ID - {}", ioData->bytesSend, ioData->key);
                    }
                }
            }

            break;
        }

        case HTTP_S_RECV:
        {

            ioData->ioOperation = HTTP_C_SEND;

            if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                spdlog::info("[-]WSARecv() HTTP_S_RECV - {}. ID - {}", error, ioData->key);
                if (error != WSA_IO_PENDING)
                {
                    spdlog::info("[-]Failed to send response - {}. ID - {}", error, ioData->key);
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    delete ioData;
                    continue;
                }
            }
            else
            {
                spdlog::info("[+]WSARecv() HTTP_S_RECV - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
            }

            break;
        }

        case HTTP_C_SEND:
        {

            ioData->ioOperation = CLIENT_ACCEPT;

            memcpy(ioData->cSendBuffer, ioData->sRecvBuffer, bytesTransferred);
            ioData->wsaClientSendBuf.len = bytesTransferred;

            if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                spdlog::info("[-]WSASend() IO pending. ID - {}", ioData->key);
                if (error != WSA_IO_PENDING)
                {
                    spdlog::info("[-]Failed to send response - {}. ID - {}", error, ioData->key);
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    delete ioData;
                    continue;
                }
            }
            else
            {
                spdlog::info("[+]WSASend() HTTP_C_SEND - {} bytes. ID - {}", ioData->bytesSend, ioData->key);
            }

            break;
        }

        case HTTP_C_RECV:
        {

            ioData->ioOperation = CLIENT_ACCEPT;

            if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                spdlog::info("[-]WSASend() IO pending. ID - {}", ioData->key);
                if (error != WSA_IO_PENDING)
                {
                    spdlog::info("[-]Failed to send response - {}. ID - {}", error, ioData->key);
                    closesocket(ioData->clientSocket);
                    closesocket(ioData->serverSocket);
                    delete ioData;
                    continue;
                }
            }
            else
            {
                spdlog::info("[+]WSARecv() HTTP_C_RECV - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
            }

            break;
        }

        case SSL_SERVER_IO:
        {

            if (strlen(ioData->sRecvBuffer) > 0)
            {
                int bio_write = BIO_write(ioData->srBio, ioData->sRecvBuffer, bytesTransferred);
                if (bio_write > 0)
                {
                    spdlog::info("[+]BIO_write() server - {} bytes. ID - {}", bio_write, ioData->key);
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
                    // SSL handshake with client
                    ioData->ioOperation = SSL_CLIENT_IO;

                    // Extract certificate of Server
                    ioData->targetCert = SSL_get_peer_certificate(ioData->targetSSL);
                    if (!ioData->targetCert)
                    {
                        spdlog::info("[-]Cert of server not extracted. ID - {}", ioData->key);
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
                        spdlog::info("[-]Failed to create client SSL CTX. ID - {}", ioData->key);
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
                            spdlog::info("[-]WSARecv() failed - {}. ID - {}", error, ioData->key);
                            if (error != WSA_IO_PENDING)
                            {
                                spdlog::info("[-]WSARecv() failed - {}. ID - {}", error, ioData->key);
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            spdlog::info("[+]WSARecv() client - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                        }
                    }

                    break;
                }

                status = SSL_get_error(ioData->targetSSL, ret_server);

                spdlog::info("[=]SSL_get_error() - {}. ID - {}", status, ioData->key);

                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
                {
                    bio_read = BIO_read(ioData->swBio, Buf, BUFFER_SIZE);

                    if (bio_read > 0)
                    {
                        if (verbose)
                        {
                            spdlog::info("[+]BIO_read() server - {} bytes. ID - {}", bio_read, ioData->key);
                        }

                        memcpy(ioData->wsaServerSendBuf.buf, Buf, bio_read);
                        ioData->wsaServerSendBuf.len = bio_read;

                        if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            spdlog::info("[-]WSASend error - {}. ID - {}", error, ioData->key);
                            if (error != WSA_IO_PENDING)
                            {
                                spdlog::info("[-]WSASend error - {}. ID - {}", error, ioData->key);
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            spdlog::info("[+]WSASend() server - {} bytes. ID - {}", ioData->bytesSend, ioData->key);
                        }
                    }
                    else
                    {
                        ioData->bytesRecv = 0;
                        ioData->wsaServerRecvBuf.len = BUFFER_SIZE;

                        if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            spdlog::info("[-]WSARecv error - {}. ID - {}", error, ioData->key);
                            if (error != WSA_IO_PENDING)
                            {
                                spdlog::info("[-]WSARecv error - {}. ID - {}", error, ioData->key);
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            spdlog::info("[+]WSARecv() server - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                        }
                    }
                }
                else if (status == SSL_ERROR_SSL)
                {
                    spdlog::info("[-]SSL_get_error() - {}. ID - {}", ERR_error_string(ERR_get_error(), NULL), ioData->key);
                    break;
                }
                else
                {
                    spdlog::info("[-]SSL_get_error() -{}. ID - {}", status, ioData->key);
                    break;
                }
            }
            else if (verbose)
            {
                spdlog::info("[+]SSL handshake with server done. ID - {}", ioData->key);
            }

            break;
        }

        case SSL_CLIENT_IO:
        {

            if (strlen(ioData->cRecvBuffer) > 0)
            {
                // ioData->clientRecvFlag = FALSE;
                int bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);
                if (bio_write > 0 && verbose)
                {
                    spdlog::info("[+]BIO_write() client - {} bytes. ID - {}", bio_write, ioData->key);
                }
                else
                {
                    spdlog::info("[-]BIO_write() client. ID - {}", ioData->key);
                }
                memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
            }

            // SSL handshake with client
            if (!SSL_is_init_finished(ioData->clientSSL))
            {
                char Buf[BUFFER_SIZE] = {};
                int bio_read = 0, ret_client, status;

                ret_client = SSL_do_handshake(ioData->clientSSL);

                if (ret_client == 1)
                {

                    ioData->ioOperation = IO;
                    ioData->clientRecvFlag = TRUE;

                    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                    if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        if (WSAGetLastError() != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]WSARecv() failed. ID - {}", ioData->key);
                            closesocket(ioData->clientSocket);
                            closesocket(ioData->serverSocket);
                            delete ioData;
                            break;
                        }
                    }
                    else
                    {
                        spdlog::info("[+]WSARecv() client - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                    }

                    break;
                }

                status = SSL_get_error(ioData->clientSSL, ret_client);

                spdlog::info("[=]SSL_get_error() - {}. ID - {}", status, ioData->key);

                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
                {
                    bio_read = BIO_read(ioData->cwBio, Buf, BUFFER_SIZE);

                    if (bio_read > 0)
                    {
                        if (verbose)
                        {
                            spdlog::info("[+]BIO_read() client - {} bytes. ID - {}", bio_read, ioData->key);
                        }

                        memcpy(ioData->wsaClientSendBuf.buf, Buf, bio_read);
                        ioData->wsaClientSendBuf.len = bio_read;

                        if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            spdlog::info("[-]WSASend() error - {}. ID - {}", error, ioData->key);
                            if (error != WSA_IO_PENDING)
                            {
                                spdlog::info("[-]WSASend() error - {}. ID - {}", error, ioData->key);
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            spdlog::info("[+]WSASend() client - {} bytes. ID - {}", ioData->bytesSend, ioData->key);
                        }
                    }
                    else
                    {

                        ioData->bytesRecv = 0;
                        ioData->clientRecvFlag = TRUE;
                        ioData->wsaClientRecvBuf.len = BUFFER_SIZE;

                        if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                        {
                            int error = WSAGetLastError();
                            spdlog::info("[-]WSARecv() error - {}. ID - {}", error, ioData->key);
                            if (error != WSA_IO_PENDING)
                            {
                                spdlog::info("[-]WSARecv() error - {}. ID - {}", error, ioData->key);
                                closesocket(ioData->clientSocket);
                                closesocket(ioData->serverSocket);
                                delete ioData;
                                break;
                            }
                        }
                        else
                        {
                            spdlog::info("[+]WSARecv() client - {} bytes. ID - {}", ioData->key);
                        }
                    }
                }
                else if (status == SSL_ERROR_SSL)
                {
                    spdlog::info("[-]SSL_get_error() - {}. ID - {}", ERR_error_string(ERR_get_error(), NULL), ioData->key);
                    break;
                }
                else
                {
                    spdlog::info("[-]SSL_get_error() - {}. ID - {}", status, ioData->key);
                    break;
                }
            }
            else
            {
                spdlog::info("[+]SSL handshake with client done. ID - {}", ioData->key);
            }

            break;
        }

        case IO:
        {

            int bioRead = 0, bioWrite = 0, sslRead = 0, sslWrite = 0, ret, error;

            if (strlen(ioData->cRecvBuffer) > 0 && !ioData->bioCFlag)
            {
                cout << "[+]Bytestransferred client - " << bytesTransferred << " ID - " << ioData->key << endl;
                bioWrite = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);

                if (bioWrite > 0)
                {
                    ioData->clientRecvFlag = FALSE;

                    // spdlog::info("[+]BIO_write() client - {} bytes. ID - {}\n{}", bioWrite, ioData->key, toHex(ioData->cRecvBuffer, bioWrite));
                    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                    sslRead = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE);

                    if (sslRead <= 0)
                    {
                        error = SSL_get_error(ioData->clientSSL, sslRead);
                        spdlog::info("[-]SSL_read error - {}. ID - {}", error, ioData->key);
                        cout << "[=]SSL_read error - " << error << " ID - " << ioData->key << endl;

                        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
                        {
                            ioData->bytesRecv = 0;
                            ioData->clientRecvFlag = TRUE;
                            memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                            if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                            {
                                int error = WSAGetLastError();
                                spdlog::info("[-]WSARecv() client IO pending. ID - {}", ioData->key);
                                cout << "[-]WSARecv() client IO - " << error << " ID - " << ioData->key << endl;
                                if (error != WSA_IO_PENDING)
                                {
                                    spdlog::info("[-]WSARecv() client IO -  {}. ID - {}", error, ioData->key);
                                    cerr << "[-]WSARecv() client IO - " << error << " ID - " << ioData->key << endl;
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
                                spdlog::info("[+]WSARecv() client IO - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                                cout << "[+]WSARecv() client IO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                            }
                            break;
                        }
                        else if (error == SSL_ERROR_SSL)
                        {
                            spdlog::info("[-]SSL_get_error() CLIENT_IO - {}. ID - {}", ERR_error_string(ERR_get_error(), NULL), ioData->key);
                            cout << "[-]SSL_get_error() CLIENT_IO - " << ERR_error_string(ERR_get_error(), NULL) << " ID - " << ioData->key << endl;
                            break;
                        }
                        else
                        {
                            spdlog::info("[+]SSL_get_error() - {}", error);
                            cout << "[+]SSL_get_error() - " << error << endl;
                            break;
                        }
                    }
                    else
                    {
                        if (verbose)
                        {
                            spdlog::info("[+]SSL_read() client - {} bytes. ID - {}", sslRead, ioData->key);
                            cout << "[+]SSL_read() client - " << sslRead << " bytes. ID - " << ioData->key << endl;
                        }
                        spdlog::info("{}", ioData->cRecvBuffer);
                        cout << ioData->cRecvBuffer << endl;
                        sslWrite = SSL_write(ioData->targetSSL, ioData->cRecvBuffer, sslRead);
                        if (sslWrite > 0)
                        {
                            if (verbose)
                            {
                                spdlog::info("[+]SSL_write() server - {} bytes.ID - {}", sslWrite, ioData->key);
                                cout << "[+]SSL_write() server - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                            }
                            memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
                        }
                        else
                        {
                            ret = SSL_get_error(ioData->targetSSL, sslWrite);
                            spdlog::info("[-]SSL_write() - {}. ID - {}", error, ioData->key);
                            cout << "[-]SSL_write() - " << ret << endl;
                        }
                        while ((sslRead = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE)) > 0)
                        {
                            if (verbose)
                            {
                                spdlog::info("[+]SSL_read() client - {} bytes. ID - {}", sslRead, ioData->key);
                                cout << "[+]SSL_read() client - " << sslRead << " bytes. ID - " << ioData->key << endl;
                            }
                            spdlog::info("{}", ioData->cRecvBuffer);
                            cout << ioData->cRecvBuffer << endl;
                            sslWrite = SSL_write(ioData->targetSSL, ioData->cRecvBuffer, sslRead);
                            if (sslWrite > 0)
                            {
                                if (verbose)
                                {
                                    spdlog::info("[+]SSL_write() server - {} bytes.ID - {}", sslWrite, ioData->key);
                                    cout << "[+]SSL_write() - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                                }
                                memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
                            }
                            else
                            {
                                ret = SSL_get_error(ioData->targetSSL, sslWrite);
                                spdlog::info("[+]SSL_write() server - {} bytes.ID - {}", error, ioData->key);
                                cout << "[-]SSL_write() server - " << ret << endl;
                            }
                        }
                        ioData->bioCFlag = TRUE;
                    }
                }
                else
                {
                    spdlog::info("[-]BIO_write() client failed. ID - {}", ioData->key);
                    cout << "[-]BIO_write() client failed" << endl;
                }
            }

            else if (strlen(ioData->sRecvBuffer) > 0 && !ioData->bioSFlag)
            {
                cout << "[+]Bytestransferred server - " << bytesTransferred << " ID - " << ioData->key << endl;
                bioWrite = BIO_write(ioData->srBio, ioData->sRecvBuffer, bytesTransferred);
                if (bioWrite > 0)
                {
                    ioData->serverRecvFlag = FALSE;

                    // spdlog::info("[+]BIO_write() server - {} bytes. ID - {}\n{}", bioWrite, ioData->key, toHex(ioData->sRecvBuffer, bioWrite));
                    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

                    sslRead = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE);

                    if (sslRead <= 0)
                    {
                        error = SSL_get_error(ioData->targetSSL, sslRead);
                        spdlog::info("[-]SSL_read error - {}. ID - {}", error, ioData->key);
                        cout << "[=]SSL_read error - " << error << " ID - " << ioData->key << endl;

                        if ((error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE))
                        {
                            ioData->bytesRecv = 0;
                            ioData->serverRecvFlag = TRUE;
                            memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

                            if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                            {
                                int error = WSAGetLastError();
                                spdlog::info("[-]WSARecv() server IO pending. ID - {}", ioData->key);
                                cout << "[-]WSARecv() server IO - " << error << " ID - " << ioData->key << endl;
                                if (error != WSA_IO_PENDING)
                                {
                                    spdlog::info("[-]WSARecv() server IO - {}. ID - {}", error, ioData->key);
                                    cerr << "[-]WSARecv() server IO - " << error << " ID - " << ioData->key << endl;
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
                                spdlog::info("[+]WSARecv() server IO - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                                cout << "[+]WSARecv() server IO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                            }
                            break;
                        }
                        else if (error == SSL_ERROR_SSL)
                        {
                            spdlog::info("[-]SSL_get_error() SERVER_IO - {}. ID - {}", ERR_error_string(ERR_get_error(), NULL), ioData->key);
                            cout << "[-]SSL_get_error() SERVER_IO - " << ERR_error_string(ERR_get_error(), NULL) << " ID - " << ioData->key << endl;
                            break;
                        }
                        else
                        {
                            spdlog::info("[-]SSL_get_error() SERVER_IO - {}. ID - {}", error, ioData->key);
                            cout << "[+]SSL_get_error() - " << error << endl;
                            break;
                        }
                    }
                    else
                    {
                        if (verbose)
                        {
                            spdlog::info("[+]SSL_read() server - {} bytes. ID - {}", sslRead, ioData->key);
                            cout << "[+]SSL_read() server - " << sslRead << " bytes. ID - " << ioData->key << endl;
                        }
                        spdlog::info("{}", ioData->sRecvBuffer);
                        cout << ioData->sRecvBuffer << endl;
                        sslWrite = SSL_write(ioData->clientSSL, ioData->sRecvBuffer, sslRead);
                        if (sslWrite > 0)
                        {
                            if (verbose)
                            {
                                spdlog::info("[+]SSL_write() client - {} bytes. ID - {}", sslWrite, ioData->key);
                                cout << "[+]SSL_write() client - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                            }
                            memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
                        }
                        else
                        {
                            error = SSL_get_error(ioData->clientSSL, sslWrite);
                            spdlog::info("[-]SSL_write() - {}. ID - {}", error, ioData->key);
                            cout << "[-]SSL_write() - " << error << endl;
                        }
                        while ((sslRead = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE)) > 0)
                        {
                            if (verbose)
                            {
                                spdlog::info("[+]SSL_read() server - {} bytes. ID - {}", sslRead, ioData->key);
                                cout << "[+]SSL_read() server - " << sslRead << " bytes. ID - " << ioData->key << endl;
                            }
                            spdlog::info("{}", ioData->sRecvBuffer);
                            cout << ioData->sRecvBuffer << endl;
                            sslWrite = SSL_write(ioData->clientSSL, ioData->sRecvBuffer, sslRead);
                            if (sslWrite > 0)
                            {
                                if (verbose)
                                {
                                    spdlog::info("[+]SSL_write() client - {} bytes. ID - {}", sslWrite, ioData->key);
                                    cout << "[+]SSL_write() client - " << sslWrite << " bytes. ID - " << ioData->key << endl;
                                }
                                memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
                            }
                            else
                            {
                                error = SSL_get_error(ioData->clientSSL, sslWrite);
                                spdlog::info("[-]SSL_write() client - {}. ID - {}", error, ioData->key);
                                cout << "[-]SSL_write() - " << error << endl;
                            }
                        }
                        ioData->bioSFlag = TRUE;
                    }
                }
                else
                {
                    spdlog::info("[-]BIO_write() server failed");
                    cout << "[-]BIO_write() server failed" << endl;
                }
            }

            if (ioData->bioCFlag)
            {
                memset(ioData->sSendBuffer, '\0', BUFFER_SIZE);
                bioRead = BIO_read(ioData->swBio, ioData->sSendBuffer, BUFFER_SIZE);
                if (bioRead > 0)
                {
                    if (verbose)
                    {
                        spdlog::info("[+]BIO_read() server - {} bytes. ID - {}", bioRead, ioData->key);
                        cout << "[+]BIO_read() server - " << bioRead << " bytes. ID - " << ioData->key << endl;
                    }
                    ioData->wsaServerSendBuf.len = bioRead;

                    if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        error = WSAGetLastError();
                        spdlog::info("[-]WSASend() IO pending. ID - {}", ioData->key);
                        cout << "[-]WSASend() error - " << error << " ID - " << ioData->key << endl;
                        if (error != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]WSASend() failed - {}. ID - {}", error, ioData->key);
                            cerr << "[-]WSASend() failed - " << error << " ID - " << ioData->key << endl;
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
                        spdlog::info("[+]WSASend() server - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                        cout << "[+]WSASend() server - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
                    }
                    break;
                }
                else if (ioData->serverRecvFlag)
                {
                    ioData->bioCFlag = FALSE;
                    break;
                }
                else
                {
                    ioData->bioCFlag = FALSE;
                    ioData->serverRecvFlag = TRUE;
                    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

                    if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        error = WSAGetLastError();
                        spdlog::info("[-]WSARecv() server BIO IO pending ID - {}", ioData->key);
                        cout << "[-]WSARecv() server BIO - " << error << " ID - " << ioData->key << endl;
                        if (error != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]WSARecv() server BIO - {}. ID - {}", error, ioData->key);
                            cerr << "[-]WSARecv() server BIO - " << error << " ID - " << ioData->key << endl;
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
                        spdlog::info("[+]WSARecv() server BIO - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                        cout << "[+]WSARecv() server BIO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                    }
                    break;
                }
            }

            if (ioData->bioSFlag)
            {
                memset(ioData->cSendBuffer, '\0', BUFFER_SIZE);
                bioRead = BIO_read(ioData->cwBio, ioData->cSendBuffer, BUFFER_SIZE);
                if (bioRead > 0)
                {
                    if (verbose)
                    {
                        spdlog::info("[+]BIO_read() client - {} bytes. ID - {}", bioRead, ioData->key);
                        cout << "[+]BIO_read() client - " << bioRead << " bytes. ID - " << ioData->key << endl;
                    }

                    ioData->wsaClientSendBuf.len = bioRead;

                    if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        spdlog::info("[-]WSASend() client BIO IO pending. ID - ", ioData->key);
                        cout << "[-]WSASend() client - " << error << " ID - " << ioData->key << endl;
                        if (error != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]WSASend() client - {}. ID - {}", error, ioData->key);
                            cerr << "[-]WSASend() client - " << error << " ID - " << ioData->key << endl;
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
                        spdlog::info("[+]WSASend() client - {}  bytes. ID - {}", ioData->bytesSend, ioData->key);
                        cout << "[+]WSASend() client - " << ioData->bytesSend << " bytes. ID - " << ioData->key << endl;
                    }
                }
                else if (ioData->clientRecvFlag)
                {
                    ioData->bioSFlag = FALSE;
                    break;
                }
                else
                {
                    ioData->bioSFlag = FALSE;
                    ioData->clientRecvFlag = TRUE;
                    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                    if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                    {
                        int error = WSAGetLastError();
                        spdlog::info("[-]WSARecv() client BIO IO pending. ID - {}", ioData->key);
                        cout << "[-]WSARecv() client BIO - " << error << " ID - " << ioData->key << endl;
                        if (error != WSA_IO_PENDING)
                        {
                            spdlog::info("[-]WSARecv() client BIO - {}. ID - {}", error, ioData->key);
                            cerr << "[-]WSARecv() client BIO - " << error << " ID - " << ioData->key << endl;
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
                        spdlog::info("[+]WSARecv() client BIO - {}  bytes. ID - {}", ioData->bytesRecv, ioData->key);
                        cout << "[+]WSARecv() client BIO - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                    }

                    break;
                }
            }

            if (strlen(ioData->cRecvBuffer) == 0 && !ioData->bioCFlag && !ioData->clientRecvFlag)
            {
                ioData->bioCFlag = FALSE;
                ioData->clientRecvFlag = TRUE;
                memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);

                if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
                {
                    int error = WSAGetLastError();
                    spdlog::info("[-]WSARecv() client IO pending (out). ID - {}", ioData->key);
                    cout << "[-]WSARecv() client IO (out) - " << error << " ID - " << ioData->key << endl;
                    if (error != WSA_IO_PENDING)
                    {
                        spdlog::info("[-]WSARecv() client IO (out) - {}. ID - {}", error, ioData->key);
                        cerr << "[-]WSARecv() client IO (out) - " << error << " ID - " << ioData->key << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        delete ioData;
                        break;
                    }
                }
                else
                {
                    spdlog::info("[+]WSARecv() client IO (out) - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
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
                    spdlog::info("[-]WSARecv() server IO pending (out). ID - {}", ioData->key);
                    cout << "[-]WSARecv() server IO (out) - " << error << " ID - " << ioData->key << endl;
                    if (error != WSA_IO_PENDING)
                    {
                        spdlog::info("[-]WSARecv() server IO (out) - {}. ID - {}", error, ioData->key);
                        cerr << "[-]WSARecv() server IO (out) - " << error << " ID - " << ioData->key << endl;
                        closesocket(ioData->clientSocket);
                        closesocket(ioData->serverSocket);
                        delete ioData;
                        break;
                    }
                }
                else
                {
                    spdlog::info("[+]WSARecv() server IO (out) - {} bytes. ID - {}", ioData->bytesRecv, ioData->key);
                    cout << "[+]WSARecv() server IO (out) - " << ioData->bytesRecv << " bytes. ID - " << ioData->key << endl;
                }

                break;
            }
        }

        default:
            break;
        }
    }

    return 0;
}

VOID cleanupSSL(VOID)
{
    EVP_PKEY_free(caKey);
    X509_free(caCert);
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    spdlog::info("[+]OpenSSL cleaned up.");
}

void CleanupProxyServer()
{
    closesocket(proxySocket); // Close the main proxy socket
    WSACleanup();             // Clean up Winsock
    cleanupSSL();             // Clean up OpenSSL resources

    if (ProxyCompletionPort)
    {
        CloseHandle(ProxyCompletionPort); // Close the completion port handle
    }

    // Additional resource cleanup if needed
    spdlog::info("[+] Proxy server cleanup complete.");
}

VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpArgv)
{
    cout << "[+]ServiceMain start " << endl;

    // Register Service Control Handler Function to SCM
    BOOL bServcieStatus = FALSE;

    hServiceStatusHandle = RegisterServiceCtrlHandler(
        SERVICE_NAME,
        ServiceControlHandler);

    if (hServiceStatusHandle == NULL)
    {
        cout << "[-]RegisterServiceCtrlHandler failed " << GetLastError() << endl;
        return;
    }
    /*else
    {
        cout << "[+]RegisterServiceCtrlHandler success " << endl;
    }*/

    // Set-up ServiceStatus Structure
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    // Call Report Status function for Initial Set-up
    ServiceReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    bServcieStatus = SetServiceStatus(hServiceStatusHandle, &ServiceStatus);

    if (bServcieStatus == FALSE)
    {
        cout << "[-]Initial Set-up failed " << GetLastError() << endl;
    }
    else
    {
        cout << "[+]Initial Set-up done" << endl;
    }

    // call ServiceInit function
    ServiceInit(dwArgc, lpArgv);

    cout << "ServiceMain end" << endl;
}

VOID ServiceControlHandler(DWORD dwControl)
{
    cout << "ServiceControlHandler" << endl;

    switch (dwControl)
    {
    case SERVICE_CONTROL_STOP:
    {
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hServiceStatusHandle, &ServiceStatus);

        // Trigger your server's cleanup logic
        CleanupProxyServer();

        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hServiceStatusHandle, &ServiceStatus);
        break;
    }

    case SERVICE_CONTROL_SHUTDOWN:
    {
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hServiceStatusHandle, &ServiceStatus);

        // Trigger the cleanup logic on shutdown
        CleanupProxyServer();

        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hServiceStatusHandle, &ServiceStatus);
        break;
    }

    default:
        break;
    }
}

VOID ServiceInit(DWORD dwArgc, LPSTR *lpArgv)
{
    hServiceEvent = CreateEvent(
        NULL,  // default security attributes
        TRUE,  // manual reset event
        FALSE, // not signalled
        NULL   // no name
    );

    if (NULL == hServiceEvent)
    {
        ServiceReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    ServiceReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    StartProxyServer();

    while (1)
    {
        WaitForSingleObject(hServiceEvent, INFINITE);

        CleanupProxyServer();

        ServiceReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
}

VOID ServiceReportStatus(
    DWORD dwCurrentState,
    DWORD dwWin32ExitCode,
    DWORD dwWaitHint)
{
    cout << "ServiceReportStatus starts" << endl;

    static DWORD dwcheckPoint = 1;
    BOOL bSetServiceStatus = FALSE;

    // fill the SERVICE_STATUS struct
    ServiceStatus.dwCurrentState = dwCurrentState;
    ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    ServiceStatus.dwWaitHint = dwWaitHint;

    // check the current state of service
    if (dwCurrentState == SERVICE_START_PENDING)
    {
        ServiceStatus.dwControlsAccepted = 0;
    }
    else
    {
        ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
    {
        ServiceStatus.dwCheckPoint = 0;
    }
    else
    {
        ServiceStatus.dwCheckPoint = dwcheckPoint++;
    }

    bSetServiceStatus = SetServiceStatus(hServiceStatusHandle, &ServiceStatus);
    if (FALSE == bSetServiceStatus)
    {
        cout << "SetServiceStatus failed " << GetLastError() << endl;
    }
    else
    {
        cout << "SetServiceStatus success" << endl;
    }
}

VOID ServiceInstall()
{
    SC_HANDLE hScOpenSCManager = NULL;
    SC_HANDLE hScCreateService = NULL;
    DWORD dwGetModuleFileName = 0;
    TCHAR szPath[MAX_PATH];

    // get module file name from SCM
    dwGetModuleFileName = GetModuleFileName(NULL, szPath, MAX_PATH);
    if (0 == dwGetModuleFileName)
    {
        cout << "GetModuleFileName failed " << GetLastError() << endl;
        return;
    }
    else
    {
        cout << "GetModuleFileName success" << endl;
    }

    // open Service Control Manager and get a handle to the SCM database
    hScOpenSCManager = OpenSCManager(
        NULL,                   // machine name - LOCAL MACHINE
        NULL,                   // By default database - SERVICES_ACTIVE_DATABASE
        SC_MANAGER_ALL_ACCESS); // access right
    if (NULL == hScOpenSCManager)
    {
        cout << "OpenSCManager failed " << GetLastError() << endl;
        return;
    }

    // create a Service
    hScCreateService = CreateService(
        hScOpenSCManager,
        SERVICE_NAME,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (NULL == hScCreateService)
    {
        cout << "CreateService failed " << GetLastError() << endl;
        return;
    }
    else
    {
        cout << "Service installed successfully" << endl;
    }

    // close the handles for Service manager and create service
    CloseServiceHandle(hScCreateService);
    CloseServiceHandle(hScOpenSCManager);
}
VOID ServiceDelete()
{
    SC_HANDLE hScOpenSCManager = NULL;
    SC_HANDLE hScOpenService = NULL;
    BOOL bDeleteService = FALSE;

    hScOpenSCManager = OpenSCManager(
        NULL,                   // local computer
        NULL,                   // ServiceActive Database
        SC_MANAGER_ALL_ACCESS); // full access rights
    if (NULL == hScOpenSCManager)
    {
        cout << "OpenSCManager failed " << GetLastError() << endl;
        return;
    }
    else
    {
        cout << "OpenSCManager success" << endl;
    }

    hScOpenService = OpenService(
        hScOpenSCManager,    // SCM database
        SERVICE_NAME,        // name of the service
        SERVICE_ALL_ACCESS); // need delete access
    if (NULL == hScOpenService)
    {
        cout << "OpenService failed " << GetLastError() << endl;
        return;
    }
    else
    {
        cout << "OpenService success" << endl;
    }

    bDeleteService = DeleteService(hScOpenService);
    if (FALSE == bDeleteService)
    {
        cout << "DeleteService failed " << GetLastError() << endl;
        return;
    }
    else
    {
        cout << "DeleteService success" << endl;
    }

    CloseServiceHandle(hScOpenService);
    CloseServiceHandle(hScOpenSCManager);
}

VOID ServiceStart()
{
    BOOL bStartService = TRUE;
    SERVICE_STATUS_PROCESS SvcStatusProcess;
    SC_HANDLE hOpenSCManager = NULL;
    SC_HANDLE hOpenService = NULL;
    BOOL bQueryServiceStatus = TRUE;
    DWORD dwBytesNeeded;
    DWORD dwWaitTime;
    DWORD dwOldCheckPoint;
    DWORD dwStartTickCount;

    hOpenSCManager = OpenSCManager(
        NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS);
    if (NULL == hOpenSCManager)
    {
        cout << "OpenSCManager failed " << GetLastError() << endl;
        return;
    }
    /*else
    {
        cout << "OpenSCManager success" << endl;
    }*/

    hOpenService = OpenService(
        hOpenSCManager,      // SCM database
        SERVICE_NAME,        // name of the service
        SERVICE_ALL_ACCESS); // need delete access
    if (NULL == hOpenService)
    {
        cout << "OpenService failed " << GetLastError() << endl;
        return;
    }
    /*else
    {
        cout << "OpenService success" << endl;
    }*/

    // query about current service status
    bQueryServiceStatus = QueryServiceStatusEx(
        hOpenService,                   // service handle
        SC_STATUS_PROCESS_INFO,         // info level
        (LPBYTE)&SvcStatusProcess,      // buffer
        sizeof(SERVICE_STATUS_PROCESS), // buffer size
        &dwBytesNeeded);                // bytes needed
    if (FALSE == bQueryServiceStatus)
    {
        cout << "QueryServiceStatusEx failed " << GetLastError() << endl;
        return;
    }
    /*else
    {
        cout << "QueryServiceStatusEx success" << endl;
    }*/

    // check if process is running or stopped
    if ((SvcStatusProcess.dwCurrentState == SERVICE_STOPPED) ||
        (SvcStatusProcess.dwCurrentState == SERVICE_STOP_PENDING))
    {
        cout << "Service is already stoped" << endl;
    }
    /*else
    {
        cout << "Service is already running" << endl;
    }*/

    dwStartTickCount = GetTickCount();
    dwOldCheckPoint = SvcStatusProcess.dwCheckPoint;

    // if service is already stopped then query the service
    while (SvcStatusProcess.dwCurrentState == SERVICE_STOP_PENDING)
    {

        dwWaitTime = SvcStatusProcess.dwWaitHint / 10;

        if (dwWaitTime < 1000)
            dwWaitTime = 1000;
        else if (dwWaitTime > 10000)
            dwWaitTime = 10000;

        Sleep(dwWaitTime);

        bQueryServiceStatus = QueryServiceStatusEx(
            hOpenService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&SvcStatusProcess,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded);
        if (FALSE == bQueryServiceStatus)
        {
            cout << "QueryServiceStatusEx failed " << GetLastError() << endl;
            CloseServiceHandle(hOpenService);
            CloseServiceHandle(hOpenSCManager);
        }
        if (SvcStatusProcess.dwCheckPoint > dwOldCheckPoint)
        {
            dwStartTickCount = GetTickCount();
            dwOldCheckPoint = SvcStatusProcess.dwCheckPoint;
        }
        else
        {
            if (GetTickCount() - dwStartTickCount > SvcStatusProcess.dwWaitHint)
            {
                printf("Timeout waiting for service to stop\n");
                CloseServiceHandle(hOpenService);
                CloseServiceHandle(hOpenSCManager);
                return;
            }
        }
    }

    // start the service
    bStartService = StartService(
        hOpenService,
        NULL,
        NULL);
    if (FALSE == bStartService)
    {
        cout << "StartService failed " << GetLastError() << endl;
        CloseServiceHandle(hOpenService);
        CloseServiceHandle(hOpenSCManager);
    }
    else
    {
        cout << "StartService success" << endl;
    }

    bQueryServiceStatus = QueryServiceStatusEx(
        hOpenService,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&SvcStatusProcess,
        sizeof(SERVICE_STATUS_PROCESS),
        &dwBytesNeeded);
    if (FALSE == bQueryServiceStatus)
    {
        cout << "QueryServiceStatusEx failed " << GetLastError() << endl;
        CloseServiceHandle(hOpenService);
        CloseServiceHandle(hOpenSCManager);
    }
    /*else
    {
        cout << "QueryServiceStatusEx success" << endl;
    }*/

    dwStartTickCount = GetTickCount();
    dwOldCheckPoint = SvcStatusProcess.dwCheckPoint;

    while (SvcStatusProcess.dwCurrentState == SERVICE_START_PENDING)
    {
        dwWaitTime = SvcStatusProcess.dwWaitHint / 10;

        if (dwWaitTime < 1000)
            dwWaitTime = 1000;
        else if (dwWaitTime > 10000)
            dwWaitTime = 10000;

        Sleep(dwWaitTime);

        bQueryServiceStatus = QueryServiceStatusEx(
            hOpenService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&SvcStatusProcess,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded);
        if (FALSE == bQueryServiceStatus)
        {
            cout << "QueryServiceStatusEx failed " << GetLastError() << endl;
            CloseServiceHandle(hOpenService);
            CloseServiceHandle(hOpenSCManager);
            break;
        }
        if (SvcStatusProcess.dwCheckPoint > dwOldCheckPoint)
        {
            dwStartTickCount = GetTickCount();
            dwOldCheckPoint = SvcStatusProcess.dwCheckPoint;
        }
        else
        {
            if (GetTickCount() - dwStartTickCount > SvcStatusProcess.dwWaitHint)
            {
                break;
            }
        }
    }

    if (SvcStatusProcess.dwCurrentState == SERVICE_RUNNING)
    {
        cout << "Service running..." << endl;
    }
    else
    {
        cout << "Service running failed " << GetLastError() << endl;
    }

    CloseServiceHandle(hOpenService);
    CloseServiceHandle(hOpenSCManager);
}

VOID ServiceStop()
{
    SERVICE_STATUS_PROCESS SvcStatusProcess;
    SC_HANDLE hScOpenSCManager = NULL;
    SC_HANDLE hScOpenService = NULL;
    BOOL bQueryServiceStatus = TRUE;
    BOOL bControlService = TRUE;
    DWORD dwBytesNeeded;
    DWORD dwWaitTime;
    DWORD dwTimeout = 30000;
    DWORD dwStartTime = GetTickCount();

    hScOpenSCManager = OpenSCManager(
        NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS);
    if (NULL == hScOpenSCManager)
    {
        cout << "OpenSCManager failed " << GetLastError() << endl;
        return;
    }
    /*else
    {
        cout << "OpenSCManager success" << endl;
    }*/

    hScOpenService = OpenService(
        hScOpenSCManager,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS);
    if (NULL == hScOpenService)
    {
        cout << "OpenService failed " << GetLastError() << endl;
    }
    /*else
    {
        cout << "OpenService success" << endl;
    }*/

    bQueryServiceStatus = QueryServiceStatusEx(
        hScOpenService,                 // service handle
        SC_STATUS_PROCESS_INFO,         // info level
        (LPBYTE)&SvcStatusProcess,      // buffer
        sizeof(SERVICE_STATUS_PROCESS), // buffer size
        &dwBytesNeeded);                // bytes needed
    if (FALSE == bQueryServiceStatus)
    {
        cout << "QueryServiceStatusEx failed " << GetLastError() << endl;
    }
    /*else
    {
        cout << "QueryServiceStatusEx success" << endl;
    }*/

    if (SvcStatusProcess.dwCurrentState == SERVICE_STOPPED)
    {
        cout << "Service already stopped" << endl;
        goto stopCleanup;
    }

    while (SvcStatusProcess.dwCurrentState == SERVICE_STOP_PENDING)
    {
        dwWaitTime = SvcStatusProcess.dwWaitHint / 10;

        if (dwWaitTime < 1000)
            dwWaitTime = 1000;
        else if (dwWaitTime > 10000)
            dwWaitTime = 10000;

        Sleep(dwWaitTime);

        bQueryServiceStatus = QueryServiceStatusEx(
            hScOpenService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&SvcStatusProcess,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded);
        if (TRUE == bQueryServiceStatus)
        {
            cout << "QueryService failed " << GetLastError() << endl;
            goto stopCleanup;
        }

        if (SvcStatusProcess.dwCurrentState == SERVICE_STOPPED)
        {
            cout << "Service stopped succesfully" << endl;
            goto stopCleanup;
        }

        if (GetTickCount() - dwStartTime > dwTimeout)
        {
            cout << "Service stop timed out" << endl;
            goto stopCleanup;
        }
    }

    // stop dependent services

    // send a stop code to the SCM
    bControlService = ControlService(
        hScOpenService,
        SERVICE_CONTROL_STOP,
        (LPSERVICE_STATUS)&SvcStatusProcess);
    if (TRUE == bControlService)
    {
        cout << "Service stop success" << endl;
    }
    else
    {
        cout << "ControlService failed " << GetLastError() << endl;
        goto stopCleanup;
    }

    while (SvcStatusProcess.dwCurrentState != SERVICE_STOPPED)
    {
        bQueryServiceStatus = QueryServiceStatusEx(
            hScOpenService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&SvcStatusProcess,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded);
        if (FALSE == bQueryServiceStatus)
        {
            cout << "QueryService failed " << GetLastError() << endl;
            goto stopCleanup;
        }

        if (SvcStatusProcess.dwCurrentState == SERVICE_STOPPED)
        {
            cout << "Service stopped successfully" << endl;
            break;
        }
        else
        {
            cout << "Service stop failed " << GetLastError() << endl;
            goto stopCleanup;
        }
    }

stopCleanup:
    CloseServiceHandle(hScOpenService);
    CloseServiceHandle(hScOpenSCManager);
}