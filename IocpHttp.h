#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
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
#include <winsock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096

bool verbose = true;
static int ID = 0;

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

typedef enum MODE
{
    CLIENT,
    SERVER,
};

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