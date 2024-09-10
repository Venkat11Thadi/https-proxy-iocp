#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
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

void initializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        cerr << "[-]WSAStartup failed - " << result << endl;
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[+]Winsock initialized" << endl;
    }
}

void initializeOpenSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    cout << "[+]OpenSSL initialized" << endl;
}

string toHex(const char* data, size_t length)
{
    ostringstream oss;

    for (size_t i = 0; i < length; i += 16)
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