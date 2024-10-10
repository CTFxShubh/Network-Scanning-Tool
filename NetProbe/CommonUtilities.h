#pragma once

#ifndef COMMONUTILITIES_H_
#define COMMONUTILITIES_H_

#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <time.h>
#include "work.h"
#include "pthread.h"

using namespace std;

class CommonUtilities {

public:

    static pthread_mutex_t mutexPoll;
    static pthread_mutex_t mutexPoll2;
    static pthread_mutex_t mutexCreateSocket;

    int sniffAPacket(const char* target, const char* port, string scanType, int protocol, Job* job, SOCKET sockDescProt, SOCKET sockDescICMP);

    static SOCKET createRawSocket(int protocol);

    void buildDestIPStruct(struct sockaddr_in* victim, const char* ip, const char* portNumber);

    string getServiceInfo(struct sockaddr_in victim, const char* port);

    string probeSSHVersion(struct sockaddr_in victim);

    string probeWHOISVersion(struct sockaddr_in victim);

    string probeHTTPVersion(struct sockaddr_in victim);

    string probePOPVersion(struct sockaddr_in victim);

    string probeIMAPVersion(struct sockaddr_in victim);

    string probeSMTPVersion(struct sockaddr_in victim);

    bool checkIfIPMatch(const char* ip, struct iphdr* ptrToIPHeader);

    int lookIntoThePacket(const char* ip, const char* portNumber, char* ptrToRecievedPacket, string scanType, Job* job);

    int parseUDPResponse(const char* ip, const char* portNumber, unsigned char* ptrToRecievedPacket, Job*);

    int parseICMPResponse(const char* ip, const char* portNumber, unsigned char* sockReadBuffer, Job* job);

    int ParseTCPResponse(const char* ip, const char* portNumber, unsigned char* ptrToRecievedPacket, string scanType, Job* job);

    SOCKET bindRawSocket(int protocol, struct sockaddr_in* victim, const char* ip);
};

#endif /* COMMONUTILITIES_H_ */
