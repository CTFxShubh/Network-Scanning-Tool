#pragma once
/*
 * TCPUtilities.h
 *
 * Created on: 27-Nov-2014
 * Author: jus-mine
 */

#ifndef TCPUTILITIES_H_
#define TCPUTILITIES_H_

#include <string>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iostream>
#include <sstream>
#include <process.h> // For _beginthreadex
#include <errno.h>
#include "CommonUtilities.h"
#include "work.h"

#define PACKET_LENGTH 2048

using namespace std;

class TCPUtilities 
{   
    //"comUtil" Object of Class "CommonUtilities"
    CommonUtilities comUtil;

    HANDLE createPacketLock = CreateMutex(NULL, FALSE, NULL); // Windows equivalent for pthread_mutex_t

public:

    //Default Constructor
    TCPUtilities();

    unsigned short csum(uint8_t* data, int length);
    
    //CheckSum Calculator 
    uint16_t calculateCheckSum(uint32_t ipSource, uint32_t ipDest, uint8_t protocol, uint16_t tcpLength, struct tcp_header tcpSegment);
    
    //Packet Creation
    void createPacket(string scanType, const char* destIP, const char* portNumber, char*, char*);
    
    //TCP Header Creater
    void createTCPHeader(struct tcp_header* tcpHeader, int sourcePort, const char* destPort, string scanType);
    
    //Send TCP Packet 
    void sendTCPPacket(Job* job, char*);
};

#endif /* TCPUTILITIES_H_ */
