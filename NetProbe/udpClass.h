#pragma once
/*
 * UDPUtilities.h
 *
 * Created on: 27-Nov-2014
 * Author: jus-mine
 */

#ifndef UDPUTILITIES_H_
#define UDPUTILITIES_H_

#include <iostream>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include "CommonUtilities.h"
#include "work.h"

#define PACKET_LENGTH 2048

using namespace std;

class UDPUtilities 
{
        //"comUtil" Object of Class "CommonUtilities"
        CommonUtilities comUtil;

    public:
        //Creating UDP Header Content
        void createUDPHeader(struct udphdr* udpHeader, int sourcePort, const char* destPort);
        
        //Creating DNS Header Content
        void createDNSPacket(char* ipAddress, char* packet);
    
        void convertToDNSNameFormat(unsigned char* dnsHeader, char* destinationHost);
    
        //Fills in the UDP Packet
        int createPacketUDP(int sourcePort, const char* destPort, char* destIpAddress, char* packet);
        
        //Send the UDP Packet
        void sendUDPPacket(Job* job);
};

#endif /* UDPUTILITIES_H_ */
