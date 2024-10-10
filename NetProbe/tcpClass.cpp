#include "tcpClass.h"
#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "CommonUtilities.h"
#include "work.h"
#include "tcp_header.h"

#define PACKET_LENGTH 2048

using namespace std;

TCPUtilities::TCPUtilities() {}

unsigned short TCPUtilities::csum(uint8_t* data, int length) 
{
    long checkSum = 0;

    while (length > 0) 
    {
        checkSum += (*data << 8 & 0xFF00) + (*(data + 1) & 0xFF);
        data += 2;
        length -= 2;
    }
    if (checkSum >> 16)
        checkSum = ((checkSum >> 16) & 0x00ff) + (checkSum & 0xFFFF);

    uint16_t finalSum = (uint16_t)(~checkSum);

    return finalSum;
}

uint16_t TCPUtilities::calculateCheckSum(uint32_t ipSource, uint32_t ipDest, uint8_t protocol, uint16_t tcpLength, struct tcp_header tcpSegment) 
{
    char packet[PACKET_LENGTH];
    int checkSumLength = 0;

    memcpy(packet, &ipSource, sizeof(ipSource));
    checkSumLength += sizeof(ipSource);

    memcpy(packet + checkSumLength, &ipDest, sizeof(ipDest));
    checkSumLength += sizeof(ipDest);

    packet[checkSumLength] = 0;
    checkSumLength += 1;

    memcpy(packet + checkSumLength, &protocol, sizeof(protocol));
    checkSumLength += sizeof(protocol);

    memcpy(packet + checkSumLength, &tcpLength, sizeof(tcpLength));
    checkSumLength += sizeof(tcpLength);

    char* tcpheader = (char*)&tcpSegment;
    memcpy(packet + checkSumLength, tcpheader, 20);
    checkSumLength += 20;

    return csum((uint8_t*)packet, checkSumLength);
}


void TCPUtilities::createPacket(string scanType, const char* destIP, const char* portNumber, char* packetData, char* srcIP) 
{
    struct tcp_header* tcp = (struct tcp_header*)packetData;
    memset(tcp, 0, sizeof(struct tcp_header));

    int min = 30000, max = 60000;
    srand(static_cast<unsigned int>(time(nullptr)));
    int sourcePort = min + rand() % (max - min + 1);

    createTCPHeader(tcp, sourcePort, portNumber, scanType);
    tcp->checksum = htons(calculateCheckSum(inet_addr(srcIP), inet_addr(destIP), IPPROTO_TCP, htons(sizeof(struct tcp_header)), *tcp));
}


void TCPUtilities::createTCPHeader(struct tcp_header* tcpHeader, int sourcePort, const char* destPort, string scanType) {
    tcpHeader->source_port = htons(static_cast<uint16_t>(sourcePort));
    tcpHeader->dest_port = htons(static_cast<uint16_t>(atoi(destPort)));
    tcpHeader->syn = 0;
    tcpHeader->sequence = 0;
    tcpHeader->ack = 0;
    tcpHeader->window = htons(1024);
    tcpHeader->checksum = 0;
    tcpHeader->rst = 0;
    tcpHeader->urgent_pointer = 0;
    tcpHeader->data_offset = 5;

    if (scanType == "SYN") {
        tcpHeader->syn = 1;
        tcpHeader->sequence = htonl(1);
    }
    else if (scanType == "XMAS") {
        tcpHeader->psh = 1;
        tcpHeader->urg = 1;
    }
    else if (scanType == "FIN") {
        tcpHeader->fin = 1;
    }
    else if (scanType == "ACK") {
        tcpHeader->ack = 1;
    }
}


void TCPUtilities::sendTCPPacket(Job* job, char* srcIP) 
{
    const char* ip = job->IP.c_str();
    const char* portNumber = job->port.c_str();
    string scanType = job->scanType;
    int probeCounter = 3;
    struct sockaddr_in victim, victim_copy;
    memset(&victim, 0, sizeof(struct sockaddr_in));
    comUtil.buildDestIPStruct(&victim, ip, portNumber);
    memcpy(&victim_copy, &victim, sizeof(victim));
    char packData[PACKET_LENGTH];
    createPacket(scanType, ip, portNumber, packData, srcIP);


    WSADATA wsaData;
    int wsResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsResult != 0) 
    {
        cerr << "WSAStartup failed with error: " << wsResult << endl;
        return;
    }


    SOCKET sockDesc = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockDesc == INVALID_SOCKET) 
    {
        cerr << "Socket creation failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return;
    }

    int status = -1;
    while (status < 0 && probeCounter > 0) 
    {
        if (sendto(sockDesc, packData, sizeof(struct tcp_header), 0, (sockaddr*)&victim, sizeof(struct sockaddr_in)) > 0) 
        {
            status = comUtil.sniffAPacket(ip, portNumber, scanType, IPPROTO_TCP, job, sockDesc, sockDesc); 
        }
        probeCounter--;
    }

    closesocket(sockDesc);
    WSACleanup();

    if (status == 0) 
    {
        static HANDLE createPacketLock = CreateMutex(NULL, FALSE, NULL);
        
        WaitForSingleObject(createPacketLock, INFINITE);
        
        job->serviceVersion = comUtil.getServiceInfo(victim_copy, portNumber);
        
        ReleaseMutex(createPacketLock);
    }

    job->jobStatus = COMPLETED;
}
