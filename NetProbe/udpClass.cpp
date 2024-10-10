#include "udpClass.h"
#include "DNS_Header.h"
#include "udp_header.h"
#include "work.h"

void UDPUtilities::createUDPHeader(struct udphdr* udpHeader, int sourcePort, const char* destPort) 
{
    udpHeader->source = htons(sourcePort);
    udpHeader->dest = htons(atoi(destPort));
    udpHeader->length = htons(sizeof(struct udphdr));
    udpHeader->checksum = 0;
}

void UDPUtilities::createDNSPacket(char* ipAddress, char* packet) 
{
    DNS_HEADER* dnsHeader = (DNS_HEADER*)packet;
    
    dnsHeader->id = htons(rand());
    dnsHeader->qr = 0;
    dnsHeader->opcode = 0;
    dnsHeader->aa = 0;
    dnsHeader->tc = 0;
    dnsHeader->rd = 1;
    dnsHeader->ra = 0;
    dnsHeader->z = 0;
    dnsHeader->ad = 0;
    dnsHeader->cd = 0;
    dnsHeader->rcode = 0;
    dnsHeader->q_count = htons(1);
    dnsHeader->ans_count = 0;
    dnsHeader->auth_count = 0;
    dnsHeader->add_count = 0;
}

void UDPUtilities::convertToDNSNameFormat(unsigned char* dnsHeader, char* destinationHost) 
{
    unsigned char* rvIterator = dnsHeader;
    int count = 0;
    
    while (*destinationHost) 
    {
        if (*destinationHost == '.') 
        {
            *rvIterator++ = count;
            count = 0;
        }
        
        else 
        {
            *rvIterator++ = *destinationHost;
            count++;
        }
        destinationHost++;
    }
    *rvIterator++ = count;
    *rvIterator = '\0';
}

int UDPUtilities::createPacketUDP(int sourcePort, const char* destPort, char* destIpAddress, char* packet) 
{
    struct udphdr* udpPack = (struct udphdr*)packet;
    
    size_t totalSize = sizeof(struct udphdr);
    
    createUDPHeader(udpPack, sourcePort, destPort);
    if (strcmp(destPort, "53") == 0) 
    {
        createDNSPacket(destIpAddress, packet + sizeof(struct udphdr));
    }
    return totalSize;
}

void UDPUtilities::sendUDPPacket(Job* job) 
{
    const char* destPort = job->port.c_str();
    const char* destIpAddress = job->IP.c_str();
    string scanType = job->scanType;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
    {
        cout << "Failed to initialize Winsock.\n";
        return;
    }

    SOCKET sockDesc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockDesc == INVALID_SOCKET) {
        cout << "Socket creation failed.\n";
        WSACleanup();
        return;
    }

    char packData[PACKET_LENGTH];
    
    memset(packData, 0, PACKET_LENGTH);
    size_t totalSize = sizeof(struct udphdr);
    
    int min = 30000, max = 60000;
    srand((unsigned int)time(NULL));
    
    int sourcePort = min + rand() % (max - min + 1);
    totalSize = createPacketUDP(sourcePort, destPort, (char*)destIpAddress, packData);

    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(atoi(destPort));
    destAddr.sin_addr.s_addr = inet_addr(destIpAddress);

    int bytesSent = sendto(sockDesc, packData, totalSize, 0, (struct sockaddr*)&destAddr, sizeof(destAddr));
    if (bytesSent == SOCKET_ERROR) {
        cout << "Send failed with error: " << WSAGetLastError() << "\n";
    }

    closesocket(sockDesc);
    WSACleanup();

    job->jobStatus = COMPLETED;
}
