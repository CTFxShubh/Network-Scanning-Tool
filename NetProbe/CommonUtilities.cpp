#include "CommonUtilities.h"
#include "tcp_header.h"
#include "ip_header.h"
#include "icmp_header.h"
#include "udp_header.h"
#include "work.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

int CommonUtilities::sniffAPacket(const char* target, const char* portNumber, string scanType, int protocol, Job* job, SOCKET sockDescProt, SOCKET sockDescICMP) {

	int status = -1;
	u_long mode = 1;
	
	ioctlsocket(sockDescProt, FIONBIO, &mode);
	ioctlsocket(sockDescICMP, FIONBIO, &mode);
	
	struct pollfd fileDesc[2];
	struct sockaddr_in recievedIPStruct;
	
	memset(&recievedIPStruct, 0, sizeof(recievedIPStruct));
	
	fileDesc[0].fd = sockDescProt; fileDesc[0].events = POLLIN;
	fileDesc[1].fd = sockDescICMP; fileDesc[1].events = POLLIN;
	
	int pollStat = WSAPoll(fileDesc, 2, 4000);
	int packetRecievedType = -1, recievedSize = -1; int supposedToBeRecievedPacket = -1;
	
	socklen_t size = sizeof(recievedIPStruct);
	
	const int MAX_RECIEVED_PACKET_LENGTH = 200;
	char sockReadBuffer[MAX_RECIEVED_PACKET_LENGTH];
	
	memset(sockReadBuffer, '\0', MAX_RECIEVED_PACKET_LENGTH);
	
	time_t startTime = time(0);
	double timeout = 4;

	while (pollStat == 1) {

		time_t current = time(0);
		double timeElapsed = difftime(current, startTime);

		if (timeElapsed > timeout) {
			break;
		}
		if (fileDesc[0].revents & POLLIN) {
			recievedSize = recvfrom(sockDescProt, sockReadBuffer, MAX_RECIEVED_PACKET_LENGTH, 0, (sockaddr*)&recievedIPStruct, &size);
		}
		if (fileDesc[1].revents & POLLIN) {
			recievedSize = recvfrom(sockDescICMP, sockReadBuffer, MAX_RECIEVED_PACKET_LENGTH, 0, (sockaddr*)&recievedIPStruct, &size);
		}
		if (recievedSize > 0) {
			status = lookIntoThePacket(target, portNumber, sockReadBuffer, scanType, job);
			if (status >= 0)
				break;
		}
	}

	return status;
}

SOCKET CommonUtilities::createRawSocket(int protocol)
{
	SOCKET sockfd = INVALID_SOCKET;
	while (sockfd == INVALID_SOCKET)
		sockfd = socket(AF_INET, SOCK_RAW, protocol);
	if (sockfd != INVALID_SOCKET) {
		BOOL optval = TRUE;
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));
	}
	return sockfd;
}

int CommonUtilities::lookIntoThePacket(const char* ip, const char* portNumber, char* sockReadBuffer, string scanType, Job* job)
{
	int status = -1;
	
	struct iphdr* ptrToIPHeader = NULL;
	struct tcp_header* ptrToTCPHeader = NULL;
	struct sockaddr_in ipSource {};
	struct servent* ptrToserviceInfo = NULL;
	
	unsigned char* ptrToRecievedPacket = NULL;
	
	ptrToRecievedPacket = (unsigned char*)sockReadBuffer;
	ptrToIPHeader = (struct iphdr*)ptrToRecievedPacket;
	ptrToRecievedPacket += sizeof(iphdr);

	if (checkIfIPMatch(ip, ptrToIPHeader)) {

		if (ptrToIPHeader->protocol == IPPROTO_TCP)
			status = ParseTCPResponse(ip, portNumber, ptrToRecievedPacket, scanType, job);
		else if (ptrToIPHeader->protocol == IPPROTO_UDP)
			status = parseUDPResponse(ip, portNumber, ptrToRecievedPacket, job);
		else if (ptrToIPHeader->protocol == IPPROTO_ICMP)
			status = parseICMPResponse(ip, portNumber, ptrToRecievedPacket, job);
	}
	else if (ptrToIPHeader->protocol == IPPROTO_ICMP)
		status = parseICMPResponse(ip, portNumber, ptrToRecievedPacket, job);

	return status;
}

bool CommonUtilities::checkIfIPMatch(const char* ip, struct iphdr* ptrToIPHeader)
{
	struct sockaddr_in ipSource;
	memset(&ipSource, 0, sizeof(ipSource));
	ipSource.sin_addr.s_addr = ptrToIPHeader->ip_srcaddr;
	
	if (strcmp(ip, inet_ntoa(ipSource.sin_addr)) == 0) {
		return true;
	}
	return false;
}

int CommonUtilities::parseUDPResponse(const char* ip, const char* portNumber, unsigned char* ptrToRecievedPacket, Job* job) {
	int status = -1;
	struct udphdr* udpHeader = NULL;
	udpHeader = (struct udphdr*)ptrToRecievedPacket;
	if (atoi(portNumber) == ntohs(udpHeader->source)) {
		job->scanResult = "Open";
		status = 0;
	}
	return status;
}

int CommonUtilities::ParseTCPResponse(const char* ip, const char* portNumber, unsigned char* ptrToRecievedPacket, string scanType, Job* job)
{
	int status = -1;
	
	struct tcp_header* ptrToTCPHeader = NULL;
	struct servent* ptrToserviceInfo = NULL;
	
	ptrToTCPHeader = (struct tcp_header*)ptrToRecievedPacket;
	ptrToRecievedPacket += ptrToTCPHeader->data_offset * 4;
	
	if (atoi(portNumber) == ntohs(ptrToTCPHeader->source_port)) {

		if (scanType == "SYN") {

			if (ptrToTCPHeader->rst == 1) {
				job->scanResult = "Closed";
				status = 1;
			}
			if (ptrToTCPHeader->syn == 1 && ptrToTCPHeader->ack == 1) {
				job->scanResult = "Open";
				status = 0;
			}
		}
		else if (scanType == "ACK") {
			if (ptrToTCPHeader->rst == 1) {
				job->scanResult = "Unfiltered";
				status = 1;
			}
		}
		else if (scanType == "NULL" || scanType == "XMAS" || scanType == "FIN") {
			if (ptrToTCPHeader->rst == 1) {
				job->scanResult = "Closed";
				status = 1;
			}
		}
	}
	return status;
}

int CommonUtilities::parseICMPResponse(const char* ip, const char* portNumber, unsigned char* ptrToPacketData, Job* job)
{
	struct sockaddr_in ipDest;
	memset(&ipDest, 0, sizeof(ipDest));
	int status = -1;
	bool flag = true;
	struct icmphdr* icmpPtr = (struct icmphdr*)ptrToPacketData;
	ptrToPacketData += sizeof(struct icmphdr);
	struct iphdr* ipHeader = (struct iphdr*)ptrToPacketData;
	ptrToPacketData += sizeof(struct iphdr);
	ipDest.sin_addr.s_addr = ipHeader->daddr;
	if (strcmp(inet_ntoa(ipDest.sin_addr), ip) == 0)
	{
		if (ipHeader->protocol == IPPROTO_TCP)
		{
			struct tcp_header* tcpHeader = (struct tcp_header*)ptrToPacketData;
			if (atoi(portNumber) == ntohs(tcpHeader->dest_port))
				status = 1;
		}
		else if (ipHeader->protocol == IPPROTO_UDP)
		{
			struct udphdr* udpHeader = (struct udphdr*)ptrToPacketData;
			if (atoi(portNumber) == ntohs(udpHeader->dest)) {
				status = 1;
				flag = false;
			}
		}
		if (status == 1)
		{
			if (flag && icmpPtr->type == 3 && (icmpPtr->code == 1 || icmpPtr->code == 2 || icmpPtr->code == 3 || icmpPtr->code == 9 || icmpPtr->code == 10 || icmpPtr->code == 13))
				job->scanResult = "Filtered";
			else if (!flag && icmpPtr->type == 3 && (icmpPtr->code == 1 || icmpPtr->code == 2 || icmpPtr->code == 9 || icmpPtr->code == 10 || icmpPtr->code == 13))
				job->scanResult = "Filtered";
			else if (!flag && icmpPtr->type == 3 && icmpPtr->code == 3)
				job->scanResult = "Closed";
		}
	}
	return status;
}

string CommonUtilities::probeHTTPVersion(sockaddr_in victim)
{
	int newSock;
	
	string getRequest;
	stringstream ss;
	
	int sentBytes, recievedSize = -1, versionLen;
	char sockReadBuffer[100];
	
	memset(sockReadBuffer, '\0', sizeof(sockReadBuffer));
	ss << "GET / HTTP/1.1 \r\nHost: " << inet_ntoa(victim.sin_addr) << "\r\nConnection: close\r\n\r\n";
	
	getRequest = ss.str();
	string stringedData;
	size_t bytesToRead{}, bytesRead{};
	
	struct timeval timeout;
	fd_set fileDesc;

	memset(&timeout, 0, sizeof(timeout));
	newSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	int status = connect(newSock, (struct sockaddr*)&victim, sizeof(victim));
	if (status == -1)
	{
		closesocket(newSock);
		return "No response";
	}
	
	timeout.tv_sec = 10; timeout.tv_usec = 0;
	
	FD_ZERO(&fileDesc);
	FD_SET(newSock, &fileDesc);
	
	sentBytes = send(newSock, getRequest.c_str(), getRequest.length(), 0);
	bytesToRead = sizeof(sockReadBuffer) - 1;
	
	status = 0;
	
	while (status < bytesToRead)
	{
		status = select(newSock + 1, &fileDesc, NULL, NULL, &timeout);
		if (status > 0)
			status = recv(newSock, &sockReadBuffer[status], bytesToRead - status, 0);
	}
	closesocket(newSock);
	
	stringedData = sockReadBuffer;
	versionLen = stringedData.find("HTTP/1.1");
	
	if (versionLen != string::npos)
	{
		versionLen = stringedData.find("\r\n", versionLen);
		if (versionLen != string::npos)
			return stringedData.substr(0, versionLen);
	}
	return "No response";
}

string CommonUtilities::probeSMTPVersion(sockaddr_in victim) {
	
	char smtpRequest[10] = "EHLO\n";
	char sockReadBuffer[1000];
	
	int recievedSize = -1, sentBytes{}, versionLen = 1000;
	
	size_t pos{}, pos1{};
	
	memset(sockReadBuffer, '\0', sizeof(sockReadBuffer));
	
	int newSock;
	string stringedData;
	
	newSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	if (connect(newSock, (struct sockaddr*)&victim, sizeof(victim)) == 0) {
		recievedSize = recv(newSock, sockReadBuffer, 2048, 0);
		if (recievedSize < 0)
			return string("ERROR");
		else {
			stringedData = string(sockReadBuffer);
			if ((pos = stringedData.find("220")) != string::npos) {
				versionLen = stringedData.length() - pos;
				const int tup = 10000;
				char temp[tup];
				stringedData.copy(temp, versionLen, pos + strlen("220"));
				temp[versionLen] = '\0';
				stringedData = string(temp);
			}
		}
	}
	return stringedData;
}

string CommonUtilities::getServiceInfo(struct sockaddr_in victim, const char* port) {
	
	string versionInfo;
	
	switch (atoi(port)) {
	case 22: versionInfo = probeSSHVersion(victim); break;
	case 43: versionInfo = probeWHOISVersion(victim); break;
	case 80: versionInfo = probeHTTPVersion(victim); break;
	case 110: versionInfo = probePOPVersion(victim); break;
	case 143: versionInfo = probeIMAPVersion(victim); break;
	case 587: versionInfo = probeSMTPVersion(victim); break;
	}
	return versionInfo;
}

SOCKET CommonUtilities::bindRawSocket(int protocol, struct sockaddr_in* victim, const char* ip)
{
	SOCKET sock = socket(AF_INET, SOCK_RAW, protocol);
	
	struct timeval timeout;
	timeout.tv_sec = 10; timeout.tv_usec = 0;
	
	memset(&timeout, 0, sizeof(timeout));
	
	if (sock == -1)
		return -1;
	if (protocol == IPPROTO_TCP)
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (const char*)&timeout, sizeof(timeout)) == -1)
			return -1;
	if (protocol == IPPROTO_ICMP)
		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == -1)
			return -1;
	if (protocol == IPPROTO_UDP)
		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) == -1)
			return -1;
	memset(victim, 0, sizeof(struct sockaddr_in));
	victim->sin_family = AF_INET;
	victim->sin_addr.s_addr = inet_addr(ip);
	return sock;
}

void CommonUtilities::buildDestIPStruct(struct sockaddr_in* victim, const char* ip, const char* portNumber) {

	victim->sin_family = AF_INET;
	victim->sin_port = htons(atoi(portNumber));
	victim->sin_addr.s_addr = inet_addr(ip);
}

string CommonUtilities::probeSSHVersion(sockaddr_in victim) {
	char sockReadBuffer[50];
	int recievedSize = -1;
	
	memset(sockReadBuffer, '\0', 50);
	
	int newSock;
	string stringedData;
	
	newSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	if (connect(newSock, (struct sockaddr*)&victim, sizeof(victim)) == 0) {
		recievedSize = recv(newSock, sockReadBuffer, 50, 0);
		if (recievedSize < 0)
			return string("ERROR");
		else {
			stringedData = string(sockReadBuffer);
		}
	}
	return stringedData;
}

string CommonUtilities::probeWHOISVersion(sockaddr_in victim) {
	
	char sockReadBuffer[512];
	memset(sockReadBuffer, '\0', 512);
	
	int recievedSize = -1, sentBytes{}, versionLen{} ;
	size_t pos{}, pos1{};
	
	string stringedData;
	
	int newSock;
	
	memset(sockReadBuffer, '\0', sizeof(sockReadBuffer));
	newSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	if (connect(newSock, (struct sockaddr*)&victim, sizeof(victim)) == 0) {
		recievedSize = recv(newSock, sockReadBuffer, 511, 0);
		if (recievedSize < 0)
			return string("ERROR");
		else {
			stringedData = string(sockReadBuffer);

			if ((pos = stringedData.find("Version")) != string::npos) {
				versionLen = pos1 - (pos + strlen("Version "));
				char temp[7];
				memset(temp, '\0', 7);
				stringedData.copy(temp, 6, pos + strlen("Version "));
				stringedData = string(temp);
			}
		}
	}
	return stringedData;
}

string CommonUtilities::probePOPVersion(sockaddr_in victim) {
	char popRequest[10] = "ABCD";
	char sockReadBuffer[100];
	int recievedSize = -1, sentBytes = 0, versionLen;
	size_t pos, pos1;
	memset(sockReadBuffer, '\0', sizeof(sockReadBuffer));
	int newSock; string stringedData;
	newSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect(newSock, (struct sockaddr*)&victim, sizeof(victim)) == 0) {

		sentBytes = send(newSock, popRequest, 22, 0);
		recievedSize = recv(newSock, sockReadBuffer, 100, 0);
		stringedData = string(sockReadBuffer);
		if (recievedSize < 0)
			return string("ERROR");
		else {
			if ((pos = stringedData.find("+OK")) != string::npos) {
				if ((pos1 = stringedData.find("ready")) != string::npos) {
					versionLen = pos1 - (pos + strlen("+OK "));
					const int tup = 10000;
					char temp[tup];
					stringedData.copy(temp, versionLen, pos + strlen("+OK "));
					temp[versionLen] = '\0';
					stringedData = string(temp);
				}
			}
		}
	}
	return stringedData;
}

string CommonUtilities::probeIMAPVersion(sockaddr_in victim) {
	
	char imapRequest[10] = "\r\n";
	char sockReadBuffer[2048];
	
	int recievedSize = -1, sentBytes{}, versionLen{} ;
	size_t pos, pos1;
	int newSock;
	
	string stringedData;
	memset(sockReadBuffer, '\0', sizeof(sockReadBuffer));
	
	newSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	if (connect(newSock, (struct sockaddr*)&victim, sizeof(victim)) == 0) {
		recievedSize = recv(newSock, sockReadBuffer, 2048, 0);
		if (recievedSize < 0)
			return string("ERROR");
		else {
			stringedData = string(sockReadBuffer);
			if ((pos = stringedData.find("]")) != string::npos) {
				if ((pos1 = stringedData.find("ready")) != string::npos) {
					versionLen = pos1 - (pos + strlen("] "));
					const int tup = 10000;
					char temp[tup];
					stringedData.copy(temp, versionLen, pos + strlen("] "));
					temp[versionLen] = '\0';
					stringedData = string(temp);
				}
			}

		}
	}
	return stringedData;
}