#pragma once

#include <stdio.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iterator>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <list>
#include <sstream>
#include "getopt.h"
#include <errno.h>
#include <fstream>

using namespace std;

class optionsManager {

	map<string, string> optionDict;
	
	static optionsManager* m_optManager;
	
	vector<string> scanList;
	
	vector<string> portList;
	
	vector<string> ipList;

public:

	void readOptions(int argc, char* argv[]);
	
	static optionsManager* Instance();
	
	string GetStandardUsageOptionScreen();
	
	map<string, string> getOptionDictionary();
	
	//void setPeerInfo(int numOfPeers, char* ptrToPeerString);
	
	//ist<string> getpeerInfoList();
	
	vector<string> split(string input, char delimiter);
	
	vector<string> getScanList();
	
	void unRollPortRange();
	
	
	void calculateIPaddresesBitwise(const char* ipWithPrefix);
	
	void printHostAddresses(unsigned long networkAddress, unsigned long broadcastAddress);
	
	void processIPFile(string fContent);
	
	vector<string> getIPList();
	
	vector<string> getPortList();
	
	void deleteAllList();
	
	void deleteSingleTon();
	string ReadIPFile(const char* filename);
};
