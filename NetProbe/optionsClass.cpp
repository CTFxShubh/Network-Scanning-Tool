#include "optionsClass.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <cstring>
#include <cstdlib>
#include <winsock2.h>
#include <WS2tcpip.h>
#include "getopt.h"

using namespace std;

optionsManager* optionsManager::m_optManager = NULL;


void optionsManager::readOptions(int argc, char* argv[])
{
    int getOptChar = 0;
    int option_index = 0;
    const char* shortOptions = "hp:i:r:f:s:u:";
    
    struct option longOptions[] =
    {
        {"help",          no_argument,       NULL, 'h'},
        {"ports",         required_argument, NULL, 'p'},
        {"ip",            required_argument, NULL, 'i'},
        {"prefix",        required_argument, NULL, 'x'},
        {"file",          required_argument, NULL, 'f'},
        {"scan",          required_argument, NULL, 's'},
        {"speedup",       required_argument, NULL, 'u'},
        {NULL,            0,                 NULL, 0  }
    };

    while ((getOptChar = getopt_long(argc, argv, shortOptions, longOptions, &option_index)) != -1) 
    {
        switch (getOptChar) 
        {
        case 'h':
            optionDict.insert(pair<string, string>("help", GetStandardUsageOptionScreen()));
            break;
        case 'p':
            optionDict.insert(pair<string, string>("ports", optarg));
            portList = split(optarg, ',');
            break;
        case 'i':
            optionDict.insert(pair<string, string>("ip", optarg));
            ipList.push_back(string(optarg));
            break;
        case 'x':
            optionDict.insert(pair<string, string>("prefix", optarg));
            break;
        case 'f':
            optionDict.insert(pair<string, string>("ipaddressfile", optarg));
            break;
        case 's':
            optionDict.insert(pair<string, string>("scan", optarg));
            if (strcmp(optarg, "SYN") == 0 || strcmp(optarg, "NULL") == 0
                || strcmp(optarg, "ACK") == 0 || strcmp(optarg, "UDP") == 0
                || strcmp(optarg, "XMAS") == 0 || strcmp(optarg, "FIN") == 0) {
                scanList.push_back(optarg);
            }
            else {
                cout << "INVALID SCAN " << endl;
                exit(0);
            }
            break;
        case 'u':
            optionDict.insert(pair<string, string>("speedup", optarg));
            break;
        default:
            fprintf(stderr, "ERROR: Unknown option '-%c'\n", getOptChar);
            exit(1);
        }
    }

    if (portList.size() == 0) 
    {
        portList = split("1-1024", ',');
    }

    if (optind < argc) 
    {
        while (optind < argc) 
        {
            if (strcmp(argv[optind], "SYN") == 0 || strcmp(argv[optind], "NULL") == 0
                || strcmp(argv[optind], "ACK") == 0 || strcmp(argv[optind], "UDP") == 0
                || strcmp(argv[optind], "XMAS") == 0 || strcmp(argv[optind], "FIN") == 0) {
                scanList.push_back(argv[optind++]);
            }
            else 
            {
                optind++;
            }
        }
    }

    unRollPortRange();
}

optionsManager* optionsManager::Instance()
{
    if (!m_optManager)
        m_optManager = new optionsManager();
    return m_optManager;
}

vector<string> optionsManager::split(string input, char delimiter) 
{
    stringstream ss(input);
    vector<string> outputList;
    string temp;

    while (getline(ss, temp, delimiter)) 
    {
        outputList.push_back(temp);
    }

    return outputList;
}

void optionsManager::unRollPortRange() 
{
    vector<string> tempList;
    for (auto& port : portList) 
    {
        size_t pos = port.find('-');
        if (pos != string::npos) 
        {
            int start = stoi(port.substr(0, pos));
            int end = stoi(port.substr(pos + 1));
            
            for (int i = start; i <= end; ++i) 
            {
                tempList.push_back(to_string(i));
            }
        }
        else 
        {
            tempList.push_back(port);
        }
    }
    portList.swap(tempList);
}

string optionsManager::GetStandardUsageOptionScreen() 
{
    return  "./portScanner [option1, ..., optionN] \n \
            --help. Example: “./portScanner --help”.\n \
            --ports <ports to scan>. Example: “./portScanner --ports 1,2,3-5”.\n \
            --ip <IP address to scan>. Example: “./portScanner --ip 127.0.0.1”.\n \
            --prefix <IP prefix to scan>. Example: “./portScanner --prefix 127.143.151.123/24”.\n \
            --file <file name containing IP addresses to scan>. Example: “./portScanner --file filename.txt”.\n \
            --speedup <parallel threads to use>. Example: “./portScanner --speedup 10”. \n \
            --scan <one or more scans>. Example: “./portScanner --scan SYN NULL FIN XMAS”.\n";
}

map<string, string> optionsManager::getOptionDictionary() 
{
    return optionDict;
}

vector<string> optionsManager::getScanList() 
{
    return scanList;
}

vector<string> optionsManager::getIPList() 
{
    return ipList;
}

vector<string> optionsManager::getPortList() 
{
    return portList;
}

void optionsManager::deleteAllList() 
{
    ipList.clear();
    portList.clear();
    scanList.clear();
    optionDict.clear();
}

void optionsManager::deleteSingleTon() 
{
    delete m_optManager;
}

void optionsManager::printHostAddresses(unsigned long networkAddress, unsigned long broadcastAddress) 
{
    struct in_addr address;
    
    for (unsigned long i = ntohl(networkAddress) + 1; i < ntohl(broadcastAddress); ++i) 
    {
        address.s_addr = htonl(i);
        ipList.push_back(string(inet_ntoa(address)));
    }
}

void optionsManager::calculateIPaddresesBitwise(const char* ipWithPrefix) 
{
    struct in_addr ipaddress;
    struct in_addr ipMask;
    
    char* inputIP;
    
    int prefix;
    unsigned long networkID, hostBits, broadcastID;

    char* pch = strtok((char*)ipWithPrefix, "/");
    inputIP = pch;
    pch = strtok(NULL, "/");
    sscanf(pch, "%d", &prefix);

    inet_pton(AF_INET, inputIP, &ipaddress);
    unsigned long subnetMask = 0;
    for (int i = 0; i < prefix; ++i) 
    {
        subnetMask |= 1 << (31 - i);
    }

    ipMask.s_addr = htonl(subnetMask);
    
    networkID = ntohl(ipaddress.s_addr) & ntohl(ipMask.s_addr);
    ipaddress.s_addr = htonl(networkID);
    
    ipList.push_back(inet_ntoa(ipaddress));
    hostBits = ~ntohl(ipMask.s_addr);
    
    broadcastID = networkID | hostBits;
    ipaddress.s_addr = htonl(broadcastID);
    
    ipList.push_back(inet_ntoa(ipaddress));
    printHostAddresses(networkID, broadcastID);
}

void optionsManager::processIPFile(string fileName) 
{
    string fileContent = ReadIPFile(fileName.c_str());
    if (!fileContent.empty()) 
    {
        istringstream iss(fileContent);
        string line;
        while (getline(iss, line)) 
        {
            ipList.push_back(line);
        }
    }
}

string optionsManager::ReadIPFile(const char* filename) 
{
    ifstream file(filename);
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}   
