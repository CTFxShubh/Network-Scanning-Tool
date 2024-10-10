#include "work.h"

void Job::setJob(void* (*fptr)(void*)) 
{
	funcPointer = fptr;
}


void Job::execute() 
{
	(*funcPointer)(this);
}

Job::Job(string ipAddress, string portNum, string scan) 
{
	IP = ipAddress;
	port = portNum;
	scanType = scan;
	jobStatus = NOTNOW;
	serviceName = "NA";
	serviceVersion = "NA";
	conclusion = "NOTAVAILABLE";
}

Job::Job() {}

Job::~Job() {};
