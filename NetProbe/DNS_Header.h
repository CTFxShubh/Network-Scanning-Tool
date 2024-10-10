#pragma once

#ifndef DNS_HEADER_H_
#define DNS_HEADER_H_

typedef struct
{
	unsigned short id;
	unsigned char rd : 1;
	unsigned char tc : 1;
	unsigned char aa : 1;
	unsigned char opcode : 4;
	unsigned char qr : 1;
	unsigned char rcode : 4;
	unsigned char cd : 1;
	unsigned char ad : 1;
	unsigned char z : 1;
	unsigned char ra : 1;
	unsigned short q_count;
	unsigned short ans_count;
	unsigned short auth_count;
	unsigned short add_count;
} DNS_HEADER;


typedef struct
{
	unsigned short qtype;
	unsigned short qclass;
} QUESTION;

#endif
