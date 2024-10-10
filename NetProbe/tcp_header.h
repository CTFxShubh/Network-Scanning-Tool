#pragma once

#ifndef TCPHEADER
#define TCPHEADER

// TCP header
typedef struct tcp_header
{
    unsigned short source_port;   // source port
    unsigned short dest_port;     // destination port
    unsigned int sequence;        // sequence number - 32 bits
    unsigned int acknowledge;     // acknowledgement number - 32 bits

    unsigned char ns : 1;          //Nonce Sum Flag Added in RFC 3540.
    unsigned char reserved_part1 : 3; //according to rfc
    unsigned char data_offset : 4;    /*The number of 32-bit words
                                      in the TCP header.
                                      This indicates where the data begins.
                                      The length of the TCP header
                                      is always a multiple
                                      of 32 bits.*/

    unsigned char fin : 1; //Finish Flag
    unsigned char syn : 1; //Synchronise Flag
    unsigned char rst : 1; //Reset Flag
    unsigned char psh : 1; //Push Flag
    unsigned char ack : 1; //Acknowledgement Flag
    unsigned char urg : 1; //Urgent Flag

    unsigned char ecn : 1; //ECN-Echo Flag
    unsigned char cwr : 1; //Congestion Window Reduced Flag

    ////////////////////////////////

    unsigned short window; // window
    unsigned short checksum; // checksum
    unsigned short urgent_pointer; // urgent pointer
} TCP_HDR, * PTCP_HDR, *LPTCP_HDR , TCPHeader, TCP_HEADER;

#endif // !TCPHEADER
