//IP Header File

#pragma once
#ifndef IPHEADER
#define IPHEADER

typedef struct iphdr
{
    unsigned char  ip_header_len : 4;
    unsigned char  ip_version : 4;
    unsigned char  ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;

    unsigned char  ip_frag_offset : 5;

    unsigned char  ip_more_fragment : 1;
    unsigned char  ip_dont_fragment : 1;
    unsigned char  ip_reserved_zero : 1;

    unsigned char  ip_frag_offset1;

    unsigned char  ip_ttl;
    unsigned char  protocol;
    unsigned short ip_checksum;
    unsigned int   ip_srcaddr;
    unsigned int   daddr;
} IPV4_HDR, * PIPV4_HDR, *LPIPV4_HDR, IPHeader;

#endif
