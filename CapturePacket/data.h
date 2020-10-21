#pragma once
#include<windef.h>
#pragma pack(1)

struct FrameHeader_t {
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
};

struct IPHeader_t
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD FLAG_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
};

struct Data_t
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
};

#pragma pack()
