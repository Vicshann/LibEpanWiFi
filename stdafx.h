// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include "wireshark.h"
#include <epan/epan_dissect.h>
#include <epan/column.h>
#include <frame_tvbuff.h>
#include "pcapio.h"

#include "WSEpan.h"



#pragma pack( push, 1 )
struct SCVFrmHeader  // pcaprec_hdr
{
 DWORD TimeSec;    // From start of capture session
 DWORD TimeMcSec;  // Microseconds (0 - 999999)
 DWORD Size1;      // sizeof(SCVPckHeader) + PacketSize  // incl_len;       /* number of octets of packet saved in file */
 DWORD Size2;      // sizeof(SCVPckHeader) + PacketSize  // orig_len;       /* actual length of packet */
 WORD  PHdrOffs;   // (WORD) Offset from this 'SCVHeader'   // Aligned as DWORD
};
struct SCVPckHeader
{
 BYTE  IsDamaged;   // BOOL
 BYTE  Unknow1;
 DWORD Unused1;     // ?????????
 BYTE  NoiseInDBM;  // 0=Unused
 BYTE  SigLvlPerc;  // 50% if SigLvlInDBM is invalid
 BYTE  DataRate05;  // Step 0.5 mbps
 BYTE  SigLvlInDBM; // Valid range 0x01(-1) - 0x64(-100)
 BYTE  DataRate128; // Step 128 mbps
 BYTE  Unused2;     // ?????????
 BYTE  SpecBand;    // EWFBands
 BYTE  Unknow2;     // 0x52 'R'
};
struct SPacketDesc
{
 UINT32 TimeSec;    // From start of capture session?
 UINT32 TimeMcSec;  // Microseconds (0 - 999999)
 UINT32 Size;       // Packet Data Size
 UINT32 Freq;       // Uncertain!   // Channel?
 UINT32 SpecBand;
 UINT32 NoiseInDBM;
 UINT32 SigLvlInDBM;
 UINT32 SigLvlPerc;
 UINT32 DataRate;   // *10
 UINT32 Damaged;    // Bool
};
struct SPacketHdr: public SPacketDesc
{
 PBYTE  Packet;
 UINT32 NxtOffset;
};
#pragma pack( pop )

template<typename T> T Align4(T val){return (val+3)&-4;}   // Can cause overflow!



// TODO: reference additional headers your program requires here
