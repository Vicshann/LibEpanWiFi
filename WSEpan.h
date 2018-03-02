//---------------------------------------------------------------------------

#ifndef WSEpanH
#define WSEpanH

//---------------------------------------------------------------------------
#pragma pack(push,1)
struct SPacketHdr;

struct SWSENode
{
/* Types of port numbers Wireshark knows about. */
 enum EPortType{
    PT_NONE,            /* no port number */
    PT_SCTP,            /* SCTP */
    PT_TCP,             /* TCP */
    PT_UDP,             /* UDP */
    PT_DCCP,            /* DCCP */
    PT_IPX,             /* IPX sockets */
    PT_NCP,             /* NCP connection */
    PT_EXCHG,           /* Fibre Channel exchange */
    PT_DDP,             /* DDP AppleTalk connection */
    PT_SBCCS,           /* FICON */
    PT_IDP,             /* XNS IDP sockets */
    PT_TIPC,            /* TIPC PORT */
    PT_USB,             /* USB endpoint 0xffff means the host */
    PT_I2C,
    PT_IBQP,            /* Infiniband QP number */
    PT_BLUETOOTH
};
//-------------------------------------------
enum EAddrType{
    AT_NONE,               /* no link-layer address */
    AT_ETHER,              /* MAC (Ethernet, 802.x, FDDI) address */
    AT_IPv4,               /* IPv4 */
    AT_IPv6,               /* IPv6 */
    AT_IPX,                /* IPX */
    AT_VINES,              /* Banyan Vines */
    AT_FC,                 /* Fibre Channel */
    AT_FCWWN,              /* Fibre Channel WWN */
    AT_SS7PC,              /* SS7 Point Code */
    AT_STRINGZ,            /* null-terminated string */
    AT_EUI64,              /* IEEE EUI-64 */
    AT_IB,                 /* Infiniband GID/LID */
    AT_USB,                /* USB Device address (0xffffffff represents the host) */                        
    AT_AX25,               /* AX.25 */
    AT_END_OF_LIST         /* Must be last in list */
};
//-------------------------------------------
struct address {
    int           type;         /* type of address */
    int           len;          /* length of address, in bytes */
    const void  *data;          /* pointer to address data */
};

struct SAddr {
    BYTE  type:4;         /* type of address */
    BYTE   len:4;         /* length of address, in bytes */
    BYTE  Value[7];       /* pointer to address data */
} ;
//-------------------------------------------
/* field types */
enum EFType {
	FT_NONE,	/* used for text labels with no value */
	FT_PROTOCOL,
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_UINT40,	/* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
	FT_UINT48,	/* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
	FT_UINT56,	/* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
	FT_UINT64,
	FT_INT8,
	FT_INT16,
	FT_INT24,	/* same as for UINT24 */
	FT_INT32,
	FT_INT40, /* same as for UINT40 */
	FT_INT48, /* same as for UINT48 */
	FT_INT56, /* same as for UINT56 */
	FT_INT64,
	FT_FLOAT,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
	FT_ETHER,
	FT_BYTES,
	FT_UINT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
	FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
	FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
	FT_GUID,	/* GUID, UUID */
	FT_OID,		/* OBJECT IDENTIFIER */
	FT_EUI64,
	FT_AX25,
	FT_VINES,
	FT_REL_OID,	/* RELATIVE-OID */
	FT_SYSTEM_ID,
	FT_STRINGZPAD,	/* for use with proto_tree_add_item() */
	FT_FCWWN,
	FT_NUM_TYPES /* last item number plus one */
};
__inline bool ISFT_INT(EFType ft){return ((ft)==FT_INT8||(ft)==FT_INT16||(ft)==FT_INT24||(ft)==FT_INT32||(ft)==FT_INT40||(ft)==FT_INT48||(ft)==FT_INT56||(ft)==FT_INT64);}
__inline bool ISFT_UINT(EFType ft){return ((ft)==FT_UINT8||(ft)==FT_UINT16||(ft)==FT_UINT24||(ft)==FT_UINT32||(ft)==FT_UINT40||(ft)==FT_UINT48||(ft)==FT_UINT56||(ft)==FT_UINT64||(ft)==FT_FRAMENUM);}
__inline bool ISFT_TIME(EFType ft){return ((ft)==FT_ABSOLUTE_TIME||(ft)==FT_RELATIVE_TIME);}
__inline bool ISFT_STRING(EFType ft){return ((ft)==FT_STRING||(ft)==FT_STRINGZ||(ft)==FT_STRINGZPAD);}

/* field types lengths */
static const int  FTL_ETHER       = 6;
static const int  FTL_GUID        = 16;
static const int  FTL_IPv4        = 4;
static const int  FTL_IPv6        = 16;
static const int  FTL_IPXNET      = 4;
static const int  FTL_EUI64       = 8;
static const int  FTL_AX25_ADDR   = 7;
static const int  FTL_VINES_ADDRN = 6;
static const int  FTL_FCWWN       = 8;
//-------------------------------------------
struct SByteArray
{
  BYTE *data;
  UINT len;
};
struct ipv4_addr
{
	UINT32	addr;	/* stored in host order */
	UINT32	nmask;	/* stored in host order */
};
struct e_in6_addr 
{
 UINT8   bytes[16];		/**< 128 bit IP6 address */
};

struct ipv6_addr
{
   e_in6_addr addr;
   UINT32 prefix;
};
struct nstime_t 
{
	UINT64	secs;
	int	nsecs;
};
struct e_guid_t 
{
    UINT32 data1;
    UINT16 data2;
    UINT16 data3;
    UINT8  data4[8];
};
//-------------------------------------------
struct fvalue_t {
	void	*ftype;
	union {
		/* Put a few basic types in here */
		UINT32		uinteger;
		INT32		sinteger;
		UINT64		integer64;
		UINT64		uinteger64;
		INT64		sinteger64;
		double		floating;
		char		*string;
		UINT8		*ustring;
		SByteArray	*bytes;
		ipv4_addr	ipv4;
		ipv6_addr	ipv6;
		e_guid_t	guid;
		nstime_t	time;
		void	    *tvb;  // tvbuff_t
		void	    *re;   // GRegex
	} value;

	/* The following is provided for private use
	 * by the fvalue. */
	int	fvalue_gboolean1;
};
//-------------------------------------------

 void* Handle;
 struct
  {
   EPortType ptype;                /**< type of the following two port numbers */
   UINT32 srcport;                 /**< source port */
   UINT32 destport;                /**< destination port */
   SAddr dl_src;                   /**< link-layer source address */
   SAddr dl_dst;                   /**< link-layer destination address */
   SAddr net_src;                  /**< network-layer source address */
   SAddr net_dst;                  /**< network-layer destination address */
   SAddr src;                      /**< source address (net if present, DL otherwise )*/
   SAddr dst;                      /**< destination address (net if present, DL otherwise )*/
  
   bool fragmented;                /**< TRUE if the protocol is only a fragment */
   bool in_error_pkt;              /**< TRUE if we're inside an {ICMP,CLNP,...} error packet */
   bool in_gre_pkt;                /**< TRUE if we're encapsulated inside a GRE packet */
  }PacketInfo;
//-------------------------------------------
 struct
  {
   char	  *name;           /**< [FIELDNAME] full name of this field */
   char	  *abbrev;         /**< [FIELDABBREV] abbreviated name of this field */
   char	  *blurb;          /**< [FIELDDESCR] Brief description of field */
   char	  *ValStr;

   EFType type;            /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
   int	  display;         /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
   UINT	  bitmask;         /**< [BITMASK] bitmask of interesting bits */
  }FieldInfo;
//-------------------------------------------
 struct
  {
	int			 start;           /**< current start of data in field_info.ds_tvb */
	int			 length;          /**< current data length of item in field_info.ds_tvb */
	int			 appendix_start;  /**< start of appendix data */
	int			 appendix_length; /**< length of appendix data */
	fvalue_t	 value;  
  }Value;

 int  Count;
 char Label[240];    // ITEM_LABEL_LENGTH=240
};
#pragma pack(pop)

typedef void (_cdecl *t_LogProc)(char* ProcName, char* Message, ...);

typedef int   (_stdcall *t_wseResolveNetAddr)(SWSENode::address* addr, char* AddrStr, int StrLen);
typedef int   (_stdcall *t_wseDissectPacket)(void* Handle, SPacketHdr* PkHdr, SWSENode* Root, BOOL Radio);
typedef int   (_stdcall *t_wseGetNodeInfo)(void* Handle, SWSENode* Node);
typedef int   (_stdcall *t_wseNextNode)(SWSENode* Node);
typedef int   (_stdcall *t_wseChildNode)(SWSENode* Node);
typedef int   (_stdcall *t_wseParentNode)(SWSENode* Node);
typedef int   (_stdcall *t_wseInitialize)(t_LogProc pLogP);
typedef void  (_stdcall *t_wseFinalize)(void);
typedef void* (_stdcall *t_wseCreateDissector)(void);
typedef void  (_stdcall *t_wseDeleteDissector)(void* Handle);

//---------------------------------------------------------------------------
#endif
