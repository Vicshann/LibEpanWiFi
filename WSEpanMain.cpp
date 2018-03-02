

#include "stdafx.h"
#include "address_types.h"

HMODULE   hCurMod;
t_LogProc Logp = NULL;
epan_t*  wepan = NULL;

//---------------------------------------------------------------------------
void _stdcall CopyAddress(SWSENode::SAddr* addr, address* wsaddr)
{
 addr->len  = wsaddr->len; 
 addr->type = wsaddr->type;
 memcpy(addr->Value, wsaddr->data, wsaddr->len);
}
//---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
 hCurMod = hModule;
 switch (ul_reason_for_call)
 {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	  break;
 }
 return TRUE;
}
//---------------------------------------------------------------------------
// Decode a network address
// Less the buffer size(StrLen) - less info will be output.
//
int _stdcall wseResolveNetAddr(const address* addr, char* AddrStr, int StrLen)
{
 *AddrStr = 0;
 address_with_resolution_to_str_buf(addr, AddrStr, StrLen);
 if(!*AddrStr)return -1;
 return 0;
}
//---------------------------------------------------------------------------
// Initialize the library
//
int _stdcall wseInitialize(t_LogProc pLogP)
{
 Logp = pLogP;

 glib_init_static();
 epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);
 epan_conversation_init();
 epan_circuit_init();

 wepan = epan_new();
 return 0; 
}
//---------------------------------------------------------------------------
// Finalize the library 
//
void _stdcall wseFinalize(void)
{
 if(!wepan)return;
 
 epan_free(wepan);

 epan_conversation_cleanup();
 epan_circuit_cleanup();
 epan_cleanup();
 glib_cleanup_static();
}
//---------------------------------------------------------------------------
// Create a separate dissector
//
void* _stdcall wseCreateDissector(void)
{
 return epan_dissect_new(wepan, TRUE, TRUE);
}
//---------------------------------------------------------------------------
// Delete a dissector
//
void _stdcall wseDeleteDissector(void* Handle)
{
 epan_dissect_free((epan_dissect_t*)Handle);
}
//---------------------------------------------------------------------------
// Get info about a dissected packet`s node
//
int _stdcall wseGetNodeInfo(proto_node* item, SWSENode* Node)
{   
 memset(Node, 0, sizeof(SWSENode));
 Node->Count  = item->tree_data->count;
 Node->Handle = item;          
             
 Node->PacketInfo.ptype        = (SWSENode::EPortType)item->tree_data->pinfo->ptype;     
 Node->PacketInfo.srcport      = item->tree_data->pinfo->srcport;    
 Node->PacketInfo.destport     = item->tree_data->pinfo->destport;                     
 Node->PacketInfo.fragmented   = item->tree_data->pinfo->fragmented; 
 Node->PacketInfo.in_error_pkt = item->tree_data->pinfo->flags.in_error_pkt;
 Node->PacketInfo.in_gre_pkt   = item->tree_data->pinfo->flags.in_gre_pkt;         
 
 CopyAddress(&Node->PacketInfo.dl_src, &item->tree_data->pinfo->dl_src);
 CopyAddress(&Node->PacketInfo.dl_dst, &item->tree_data->pinfo->dl_dst);
 CopyAddress(&Node->PacketInfo.net_src, &item->tree_data->pinfo->net_src);
 CopyAddress(&Node->PacketInfo.net_dst, &item->tree_data->pinfo->net_dst);
 CopyAddress(&Node->PacketInfo.src, &item->tree_data->pinfo->src);
 CopyAddress(&Node->PacketInfo.dst, &item->tree_data->pinfo->dst);
  
 if(item->finfo)
  {
   if(!item->finfo->rep)proto_item_fill_label(item->finfo, (gchar*)&Node->Label);   
     else memcpy(&Node->Label, &item->finfo->rep->representation, ITEM_LABEL_LENGTH);         
                               
   Node->FieldInfo.name    = (char*)item->finfo->hfinfo->name;  
   Node->FieldInfo.abbrev  = (char*)item->finfo->hfinfo->abbrev;      
   Node->FieldInfo.blurb   = (char*)item->finfo->hfinfo->blurb;       
   Node->FieldInfo.ValStr  = (char*)&Node->Label;  

   Node->FieldInfo.type    = (SWSENode::EFType)item->finfo->hfinfo->type;         
   Node->FieldInfo.display = item->finfo->hfinfo->display;     
   Node->FieldInfo.bitmask = item->finfo->hfinfo->bitmask;      

   Node->Value.start  = item->finfo->start;      
   Node->Value.length = item->finfo->length;       
   Node->Value.appendix_start  = item->finfo->appendix_start;
   Node->Value.appendix_length = item->finfo->appendix_length;
   memcpy(&Node->Value.value, &item->finfo->value, sizeof(SWSENode::fvalue_t));
  }  
 return 0;
}
//------------------------------------------------------------------------------------
// Dissect a received packet
//
int _stdcall wseDissectPacket(void* Handle, SPacketHdr* PkHdr, SWSENode* Root, BOOL Radio)
{
 wtap_pkthdr wthdr;
 frame_data  fdata;

 memset(&wthdr, 0, sizeof(wthdr));
 memset(&fdata, 0, sizeof(fdata)); 

 wthdr.pkt_encap = WTAP_ENCAP_IEEE_802_11; //   WTAP_ENCAP_IEEE_802_11_WITH_RADIO; // WTAP_ENCAP_IEEE_802_11; 
// wthdr.pseudo_header.ieee_802_11.presence_flags = PHDR_802_11_HAS_CHANNEL | PHDR_802_11_HAS_DATA_RATE | PHDR_802_11_HAS_SIGNAL_PERCENT;
// wthdr.pseudo_header.ieee_802_11.fcs_len = -1; // Unknown
// wthdr.pseudo_header.ieee_802_11.channel = 1; //cv_hdr.channel;
// wthdr.pseudo_header.ieee_802_11.data_rate = 9600; //;cv_hdr.rate | (cv_hdr.direction << 8);
// wthdr.pseudo_header.ieee_802_11.signal_percent = 44; //cv_hdr.signal_level_percent;

 wthdr.len      = PkHdr->Size; // cv_hdr.data_len;
 wthdr.caplen   = PkHdr->Size; // cv_hdr.data_len;
 wthdr.ts.secs  = 100; //mktime(&tm);
 wthdr.ts.nsecs = 100; //cv_hdr.usecs * 1000;
 wthdr.rec_type = REC_TYPE_PACKET;
 wthdr.presence_flags = WTAP_HAS_TS;

 fdata.num = 1;
 fdata.pkt_len = PkHdr->Size;
 fdata.cap_len = PkHdr->Size;
 fdata.lnk_t   = WTAP_ENCAP_IEEE_802_11;        //  WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
 fdata.abs_ts.secs    = PkHdr->TimeSec;
 fdata.abs_ts.nsecs   = PkHdr->TimeMcSec*1000;
 fdata.flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII;

 epan_dissect_reset((epan_dissect_t*)Handle);  
 epan_dissect_run((epan_dissect_t*)Handle, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &wthdr, frame_tvbuff_new(&fdata, PkHdr->Packet), &fdata, NULL); 
  
 return wseGetNodeInfo(((epan_dissect_t*)Handle)->tree, Root);     
}
//---------------------------------------------------------------------------
int _stdcall wseNextNode(SWSENode* Node)
{
 proto_node* tnode = ((proto_node*)Node->Handle)->next;
 memset(Node,0,sizeof(SWSENode));
 if(!tnode)return 1;  // No more nodes
 return wseGetNodeInfo(tnode, Node);
}
//---------------------------------------------------------------------------
int _stdcall wseChildNode(SWSENode* Node)
{
 proto_node* tnode = ((proto_node*)Node->Handle)->first_child;
 memset(Node,0,sizeof(SWSENode));
 if(!tnode)return 1;  // No more nodes
 return wseGetNodeInfo(tnode, Node);
}
//---------------------------------------------------------------------------
int _stdcall wseParentNode(SWSENode* Node)
{
 proto_node* tnode = ((proto_node*)Node->Handle)->parent;
 memset(Node,0,sizeof(SWSENode));
 if(!tnode)return 1;  // No more nodes
 return wseGetNodeInfo(tnode, Node);
}
//===========================================================================
//
//                                 TEST APP
//
//===========================================================================


#ifdef TESTAPP

BYTE TestPacket2[108] = {
	0x40, 0x00, 0x3A, 0x01, 0xDC, 0x9F, 0xDB, 0x50, 0x69, 0x8F, 0xDC, 0x9F, 0xDB, 0x90, 0x28, 0xF9, 
	0xDC, 0x9F, 0xDB, 0x50, 0x69, 0x8F, 0xC0, 0x91, 0x00, 0x06, 0x67, 0x6F, 0x72, 0x70, 0x6F, 0x36, 
	0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6C, 
	0xDD, 0x1E, 0x00, 0x90, 0x4C, 0x33, 0xCC, 0x11, 0x1B, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x2D, 0x1A, 0xCC, 0x11, 0x1B, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


void proto_tree_print(epan_dissect_t *edt);
void fill_framedata(frame_data *fdata, UINT64 frame_number, SPacketDesc *h, int ll_type);
//------------------------------------------------------------------------------
bool _stdcall GetCVPacket(SPacketHdr* PkHdr, PBYTE Data, UINT Size)
{
 UINT Offset = PkHdr->NxtOffset;
 if(Offset > Size)return false;
 PBYTE Base = &Data[Offset];
 SCVFrmHeader* Frm = (SCVFrmHeader*)Base;
 if(((int)Frm->Size1 <= 0)||((int)Frm->Size2 <= 0))return false;   // ??????
 PkHdr->TimeSec     = Frm->TimeSec;
 PkHdr->TimeMcSec   = Frm->TimeMcSec;
 PkHdr->NxtOffset  += Align4(Frm->Size2 + Frm->PHdrOffs);
 SCVPckHeader* Hdr  = (SCVPckHeader*)&Base[Frm->PHdrOffs];
 PkHdr->Packet      = &Base[Frm->PHdrOffs+sizeof(SCVPckHeader)];
 PkHdr->Size        = Frm->Size2 - sizeof(SCVPckHeader);
 PkHdr->SpecBand    = Hdr->SpecBand;
 PkHdr->NoiseInDBM  = Hdr->NoiseInDBM;
 PkHdr->SigLvlInDBM = Hdr->SigLvlInDBM;
 PkHdr->SigLvlPerc  = Hdr->SigLvlPerc;
 PkHdr->DataRate    = (Hdr->DataRate128 + ((float)Hdr->DataRate05*0.5)) * 10;
 PkHdr->Damaged     = Hdr->IsDamaged;  // Not all adapters can detect
 return true;
}
//---------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{  
 //wtap_pseudo_header pseudo_header;
 wtap_pkthdr wthdr;
 frame_data fdata;
 SPacketHdr PkHdr;
 Buffer tbuf; 
  
 memset(&wthdr, 0, sizeof(wthdr));
 memset(&fdata, 0, sizeof(fdata));
 memset(&PkHdr,0,sizeof(PkHdr));
 memset(&tbuf, 0, sizeof(tbuf));  

 glib_init_static();

 epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);
 epan_conversation_init();
 epan_circuit_init();

 epan_t* wepan = epan_new();
 epan_dissect_t* edt = epan_dissect_new(wepan, TRUE, TRUE);

 GetCVPacket(&PkHdr, (PBYTE)&TestPacket2, sizeof(TestPacket2));
                     PkHdr.Size = sizeof(TestPacket2);
 ws_buffer_init(&tbuf, PkHdr.Size+256);
 ws_buffer_append(&tbuf, (guint8*)&TestPacket2, PkHdr.Size);
                            
 //	case MEDIUM_WIFI :
     
 wthdr.pkt_encap = WTAP_ENCAP_IEEE_802_11_WITH_RADIO; // WTAP_ENCAP_IEEE_802_11; //  WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
 wthdr.pseudo_header.ieee_802_11.presence_flags = PHDR_802_11_HAS_CHANNEL | PHDR_802_11_HAS_DATA_RATE | PHDR_802_11_HAS_SIGNAL_PERCENT;
 wthdr.pseudo_header.ieee_802_11.fcs_len = -1; /* Unknown */
 wthdr.pseudo_header.ieee_802_11.channel = 1; //cv_hdr.channel;
 wthdr.pseudo_header.ieee_802_11.data_rate = 9600; //;cv_hdr.rate | (cv_hdr.direction << 8);
 wthdr.pseudo_header.ieee_802_11.signal_percent = 44; //cv_hdr.signal_level_percent;

 wthdr.rec_type = REC_TYPE_PACKET;
 wthdr.presence_flags = WTAP_HAS_TS;

 wthdr.len    = PkHdr.Size; // cv_hdr.data_len;
 wthdr.caplen = PkHdr.Size; // cv_hdr.data_len;

 wthdr.ts.secs  = 100; //mktime(&tm);
 wthdr.ts.nsecs = 100; //cv_hdr.usecs * 1000;


 fill_framedata(&fdata, 1, &PkHdr, WTAP_ENCAP_IEEE_802_11_WITH_RADIO); //WTAP_ENCAP_IEEE_802_11); //WTAP_ENCAP_IEEE_802_11_WITH_RADIO);  // ll_type
 tvbuff_t* tvb = frame_tvbuff_new_buffer(&fdata, &tbuf);   
               
 epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &wthdr, tvb, &fdata, NULL);


 proto_tree_print(edt);


 epan_dissect_free(edt);
 epan_free(wepan);

 epan_conversation_cleanup();
 epan_circuit_cleanup();
 epan_cleanup();
 glib_cleanup_static();

 return 0;
}

//-------------------------------------------------------------------------------------------
void fill_framedata(frame_data *fdata, UINT64 frame_number, SPacketDesc *h, int ll_type)
{
 memset(fdata, 0, sizeof(frame_data) ); 
//    fdata->next = NULL;
//    fdata->prev = NULL;
    fdata->pfd = NULL;
    fdata->num = frame_number;
    fdata->pkt_len = h->Size;
    fdata->cum_bytes  = 0; 
    fdata->cap_len = h->Size;
    fdata->file_off = 0; 
    fdata->lnk_t = ll_type;
    fdata->abs_ts.secs    = h->TimeSec;
    fdata->abs_ts.nsecs   = h->TimeMcSec*1000;
    fdata->flags.passed_dfilter = 0;
    fdata->flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII;
    fdata->flags.visited = 0;
    fdata->flags.marked = 0;
    fdata->flags.ref_time = 0;
    fdata->color_filter   = NULL;

    /*
     * If we don't have the timestamp of the first packet in the capture, it's
     * because this is the first packet. Save the timestamp of this packet as
     * the timestamp of the first packet.
     */
//    if (nstime_is_unset(&first_ts) )first_ts = fdata->abs_ts;

    /* Get the time elapsed between the first packet and this packet. */
//    nstime_delta(&fdata->rel_ts, &fdata->abs_ts, &first_ts);

    /*
     * If we don't have the time stamp of the previous captured packet, it's
     * because this is the first packet.  Save the time stamp of this packet as
     * the time stamp of the previous captured packet.
     */
//    if (nstime_is_unset(&prev_cap_ts) )prev_cap_ts = fdata->abs_ts;

    /*
     * Get the time elapsed between the previous captured packet and this
     * packet.
     */
//    nstime_delta(&fdata->del_cap_ts, &fdata->abs_ts, &prev_cap_ts);

    /*
     * We treat delta between this packet and the previous captured packet
     * and delta between this packet and the previous displayed packet
     * as the same.
     */
//    fdata->del_dis_ts = fdata->del_cap_ts;

 //   prev_cap_ts = fdata->abs_ts;
}
//-------------------------------------------------------------------------------------------
/* Free up all data attached to a "frame_data" structure. */
void clear_fdata(frame_data *fdata)
{
  if (fdata->pfd)g_slist_free(fdata->pfd);
}
//-------------------------------------------------------------------------------------------
static int print_hidden = 1;

void proto_tree_print_node(proto_node *node, gpointer data)
{
    gchar *label_ptr;
    field_info *fi;
    char *s;

    fi = PITEM_FINFO(node);

    if (fi->hfinfo->id == hf_text_only) {
	/* XXX - Text label. Do nothing for now. */

	/* Get the text */
	label_ptr = fi->rep ? fi->rep->representation : "";

	printf("Text label: %s\n", label_ptr);
    } else if (!PROTO_ITEM_IS_HIDDEN(node)
	       || (PROTO_ITEM_IS_HIDDEN(node) && print_hidden) ) {
	/*
	 * Normal protocols and fields
	 */

	switch (fi->hfinfo->type) {
	case FT_PROTOCOL:
	    printf("proto = %s, start = %d, len = %d   - %s\n",
		   fi->hfinfo->name, fi->start, fi->length, fi->hfinfo->blurb);   // abbrev
	    break;
	case FT_NONE:
	    printf("fi->hfinfo->type is FT_NONE\n");
	    break;
	default:
	    s = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, BASE_NONE, NULL);

	    printf("  %s: %s   - %s\n", fi->hfinfo->name, s, fi->hfinfo->blurb);  // abbrev

	    g_free(s); /* fvalue_to_string_repr() allocated for us. Needs to
			  be freed. */
	}
    }

    /*
     * What is this assert() in the Wireshark code for, again? I don't
     * know why this condition needs to be satisfied; I just stole the code
     * and this came with the bounty. EP.-
     */
    g_assert(fi->tree_type >= -1 && fi->tree_type < num_tree_types);

    /* We always make all levels available to the Tcl world; recurse here */
    if (node->first_child != NULL)
	proto_tree_children_foreach(node, proto_tree_print_node, data);
}
//-------------------------------------------------------------------------------------------
void proto_tree_print(epan_dissect_t *edt)
{
    printf("-----------------------------------\n");

    proto_tree_children_foreach(edt->tree, proto_tree_print_node, NULL);
}
//-------------------------------------------------------------------------------------------
static char *get_line_buf(size_t len)
{
    static char *line_bufp = NULL;
    static size_t line_buf_len = 256;
    size_t new_line_buf_len;

    for (new_line_buf_len = line_buf_len; new_line_buf_len < len;
	 new_line_buf_len *= 2)
	;

    if (line_bufp == NULL) {
	line_buf_len = new_line_buf_len;
	line_bufp = (char*)g_malloc(line_buf_len + 1);
    } else {
	if (new_line_buf_len > line_buf_len) {
	    line_buf_len = new_line_buf_len;
	    line_bufp = (char*)g_realloc(line_bufp, line_buf_len + 1);
	}
    }

    return line_bufp;
}
//-------------------------------------------------------------------------------------------
void print_columns(column_info *cinfo)
{
    char *line_bufp;
    int i;
    size_t buf_offset;
    size_t column_len;

    line_bufp = get_line_buf(256);
    buf_offset = 0;
    *line_bufp = '\0';

    for (i = 0; i < cinfo->num_cols; i++) {
	switch (cinfo->col_fmt[i]) {
	case COL_NUMBER:
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 3)
		column_len = 3;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%3s", cinfo->col_data[i]);
	    break;

	case COL_CLS_TIME:
	case COL_REL_TIME:
	case COL_ABS_TIME:
    case COL_ABS_YMD_TIME:
	case COL_ABS_YDOY_TIME: /* XXX - wider */
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 10)
		column_len = 10;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%10s", cinfo->col_data[i]);
	    break;

	case COL_DEF_SRC:
	case COL_RES_SRC:
	case COL_UNRES_SRC:
	case COL_DEF_DL_SRC:
	case COL_RES_DL_SRC:
	case COL_UNRES_DL_SRC:
	case COL_DEF_NET_SRC:
	case COL_RES_NET_SRC:
	case COL_UNRES_NET_SRC:
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 12)
		column_len = 12;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%12s", cinfo->col_data[i]);
	    break;

	case COL_DEF_DST:
	case COL_RES_DST:
	case COL_UNRES_DST:
	case COL_DEF_DL_DST:
	case COL_RES_DL_DST:
	case COL_UNRES_DL_DST:
	case COL_DEF_NET_DST:
	case COL_RES_NET_DST:
	case COL_UNRES_NET_DST:
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 12)
		column_len = 12;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%-12s", cinfo->col_data[i]);
	    break;

	default:
	    column_len = strlen(cinfo->col_data[i]);
	    line_bufp = get_line_buf(buf_offset + column_len);
	    strcat(line_bufp + buf_offset, cinfo->col_data[i]);
	    break;
	}

	buf_offset += column_len;

	if (i != cinfo->num_cols - 1) {
	    /*
	     * This isn't the last column, so we need to print a
	     * separator between this column and the next.
	     *
	     * If we printed a network source and are printing a
	     * network destination of the same type next, separate
	     * them with "->"; if we printed a network destination
	     * and are printing a network source of the same type
	     * next, separate them with "<-"; otherwise separate them
	     * with a space.
	     *
	     * We add enough space to the buffer for " <- " or " -> ",
	     * even if we're only adding " ".
	     */

	    line_bufp = get_line_buf(buf_offset + 4);

	    switch (cinfo->col_fmt[i]) {
	    case COL_DEF_SRC:
	    case COL_RES_SRC:
	    case COL_UNRES_SRC:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_DST:
		case COL_RES_DST:
		case COL_UNRES_DST:
		    strcat(line_bufp + buf_offset, " -> ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_DL_SRC:
	    case COL_RES_DL_SRC:
	    case COL_UNRES_DL_SRC:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_DL_DST:
		case COL_RES_DL_DST:
		case COL_UNRES_DL_DST:
		    strcat(line_bufp + buf_offset, " -> ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_NET_SRC:
	    case COL_RES_NET_SRC:
	    case COL_UNRES_NET_SRC:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_NET_DST:
		case COL_RES_NET_DST:
		case COL_UNRES_NET_DST:
		    strcat(line_bufp + buf_offset, " -> ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_DST:
	    case COL_RES_DST:
	    case COL_UNRES_DST:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_SRC:
		case COL_RES_SRC:
		case COL_UNRES_SRC:
		    strcat(line_bufp + buf_offset, " <- ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_DL_DST:
	    case COL_RES_DL_DST:
	    case COL_UNRES_DL_DST:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_DL_SRC:
		case COL_RES_DL_SRC:
		case COL_UNRES_DL_SRC:
		    strcat(line_bufp + buf_offset, " <- ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_NET_DST:
	    case COL_RES_NET_DST:
	    case COL_UNRES_NET_DST:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_NET_SRC:
		case COL_RES_NET_SRC:
		case COL_UNRES_NET_SRC:
		    strcat(line_bufp + buf_offset, " <- ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    default:
		strcat(line_bufp + buf_offset, " ");
		buf_offset += 1;
	    }
	}
    }

    puts(line_bufp);
}
//----------------------------------------------------------------------------------------------------
#endif