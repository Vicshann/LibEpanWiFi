# LibEpanWiFi

DLL usage example:

   wseInitialize(LogProc);
   InspectDissect = wseCreateDissector();
         SPacketHdr pkhdr;
         SWSENode Root;
         PkHdr.NxtOffset = 0;
	 if(wseDissectPacket(InspectDissect, &pkhdr, &Root, FALSE) || !Root.Handle)return -1;
	 wseChildNode(&Root);
	 wseNextNode(&Root); 
   wseDeleteDissector(InspectDissect);
   wseFinalize();
