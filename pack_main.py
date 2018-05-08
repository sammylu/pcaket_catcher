from scapy.all import *
import packet_catch.pack_get_class
def get_ether(p,dpkt):#获得ether数据包
    try:
        EDst = str(dpkt[i][Ether].dst);
    except IndexError:
        print("\033[0;31;0m没有以太网数据包\033[0m");
    else:
        print("\033[0;32;0m以太网协议\033[0m")
        EDst=str(dpkt[i][Ether].dst);
        ESrc=str(dpkt[i][Ether].src);
        EType=int(dpkt[i][Ether].type);##16进制
        p.getether(EDst, ESrc, EType);
        p.showether();
def get_pppoe(p,dpkt):#获得pppoe数据包
    try:
        Pversion=dpkt[i][PPPoE].version;
    except IndexError:
        print("\033[0;31;0m没有PPPOE数据包\033[0m");
    else:
        print("\033[0;32;0mPPPOE协议\033[0m");
        Pversion=dpkt[i][PPPoE].version;
        Ptype=dpkt[i][PPPoE].type;
        Pcode=dpkt[i][PPPoE].code;
        Psessionid=dpkt[i][PPPoE].sessionid;
        Plen=dpkt[i][PPPoE].len;
        #存入类
        p.getpppoe(Pversion,Ptype,Pcode,Psessionid,Plen);
        p.showpppoe();
def get_ip(p,dpkt):#获得ip数据包
    try:
        IVersion=dpkt[i][IP].version;
    except IndexError:
        print("\033[0;31;0m没有IP数据包\033[0m");
    else:
        print("\033[0;32;0mIP协议\033[0m");
        IVersion = int(dpkt[i][IP].version);
        IIhl = int(dpkt[i][IP].ihl);
        ITos = int(dpkt[i][IP].tos);##16进制
        ILen = int(dpkt[i][IP].len);
        IId = int(dpkt[i][IP].id);
        IFlags = str(dpkt[i][IP].flags);
        IFrag = int(dpkt[i][IP].frag);
        ITtl=int(dpkt[i][IP].ttl);
        IProto=int(dpkt[i][IP].proto);
        IChksum=int(dpkt[i][IP].chksum);##16进制
        ISrc=str(dpkt[i][IP].src)
        IDst=str(dpkt[i][IP].dst);
        IOptions=str(dpkt[i][IP].options);
        p.getip(IVersion,IIhl,ITos,ILen,IId,IFlags,IFrag,ITtl,IProto,IChksum,ISrc,IDst,IOptions);
        p.showip();
def get_tcp(p,dpkt):
    try:
        Tsport=dpkt[i][TCP].sport;
    except IndexError:
        print("\033[0;31;0m没有TCP数据包\033[0m");
    else:
        print("\033[0;32;0mTCP协议\033[0m");
        Tsport=dpkt[i][TCP].sport;
        Tdport=dpkt[i][TCP].dport;
        Tseq=dpkt[i][TCP].seq;
        Tack=dpkt[i][TCP].ack;
        Tdataofs=dpkt[i][TCP].dataofs;
        Treserved=dpkt[i][TCP].reserved;
        Tflags=dpkt[i][TCP].flags;
        Twindow=dpkt[i][TCP].window;
        Tchksum=dpkt[i][TCP].chksum;
        Turgptr=dpkt[i][TCP].urgptr;
        Toptions=dpkt[i][TCP].options;
        p.gettcp(Tsport, Tdport,Tseq,Tack,Tdataofs,Treserved,Tflags,Twindow,Tchksum,Turgptr,Toptions);
        p.showtcp();
def get_arp(p,dpkt):
    try:
        Ahtype=dpkt[i][ARP].hwtype;
    except IndexError:
        print("\033[0;31;0m没有ARP数据包\033[0m");
    else:
        Ahtype = dpkt[i][ARP].hwtype;
        Aptype = dpkt[i][ARP].ptype;
        Ahlen = dpkt[i][ARP].hwlen;
        Aplen = dpkt[i][ARP].plen;
        Aop = dpkt[i][ARP].op;
        Ahsrc = dpkt[i][ARP].hwsrc;
        Apsrc = dpkt[i][ARP].psrc;
        Ahdst = dpkt[i][ARP].hwdst;
        Apdst = dpkt[i][ARP].pdst;
        p.getarp(Ahtype,Aptype,Ahlen,Aplen,Aop,Ahsrc,Apsrc,Ahdst,Apdst);
        p.showarp();
def get_udp(p,dpkt):
    try:
        Usport=dpkt[i][UDP].sport;
    except IndexError:
        print("\033[0;31;0m没有UDP数据包\033[0m");
    else:
        Usport=dpkt[i][UDP].sport;
        Udport=dpkt[i][UDP].dport;
        Ulen=dpkt[i][UDP].len;
        Uchksum=dpkt[i][UDP].chksum;
        p.getudp(Usport,Udport,Ulen,Uchksum);
        p.showudp();










#获得数据包
dpkt=sniff(iface="eth0",count=10);
for i in range(len(dpkt)):
    p = packet_catch.pack_get_class.packet();
    get_ether(p,dpkt);
    get_pppoe(p,dpkt);
    get_ip(p,dpkt);
    get_tcp(p,dpkt);
    get_arp(p,dpkt);
    get_udp(p,dpkt);
    print("----------------------------------------------------------------------");