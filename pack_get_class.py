
##设置一个类用来存每一个数据包的信息
class packet:
    ether={};
    ip={};
    pppoe={};
    icmp={};
    tcp={};
    arp={};
    udp={};
    #ether数据包
    def getether(self,dst,src,type):
        self.ether['dst']=dst;
        self.ether['src']=src;
        self.ether['type']=type;
    def showether(self):
        print("目的地址:",self.ether['dst']," 源地址:",self.ether['src']," 类型:%#x"%self.ether['type']);
    #ip数据包
    def getip(self,version,ihl,tos,len,id,flags,frag,ttl,proto,chksum,src,dst,options):
        self.ip['version']=version;
        self.ip['ihl']=ihl;
        self.ip['tos']=tos;
        self.ip['len']=len;
        self.ip['id']=id;
        self.ip['flags']=flags;
        self.ip['frag']=frag;
        self.ip['ttl']=ttl;
        self.ip['proto']=proto;
        self.ip['chksum']=chksum;
        self.ip['src']=src;
        self.ip['dst']=dst;
        self.ip['options']=options;
    def showip(self):
        print("版本号:",self.ip['version']," 首部长度",self.ip['ihl']," 服务类型:%#x"%self.ip['tos']," 总长度:",self.ip['len']);
        print("标识:",self.ip['id']," 标志:",self.ip['flags']," 片偏移:",self.ip['frag']);
        print("TTL:",self.ip['ttl']," 协议:",self.ip['proto']," 首部检验和:%#x"%self.ip['chksum']);
        print("源地址:",self.ip['src']);
        print("目的地址:",self.ip['dst']);
    #pppoe数据包
    def getpppoe(self,version,type,code,sessionid,len):
        self.pppoe['version']=version;
        self.pppoe['type']=type;
        self.pppoe['code']=code;
        self.pppoe['sessionid']=sessionid;
        self.pppoe['len']=len;
    def showpppoe(self):
        print("版本号:",self.pppoe['version']," 类型:",self.pppoe['type']," 代码:",self.pppoe['code']," 会话ID:%#x"%(self.pppoe['sessionid'])," 长度:",self.pppoe['len']);
    #tcp数据包
    def gettcp(self,sport,dport,seq,ack,dataofs,reserved,flags,window,chksum,urgptr,options):
        self.tcp['sport']=sport;
        self.tcp['dport']=dport;
        self.tcp['seq']=seq;
        self.tcp['ack']=ack;
        self.tcp['dataofs']=dataofs;
        self.tcp['reserved']=reserved;
        self.tcp['flags']=flags;
        self.tcp['window']=window;
        self.tcp['chksum']=chksum;
        self.tcp['urgptr']=urgptr;
        self.tcp['options']=options;
    def showtcp(self):
        print("源端口:",self.tcp['sport']," 目的端口:",self.tcp['dport']);
        print("序号:",self.tcp['seq']);
        print("确认序列号:",self.tcp['ack']);
        print("首部长度:",self.tcp['dataofs']," 保留位:",self.tcp['reserved']," 标志:",self.tcp['flags']," 窗口大小:",self.tcp['window']);
        print("校验和:%#x"%(self.tcp['chksum'])," 紧急指针: ",self.tcp['urgptr']);
        print("选项:",self.tcp['options']);
    #arp数据包
    def getarp(self,htype,ptype,hlen,plen,op,hsrc,psrc,hdst,pdst):
        self.arp['htype']=htype;
        self.arp['ptype']=ptype;
        self.arp['hlen']=hlen;
        self.arp['plen']=plen;
        self.arp['op']=op;
        self.arp['hsrc']=hsrc;
        self.arp['psrc']=psrc;
        self.arp['hdst']=hdst;
        self.arp['pdst']=pdst;
    def showarp(self):
        print("硬件类型%#x:"%(self.arp['htype'])," 协议类型%#x:"%(self.arp['ptype']));
        print("硬件地址长度:",self.arp['hlen']," 协议地址长度:",self.arp['plen']," 操作OP:",self.arp['op']);
        print("源mac地址:",self.arp['hsrc']," 目的mac地址:",self.arp['hdst']);
        print("源ip地址:",self.arp['psrc']," 目的ip地址:",self.arp['pdst']);
    #udo数据包
    def getudp(self,sport,dport,len,chksum):
        self.udp['sport']=sport;
        self.udp['dport']=dport;
        self.udp['len']=len;
        self.udp['chksum']=chksum;
    def showudp(self):
        print("源端口:",self.udp['sport']);
        print("端口L:",self.udp['dport']);
        print("长度:",self.udp['len']," 检验和:%#x"%(self.udp['chksum']));

