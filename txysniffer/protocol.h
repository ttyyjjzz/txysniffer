#ifndef PROTOCOL_H
#define PROTOCOL_H

#pragma once
#include "pcap.h"

#define PROTO_ARP 0x0806//ARP协议类型
#define PROTO_IP 0x0800//IP协议类型
#define PROTO_RARP 0x8035//RARP协议类型
#define PROTO_PPP 0x880B//PPP协议类型
#define PROTO_SNMP 0x814C//SNMP协议类型
#define PROTO_TCP 6//TCP协议类型
#define PROTO_UDP 17//UDP协议类型
#define PROTO_ICMP 1//ICMP协议类型

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321

typedef struct packet {
	const struct pcap_pkthdr *header;
	const u_char *pkt_data;
}packet;

typedef struct packet_index {
	int no;
	ULONGLONG pos;
	int len;
}packet_index;

//MAC头,14
typedef struct eth_header {
	u_char dest[6];//目的地址，6个字节
	u_char src[6];//源地址，6个字节
	u_short type;//类型，2个字节
} eth_header;

//ARP头
typedef struct arp_header {
	u_short hard;//硬件类型，2个字节
	u_short pro;//协议类型，2个字节
	u_char hard_len;//硬件地址长度，1个字节
	u_char pro_len;//协议地址长度，1个字节
	u_short oper;//操作码，2个字节，1代表请求，2代表回复
	u_char src_mac[6];//发送方MAC，6个字节
	u_char src_ip[4];//发送方IP，4个字节
	u_char dest_mac[6];//接收方MAC，6个字节
	u_char dest_ip[4];//接收方IP，4个字节
} arp_header;

//IP地址
typedef struct ip_address {
	u_char byte1;//IP地址第1个字段
	u_char byte2;//IP地址第2个字段
	u_char byte3;//IP地址第3个字段
	u_char byte4;//IP地址第4个字段
} ip_address;

//IP头,20
typedef struct ip_header {
#if defined(LITTLE_ENDIAN)//小端模式
	u_char ihl : 4;//报头长度
	u_char version : 4;//版本号
#elif defined(BIG_ENDIAN)//大端模式
	u_char version : 4;//版本号
	u_char  ihl : 4;//报头长度
#endif
	u_char tos;//TOS服务类型，1个字节
	u_short total_len;//包总长，2个字节
	u_short id;//标识，2个字节
	u_short frag_off;//片位移
	u_char ttl;//生存时间，1个字节
	u_char proto;//协议，1个字节
	u_short check;//校验和，2个字节
	u_int src_addr;//源地址，4个字节
	u_int dest_addr;//目的地址，4个字节
	u_int opt;//选项等，4个字节
} ip_header;

//TCP头,20
typedef struct tcp_header {
	u_short src_port;//源端口地址，2个字节
	u_short dest_port;//目的端口地址，2个字节
	u_int seq;//序列号，4个字节
	u_int ack_seq;//确认序列号 ，4个字节
#if defined(LITTLE_ENDIAN)//小端模式
	u_short res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
#elif defined(BIG_ENDIAN)//大端模式
	u_short doff : 4,
		res1 : 4,
		cwr : 1,
		ece : 1,
		urg : 1,
		ack : 1,
		psh : 1,
		rst : 1,
		syn : 1,
		fin : 1;
#endif
	u_short window;//窗口大小，2个字节
	u_short check;//校验和，2个字节
	u_short urg_ptr;//紧急指针，2个字节
	u_int opt;//选项，4个字节
} tcp_header;

//UDP头,8
typedef struct udp_header {
	u_short sport;//源端口，2个字节
	u_short dport;//目的端口，2个字节
	u_short len;//数据报长度，2个字节
	u_short check;//校验和，2个字节
} udp_header;

//ICMP头,4
struct icmp_header {
	u_char type;//类型，1个字节
	u_char code;//代码，1个字节
	u_char seq;//序列号，1个字节
	u_char check;//校验和，1个字节
};

typedef struct http_packet {
	CString request_method;  // 代表请求的方法，如GET、POST、HEAD、OPTIONS、PUT、DELETE和TARCE
	CString request_uri;     // 代表请求的URI，如/sample.jsp
	CString request_Protocol_version;// 代表请求的协议和协议的版本,如HTTP/1.1

	CString request_accept;  // 代表请求的Accept，如 */*
	CString request_referer; // 代表请求的Referer，如 http://www.gucas.ac.cn/gucascn/index.aspx
	CString request_accept_language;  // 代表请求的 Accept-language，如 zh-cn
	CString request_accept_encoding;  // 代表请求的 Accept_encoding，如 gzip、deflate
	CString request_modified_date;  // 代表请求的If-Modified-Since，如 Sun,27 Sep 2009 02:33:14 GMT
	CString request_match;         // 代表请求的If-None-Match，如 "011d3dc1a3fcal:319"
	CString request_user_agent;  // 代表请求的User-Agent，如 Mozilla/4.0(compatible:MSIE 6.0;Windows NT 5.1;SV1;.NET CLR 1.1.4322;.NEt...
	CString request_host;      // 代表请求的Host，如 www.gucas.ac.cn
	CString request_connection;// 代表请求的Connection，如 Keep-Alive
	CString request_cookie;    // 代表请求的Cookie，如 ASP.NET_SessionId=hw15u245x23tqr45ef4jaiqc

	CString request_entity_boy;// 代表请求的实体主体
							   //===================================================================================
	CString respond_Protocol_version; // 代表响应协议和协议的版本,如HTTP/1.1
	CString respond_status;         // 代表响应状态代码，如200
	CString respond_description;  // 代表响应状态代码的文本描述，如OK

	CString respond_content_type; // 代表响应内容的类型，如text/html
	CString respond_charset;      // 代表响应字符，如UTF-8
	CString respond_content_length; // 代表响应内容的长度，如9
	CString respond_connection; // 代表响应连接状态，如close
	CString respond_Cache_Control; // 代表响应连接状态，如private
	CString respond_X_Powered_By; // 代表响应连接状态，如ASP.NET
	CString respond_X_AspNet_Version; // 代表响应连接状态，如1.1.4322
	CString respond_Set_Cookie; // 代表响应连接状态，如ASP.NET_SessionId=w0qojdwi0welb4550lafq55;path=/

	CString respond_date;       // 代表响应日期，如fri,23 Oct 2009 11:15:31 GMT
	CString respond_Etag;       // 代表无修改，如"Ocld8a8cc91:319"
	CString respond_server;     // 代表响应服务，如lighttpd

	CString respond_entity_boy; // 代表响应实体主体，如IMOld(8);
}http_packet;

//保存用数据结构
struct data_packet {
	char type[8];//包类型
	int time[6];//时间
	int len;//长度

	struct eth_header *ethh;//MAC头
	struct arp_header *arph;//ARP头
	struct ipv4_header *ip4h;//IPv4头
	struct ipv6_header *ip6h;//IPv6头
	struct tcp_header *tcph;//TCP头
	struct udp_header *udph;//UDP头
	struct icmpv4_header *icmp4h;//ICMPv4头
	struct icmpv6_header *icmp6h;//ICMPv6头
	void *apph;//应用层包头
};

#endif