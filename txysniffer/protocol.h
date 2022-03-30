#ifndef PROTOCOL_H
#define PROTOCOL_H

#pragma once
#include "pcap.h"

#define PROTO_ARP 0x0806//ARPЭ������
#define PROTO_IP 0x0800//IPЭ������
#define PROTO_RARP 0x8035//RARPЭ������
#define PROTO_PPP 0x880B//PPPЭ������
#define PROTO_SNMP 0x814C//SNMPЭ������
#define PROTO_TCP 6//TCPЭ������
#define PROTO_UDP 17//UDPЭ������
#define PROTO_ICMP 1//ICMPЭ������

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

//MACͷ,14
typedef struct eth_header {
	u_char dest[6];//Ŀ�ĵ�ַ��6���ֽ�
	u_char src[6];//Դ��ַ��6���ֽ�
	u_short type;//���ͣ�2���ֽ�
} eth_header;

//ARPͷ
typedef struct arp_header {
	u_short hard;//Ӳ�����ͣ�2���ֽ�
	u_short pro;//Э�����ͣ�2���ֽ�
	u_char hard_len;//Ӳ����ַ���ȣ�1���ֽ�
	u_char pro_len;//Э���ַ���ȣ�1���ֽ�
	u_short oper;//�����룬2���ֽڣ�1��������2����ظ�
	u_char src_mac[6];//���ͷ�MAC��6���ֽ�
	u_char src_ip[4];//���ͷ�IP��4���ֽ�
	u_char dest_mac[6];//���շ�MAC��6���ֽ�
	u_char dest_ip[4];//���շ�IP��4���ֽ�
} arp_header;

//IP��ַ
typedef struct ip_address {
	u_char byte1;//IP��ַ��1���ֶ�
	u_char byte2;//IP��ַ��2���ֶ�
	u_char byte3;//IP��ַ��3���ֶ�
	u_char byte4;//IP��ַ��4���ֶ�
} ip_address;

//IPͷ,20
typedef struct ip_header {
#if defined(LITTLE_ENDIAN)//С��ģʽ
	u_char ihl : 4;//��ͷ����
	u_char version : 4;//�汾��
#elif defined(BIG_ENDIAN)//���ģʽ
	u_char version : 4;//�汾��
	u_char  ihl : 4;//��ͷ����
#endif
	u_char tos;//TOS�������ͣ�1���ֽ�
	u_short total_len;//���ܳ���2���ֽ�
	u_short id;//��ʶ��2���ֽ�
	u_short frag_off;//Ƭλ��
	u_char ttl;//����ʱ�䣬1���ֽ�
	u_char proto;//Э�飬1���ֽ�
	u_short check;//У��ͣ�2���ֽ�
	u_int src_addr;//Դ��ַ��4���ֽ�
	u_int dest_addr;//Ŀ�ĵ�ַ��4���ֽ�
	u_int opt;//ѡ��ȣ�4���ֽ�
} ip_header;

//TCPͷ,20
typedef struct tcp_header {
	u_short src_port;//Դ�˿ڵ�ַ��2���ֽ�
	u_short dest_port;//Ŀ�Ķ˿ڵ�ַ��2���ֽ�
	u_int seq;//���кţ�4���ֽ�
	u_int ack_seq;//ȷ�����к� ��4���ֽ�
#if defined(LITTLE_ENDIAN)//С��ģʽ
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
#elif defined(BIG_ENDIAN)//���ģʽ
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
	u_short window;//���ڴ�С��2���ֽ�
	u_short check;//У��ͣ�2���ֽ�
	u_short urg_ptr;//����ָ�룬2���ֽ�
	u_int opt;//ѡ�4���ֽ�
} tcp_header;

//UDPͷ,8
typedef struct udp_header {
	u_short sport;//Դ�˿ڣ�2���ֽ�
	u_short dport;//Ŀ�Ķ˿ڣ�2���ֽ�
	u_short len;//���ݱ����ȣ�2���ֽ�
	u_short check;//У��ͣ�2���ֽ�
} udp_header;

//ICMPͷ,4
struct icmp_header {
	u_char type;//���ͣ�1���ֽ�
	u_char code;//���룬1���ֽ�
	u_char seq;//���кţ�1���ֽ�
	u_char check;//У��ͣ�1���ֽ�
};

typedef struct http_packet {
	CString request_method;  // ��������ķ�������GET��POST��HEAD��OPTIONS��PUT��DELETE��TARCE
	CString request_uri;     // ���������URI����/sample.jsp
	CString request_Protocol_version;// ���������Э���Э��İ汾,��HTTP/1.1

	CString request_accept;  // ���������Accept���� */*
	CString request_referer; // ���������Referer���� http://www.gucas.ac.cn/gucascn/index.aspx
	CString request_accept_language;  // ��������� Accept-language���� zh-cn
	CString request_accept_encoding;  // ��������� Accept_encoding���� gzip��deflate
	CString request_modified_date;  // ���������If-Modified-Since���� Sun,27 Sep 2009 02:33:14 GMT
	CString request_match;         // ���������If-None-Match���� "011d3dc1a3fcal:319"
	CString request_user_agent;  // ���������User-Agent���� Mozilla/4.0(compatible:MSIE 6.0;Windows NT 5.1;SV1;.NET CLR 1.1.4322;.NEt...
	CString request_host;      // ���������Host���� www.gucas.ac.cn
	CString request_connection;// ���������Connection���� Keep-Alive
	CString request_cookie;    // ���������Cookie���� ASP.NET_SessionId=hw15u245x23tqr45ef4jaiqc

	CString request_entity_boy;// ���������ʵ������
							   //===================================================================================
	CString respond_Protocol_version; // ������ӦЭ���Э��İ汾,��HTTP/1.1
	CString respond_status;         // ������Ӧ״̬���룬��200
	CString respond_description;  // ������Ӧ״̬������ı���������OK

	CString respond_content_type; // ������Ӧ���ݵ����ͣ���text/html
	CString respond_charset;      // ������Ӧ�ַ�����UTF-8
	CString respond_content_length; // ������Ӧ���ݵĳ��ȣ���9
	CString respond_connection; // ������Ӧ����״̬����close
	CString respond_Cache_Control; // ������Ӧ����״̬����private
	CString respond_X_Powered_By; // ������Ӧ����״̬����ASP.NET
	CString respond_X_AspNet_Version; // ������Ӧ����״̬����1.1.4322
	CString respond_Set_Cookie; // ������Ӧ����״̬����ASP.NET_SessionId=w0qojdwi0welb4550lafq55;path=/

	CString respond_date;       // ������Ӧ���ڣ���fri,23 Oct 2009 11:15:31 GMT
	CString respond_Etag;       // �������޸ģ���"Ocld8a8cc91:319"
	CString respond_server;     // ������Ӧ������lighttpd

	CString respond_entity_boy; // ������Ӧʵ�����壬��IMOld(8);
}http_packet;

//���������ݽṹ
struct data_packet {
	char type[8];//������
	int time[6];//ʱ��
	int len;//����

	struct eth_header *ethh;//MACͷ
	struct arp_header *arph;//ARPͷ
	struct ipv4_header *ip4h;//IPv4ͷ
	struct ipv6_header *ip6h;//IPv6ͷ
	struct tcp_header *tcph;//TCPͷ
	struct udp_header *udph;//UDPͷ
	struct icmpv4_header *icmp4h;//ICMPv4ͷ
	struct icmpv6_header *icmp6h;//ICMPv6ͷ
	void *apph;//Ӧ�ò��ͷ
};

#endif