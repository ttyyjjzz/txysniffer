#ifndef PROTOCOL_H
#define PROTOCOL_H

#pragma once
#include "pcap.h"

#define PROTO_ARP 0x0806//ARPЭ������
#define PROTO_IP_V4 0x0800//IPv4Э������
#define PROTO_IP_V6 0x86dd//IPv6Э������

#define V4_PROTO_TCP 6//IPv4ͷ�ṹ�µ�TCPЭ������
#define V4_PROTO_UDP 17//IPv4ͷ�ṹ�µ�UDPЭ������
#define V4_PROTO_ICMP_V4 1//IPv4ͷ�ṹ�µ�ICMPv4Э������

#define V6_PROTO_TCP 0x06//IPv6ͷ�ṹ�µ�TCPЭ������
#define V6_PROTO_UDP 0x11//IPv6ͷ�ṹ�µ�UDPЭ������
#define V6_PROTO_ICMP_V6 0x3a//IPv6ͷ�ṹ�µ�ICMPv6Э������

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321

//MACͷ
struct eth_header {
	u_char dest[6];//Ŀ�ĵ�ַ��6���ֽ�
	u_char src[6];//Դ��ַ��6���ֽ�
	u_short type;//���ͣ�2���ֽ�
};

//ARPͷ
struct arp_header {
	u_short hard;//Ӳ�����ͣ�2���ֽ�
	u_short pro;//Э�����ͣ�2���ֽ�
	u_char hard_len;//Ӳ����ַ���ȣ�1���ֽ�
	u_char pro_len;//Э���ַ���ȣ�1���ֽ�
	u_short oper;//�����룬2���ֽڣ�1��������2����ظ�
	u_char src_mac[6];//���ͷ�MAC��6���ֽ�
	u_char src_ip[4];//���ͷ�IP��4���ֽ�
	u_char dest_mac[6];//���շ�MAC��6���ֽ�
	u_char dest_ip[4];//���շ�IP��4���ֽ�
};

//IPv4ͷ
struct ipv4_header {
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
};

//IPv6ͷ
struct ipv6_header {
	u_int version : 4,//�汾
		flowtype : 8,//�����ͣ�8λ
		flowid : 20;//����ǩ��20λ
	u_short plen;//Э�鳤�ȣ�2���ֽ�
	u_char next_head;//��һ��ͷ����1���ֽ�
	u_char hop_limit;//�����ƣ�1���ֽ�
	u_short src_addr[8];//Դ��ַ��2���ֽ�
	u_short dest_addr[8];//Ŀ�ĵ�ַ��2���ֽ�
};

//TCPͷ
struct tcp_header {
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
};

//UDPͷ
struct udp_header {
	u_short sport;//Դ�˿ڣ�2���ֽ�
	u_short dport;//Ŀ�Ķ˿ڣ�2���ֽ�
	u_short len;//���ݱ����ȣ�2���ֽ�
	u_short check;//У��ͣ�2���ֽ�
};

//ICMPv4ͷ
struct icmpv4_header {
	u_char type;//���ͣ�1���ֽ�
	u_char code;//���룬1���ֽ�
	u_char seq;//���кţ�1���ֽ�
	u_char check;//У��ͣ�1���ֽ�
};

//ICMPv6ͷ
struct icmpv6_header {
	u_char type;//���ͣ�1���ֽ�
	u_char code;//���룬1���ֽ�
	u_char seq;//���кţ�1���ֽ�
	u_char check;//У��ͣ�1���ֽ�
	u_char op_type;//ѡ����ͣ�1���ֽ�
	u_char op_len;//ѡ����ȣ�1���ֽ�
	u_char op_eth_addr[6];//ѡ���·���ַ��1���ֽ�
};

//����
typedef struct packet_count
{
	int num_arp;//ARP
	int num_ip4;//IPv4
	int num_ip6;//IPv6
	int num_udp;//UDP
	int num_tcp;//TCP
	int num_icmp4;//ICMPv4
	int num_icmp6;//ICMPv6
	int num_http;//HTTP
	int num_other;//����
	int num_total;//�ܼ�
};

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