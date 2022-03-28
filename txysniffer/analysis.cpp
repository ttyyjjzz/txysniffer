#include "stdafx.h"
#include "analysis.h"

//��·�����ݽ���
int analyse_data_frame(const u_char *packet, struct data_packet *data, struct packet_count *count)
{   //packetΪ��������ݰ���data��Ҫ���ڱ����ϵ�����
	struct eth_header *ethh = (struct eth_header*)packet;
	data->ethh = (struct eth_header*)malloc(sizeof(struct eth_header));
	if (data->ethh == NULL)
		return -1;
	for (int i = 0; i < 6; i++)
	{ //��¼Դ��ַ��Ŀ�ĵ�ַ
		data->ethh->src[i] = ethh->src[i];
		data->ethh->dest[i] = ethh->dest[i];
	}
	count->num_total++;//ͳ�Ƹ���
	data->ethh->type = ntohs(ethh->type);//תΪ�����ֽ�˳��

	switch (data->ethh->type)//MACͷ��СΪ14�ֽڣ����֮���ÿ������СҪ+14
	{
	case PROTO_ARP://ARP��
		return analyse_ARP((u_char*)packet + 14, data, count);
		break;
	case PROTO_IP_V4://IPv4��
		return analyse_IPv4((u_char*)packet + 14, data, count);
		break;
	case PROTO_IP_V6://IPv6��
		return analyse_IPv6((u_char*)packet + 14, data, count);
		break;
	default://������
		count->num_other++;
		return -1;
	}
	return 1;
}

//��������ݽ���
int analyse_ARP(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct arp_header *arph = (struct arp_header*)packet;
	data->arph = (struct arp_header*)malloc(sizeof(struct arp_header));
	if (data->arph == NULL)
		return -1;
	for (int i = 0; i < 6; i++)//����IP��MAC
	{
		if (i < 4)
		{
			data->arph->src_ip[i] = arph->src_ip[i];
			data->arph->dest_ip[i] = arph->dest_ip[i];
		}
		data->arph->src_mac[i] = arph->src_mac[i];
		data->arph->dest_mac[i] = arph->dest_mac[i];
	}
	//������Ϣ
	data->arph->hard_len = arph->hard_len;
	data->arph->hard = ntohs(arph->hard);
	data->arph->oper = ntohs(arph->oper);
	data->arph->pro_len = arph->pro_len;
	data->arph->pro = ntohs(arph->pro);
	strcpy(data->type, "ARP");
	count->num_arp++;//ͳ�Ƹ���
	return 1;
}

int analyse_IPv4(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct ipv4_header *iph = (struct ipv4_header*)packet;
	data->ip4h = (struct ipv4_header*)malloc(sizeof(struct ipv4_header));
	if (data->ip4h == NULL)
		return -1;
	//�����Ϣ
	data->ip4h->check = iph->check;
	data->ip4h->src_addr = iph->src_addr;
	data->ip4h->dest_addr = iph->dest_addr;
	data->ip4h->frag_off = iph->frag_off;
	data->ip4h->id = iph->id;
	data->ip4h->proto = iph->proto;
	data->ip4h->total_len = ntohs(iph->total_len);
	data->ip4h->tos = iph->tos;
	data->ip4h->ttl = iph->ttl;
	data->ip4h->ihl = iph->ihl;
	data->ip4h->version = iph->version;
	data->ip4h->opt = iph->opt;
	count->num_ip4++;//ͳ�Ƹ���
	
	int iplen = iph->ihl * 4;//ipͷ����
	switch (iph->proto)
	{
	case V4_PROTO_TCP:
		return analyse_TCP((u_char*)iph + iplen, data, count);
		break;
	case V4_PROTO_UDP:
		return analyse_UDP((u_char*)iph + iplen, data, count);
		break;
	case V4_PROTO_ICMP_V4:
		return analyse_ICMPv4((u_char*)iph + iplen, data, count);
		break;
	default:
		return-1;
	}
	return 1;
}

int analyse_IPv6(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct ipv6_header *iph6 = (struct ipv6_header*)packet;
	data->ip6h = (struct ipv6_header*)malloc(sizeof(struct ipv6_header));
	if (data->ip6h == NULL)
		return -1;
	for (int i = 0; i < 16; i++)
	{
		data->ip6h->src_addr[i] = iph6->src_addr[i];
		data->ip6h->dest_addr[i] = iph6->dest_addr[i];
	}
	//������Ϣ
	data->ip6h->version = iph6->version;
	data->ip6h->flowtype = iph6->flowtype;
	data->ip6h->flowid = iph6->flowid;
	data->ip6h->plen = ntohs(iph6->plen);
	data->ip6h->next_head = iph6->next_head;
	data->ip6h->hop_limit = iph6->hop_limit;
	count->num_ip6++;//ͳ�Ƹ���
	switch (iph6->next_head)//��ʱ����СΪ40�ֽڣ����֮���ÿ������СҪ+40
	{
	case V6_PROTO_TCP:
		return analyse_TCP((u_char*)iph6 + 40, data, count);
		break;
	case V6_PROTO_UDP:
		return analyse_UDP((u_char*)iph6 + 40, data, count);
		break;
	case V6_PROTO_ICMP_V6:
		return analyse_ICMPv6((u_char*)iph6 + 40, data, count);
		break;
	default:
		return-1;
	}
	return 1;
}

//��������ݽ���
int analyse_TCP(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct tcp_header *tcph = (struct tcp_header*)packet;
	data->tcph = (struct tcp_header*)malloc(sizeof(struct tcp_header));
	if (NULL == data->tcph)
		return -1;
	//�����Ϣ
	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->check = tcph->check;
	data->tcph->doff = tcph->doff;
	data->tcph->res1 = tcph->res1;
	data->tcph->cwr = tcph->cwr;
	data->tcph->ece = tcph->ece;
	data->tcph->urg = tcph->urg;
	data->tcph->ack = tcph->ack;
	data->tcph->psh = tcph->psh;
	data->tcph->rst = tcph->rst;
	data->tcph->syn = tcph->syn;
	data->tcph->fin = tcph->fin;
	data->tcph->dest_port = ntohs(tcph->dest_port);
	data->tcph->src_port = ntohs(tcph->src_port);
	data->tcph->seq = tcph->seq;
	data->tcph->urg_ptr = tcph->urg_ptr;
	data->tcph->window = tcph->window;
	data->tcph->opt = tcph->opt;
	
	//http����(Ŀ�Ļ�Դ�˿ں��Ƿ�Ϊ80)
	if (ntohs(tcph->dest_port) == 80 || ntohs(tcph->src_port) == 80) 
	{
		count->num_http++;
		strcpy(data->type, "HTTP");
	}
	else {
		count->num_tcp++;
		strcpy(data->type, "TCP");
	}
	return 1;
}

int analyse_UDP(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct udp_header* udph = (struct udp_header*)packet;
	data->udph = (struct udp_header*)malloc(sizeof(struct udp_header));
	if (NULL == data->udph)
		return -1;
	//�����Ϣ
	data->udph->check = udph->check;
	data->udph->dport = ntohs(udph->dport);
	data->udph->len = ntohs(udph->len);
	data->udph->sport = ntohs(udph->sport);
	strcpy(data->type, "UDP");
	count->num_udp++;//ͳ�Ƹ���
	return 1;
}

int analyse_ICMPv4(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct icmpv4_header* icmph = (struct icmpv4_header*)packet;
	data->icmp4h = (struct icmpv4_header*)malloc(sizeof(struct icmpv4_header));
	if (data->icmp4h == NULL)
		return -1;
	//�����Ϣ
	data->icmp4h->check = icmph->check;
	data->icmp4h->code = icmph->code;
	data->icmp4h->seq = icmph->seq;
	data->icmp4h->type = icmph->type;
	strcpy(data->type, "ICMP");
	count->num_icmp4++;//ͳ�Ƹ���
	return 1;
}

int analyse_ICMPv6(const u_char *packet, struct data_packet *data, struct packet_count *count)
{
	struct icmpv6_header* icmph6 = (struct icmpv6_header*)packet;
	data->icmp6h = (struct icmpv6_header*)malloc(sizeof(struct icmpv6_header));
	if (data->icmp6h == NULL)
		return -1;
	//��·���ַ
	for (int i = 0; i < 6; i++)
		data->icmp6h->op_eth_addr[i] = icmph6->op_eth_addr[i];
	//������Ϣ
	data->icmp6h->check = icmph6->check;
	data->icmp6h->code = icmph6->code;
	data->icmp6h->seq = icmph6->seq;
	data->icmp6h->type = icmph6->type;
	data->icmp6h->op_len = icmph6->op_len;
	data->icmp6h->op_type = icmph6->op_type;
	strcpy(data->type, "ICMPv6");
	count->num_icmp6++;//ͳ�Ƹ���
	return 1;
}