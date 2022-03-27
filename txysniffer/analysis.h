#pragma once
#include "protocol.h"

int analyse_data_frame(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_ARP(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_IPv4(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_IPv6(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_TCP(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_UDP(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_ICMPv4(const u_char *packet, struct data_packet *data, struct packet_count *count);
int analyse_ICMPv6(const u_char *packet, struct data_packet *data, struct packet_count *count);


