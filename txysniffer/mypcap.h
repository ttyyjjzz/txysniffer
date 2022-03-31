#pragma once

#ifndef _MYPCAP_H_
#define _MYPCAP_H_

#include "protocol.h"

class MyPcap
{
public:
	MyPcap(void);
	~MyPcap(void);

private:
	CFile *m_pfileData;  // 保存数据包的文件
	CFile *m_pfileIndex; // 数据包索引文件
	int m_iCurNo;       // 当前序号位置

public:
	void AppendPacket(packet *pkt);
	packet *GetPacket(int m_iNo);

public:
	// 返回本机所有的网卡
	pcap_if_t *  get_ncList();

};

#endif