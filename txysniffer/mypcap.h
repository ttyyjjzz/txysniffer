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
	CFile *m_pfileData;  // �������ݰ����ļ�
	CFile *m_pfileIndex; // ���ݰ������ļ�
	int m_iCurNo;       // ��ǰ���λ��

public:
	void AppendPacket(packet *pkt);
	packet *GetPacket(int m_iNo);

public:
	// ���ر������е�����
	pcap_if_t *  get_ncList();

};

#endif