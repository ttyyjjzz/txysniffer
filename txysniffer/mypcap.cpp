#include "StdAfx.h"
#include "mypcap.h"


// file process
MyPcap::MyPcap(void) :m_iCurNo(0)
{
	//使用GetModuleFileName获取应用程序路径
	TCHAR szModuleName[MAX_PATH];
	::GetModuleFileName(NULL, szModuleName, MAX_PATH);
	CString strDir = szModuleName;
	strDir = strDir.Left(strDir.ReverseFind(TEXT('\\'))); // Left() -> Extracts the leftmost nCount characters from this CStringT object and returns a copy of the extracted substring

	CString fileData;
	fileData.Format(TEXT("%s\\packet.dmp"), strDir);
	m_pfileData = new CFile(fileData, CFile::modeCreate | CFile::modeReadWrite); //create or write data(packet) file

	CString fileIndex;
	fileIndex.Format(TEXT("%s\\packet.idx"), strDir);
	m_pfileIndex = new CFile(fileIndex, CFile::modeCreate | CFile::modeReadWrite); //create or write index(packet) file
}

MyPcap::~MyPcap(void)
{
	if (m_pfileData)
	{
		m_pfileData->Close();
		delete m_pfileData;
		m_pfileData = NULL; // safer
	}
	if (m_pfileIndex)
	{
		m_pfileIndex->Close();
		delete m_pfileIndex;
		m_pfileIndex = NULL;
	}
}

// Append packet
void MyPcap::AppendPacket(packet *pkt)
{
	const pcap_pkthdr *header = pkt->header;
	const u_char *data = pkt->pkt_data;
	++m_iCurNo;

	packet_index index;
	index.no = m_iCurNo;
	index.pos = m_pfileData->GetPosition();
	index.len = sizeof(pcap_pkthdr) + header->len;

	m_pfileIndex->SeekToEnd();
	m_pfileIndex->Write(&index, sizeof(packet_index));

	m_pfileData->SeekToEnd();
	m_pfileData->Write(header, sizeof(pcap_pkthdr));
	m_pfileData->Write(data, header->len);

	m_pfileIndex->Flush(); // write from memory to disk immediatly
	m_pfileData->Flush();
}

// Get packet
packet * MyPcap::GetPacket(int m_iNo)
{
	int iPos = (m_iNo - 1) * sizeof(packet_index);
	packet_index pIndex;

	m_pfileIndex->Seek(iPos, CFile::begin);
	m_pfileIndex->Read(&pIndex, sizeof(packet_index));

	m_pfileData->Seek(pIndex.pos, CFile::begin);
	byte *buffer = new byte[pIndex.len];
	m_pfileData->Read(buffer, pIndex.len);

	packet *pkt = new packet();
	pkt->header = (pcap_pkthdr *)buffer;
	pkt->pkt_data = (u_char *)(buffer + sizeof(pcap_pkthdr));

	return pkt;
}

// 返回本机所有的网卡
pcap_if_t *  MyPcap::get_ncList()
{
	char errorBufffer[PCAP_ERRBUF_SIZE];
	pcap_if_t* m_allncs = new pcap_if_t();
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_allncs, errorBufffer) == -1)
	{
		CString errmsg;
		USES_CONVERSION;
		errmsg.Format(_T("列出网卡错误: %s\n"), A2W(errorBufffer));
		AfxMessageBox(errmsg);
		return NULL;
	}
	else if (m_allncs == NULL)
	{
		AfxMessageBox(_T("列出网卡错误"));
		return NULL;
	}
	else
		return m_allncs;
}

