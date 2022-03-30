
// txysnifferDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "txysniffer.h"
#include "txysnifferDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include "protocol.h"

/*#include <vector>
using namespace std;*/

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

#define M_MESSAGEWINPCAP (WM_USER+50)
char *filter;
static HWND hDlgHandle;
DWORD WINAPI txysniffer_capThread(LPVOID lpParameter);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CtxysnifferDlg �Ի���



CtxysnifferDlg::CtxysnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_TXYSNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CtxysnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BUTTON1, m_startbutton);
	DDX_Control(pDX, IDC_BUTTON2, m_stopbutton);
	DDX_Control(pDX, IDC_BUTTON3, m_clearbutton);
	DDX_Control(pDX, IDC_BUTTON4, m_exitbutton);
	DDX_Control(pDX, IDC_COMBO1, m_netcardComboBox);
	DDX_Control(pDX, IDC_EDIT1, m_TCPedit);
	DDX_Control(pDX, IDC_EDIT2, m_UDPedit);
	DDX_Control(pDX, IDC_EDIT3, m_HTTPedit);
	DDX_Control(pDX, IDC_EDIT4, m_ARPedit);
	DDX_Control(pDX, IDC_EDIT5, m_IPedit);
	DDX_Control(pDX, IDC_EDIT7, m_ICMPedit);
	DDX_Control(pDX, IDC_EDIT10, m_elseedit);
	DDX_Control(pDX, IDC_EDIT11, m_totaledit);
	DDX_Control(pDX, IDC_EDIT12, m_edit);//���ݰ�������ʾ
	DDX_Control(pDX, IDC_LIST1, m_list);
	DDX_Control(pDX, IDC_TREE1, m_tree);
	DDX_Control(pDX, IDC_CHECK1, m_ALLcheck);
	DDX_Control(pDX, IDC_CHECK2, m_ARPcheck);
	DDX_Control(pDX, IDC_CHECK3, m_IPcheck);
	DDX_Control(pDX, IDC_CHECK4, m_TCPcheck);
	DDX_Control(pDX, IDC_CHECK5, m_UDPcheck);
	DDX_Control(pDX, IDC_CHECK6, m_ICMPcheck);
	DDX_Control(pDX, IDC_CHECK7, m_HTTPcheck);
	DDX_Control(pDX, IDC_CHECK8, m_FTPcheck);
}

BEGIN_MESSAGE_MAP(CtxysnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CtxysnifferDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CtxysnifferDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CtxysnifferDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CtxysnifferDlg::OnBnClickedButton4)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CtxysnifferDlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CtxysnifferDlg::OnNMCustomdrawList1)
END_MESSAGE_MAP()


// CtxysnifferDlg ��Ϣ�������

//�����ʼ������
BOOL CtxysnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
    
	//���ݰ��б����
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list.InsertColumn(0, _T("���"), 2, 50);//2����
	m_list.InsertColumn(1, _T("ʱ��"), 2, 200);
	m_list.InsertColumn(2, _T("����"), 2, 100);
	m_list.InsertColumn(3, _T("ԴMAC��ַ"), 2, 200);
	m_list.InsertColumn(4, _T("Ŀ��MAC��ַ"), 2, 200);
	m_list.InsertColumn(5, _T("Э��"), 2, 100);
	m_list.InsertColumn(6, _T("ԴIP��ַ"), 2, 150);
	m_list.InsertColumn(7, _T("Ŀ��IP��ַ"), 2, 150);

	//������
	m_netcardComboBox.AddString(_T("��ѡ������(��ѡ)"));
	txysniffer_initCap();//��ȡ����������ʾ����������
		return FALSE;
	m_netcardComboBox.SetCurSel(0);//Ĭ����ʾ

	//Э��ѡ��CheckBox
	m_ALLcheck.GetCheck() == BST_CHECKED;
	m_ARPcheck.GetCheck() == BST_UNCHECKED;
	m_IPcheck.GetCheck() == BST_UNCHECKED;
	m_TCPcheck.GetCheck() == BST_UNCHECKED;
	m_UDPcheck.GetCheck() == BST_UNCHECKED;
	m_ICMPcheck.GetCheck() == BST_UNCHECKED;
	m_HTTPcheck.GetCheck() == BST_UNCHECKED;
	m_FTPcheck.GetCheck() == BST_UNCHECKED;

	return TRUE;// ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CtxysnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CtxysnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CtxysnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//////////////////////1.1��ʼ��winpcap//////////////////////
void CtxysnifferDlg::txysniffer_initCap()
{
	pcap_if_t *allncs;//�����б�
	pcap_if_t *nc;//����
	int ncCount;//��������
	char errorBufffer[PCAP_ERRBUF_SIZE];//���󻺳���

	ncCount = 0;
	if (pcap_findalldevs(&allncs, errorBufffer) == -1)
		return ;
	for (nc = allncs; nc; nc = nc->next)
	{
		if (nc->description)
			m_netcardComboBox.AddString(CString(nc->description));
		ncCount++;
	}
}

//////////////////////1.2���ݰ�ץȡ//////////////////////
DWORD WINAPI txysniffer_capThread(LPVOID lpParameter)
{
	pcap_if_t *allncs;//�����б�
	pcap_if_t *nc;//����
	pcap_t *dpHandle;//����
	char errorBufffer[PCAP_ERRBUF_SIZE];//���󻺳���

	CtxysnifferDlg *pthis = (CtxysnifferDlg*)lpParameter;

	//(1)������ѡ������
	int ncIndex;//��������

	ncIndex = pthis->m_netcardComboBox.GetCurSel();
	if (ncIndex == 0 || ncIndex == CB_ERR)
	{
		MessageBox(_T("��ѡ����ʵ������ӿ�"));
		return -1;
	}

	//(2)���ѡ������
	int dataPackageLen = 65536;//���ݰ�����
	int mode = 1;//����ģʽ��־
	int overtime = 1000;//����ʱʱ��

	nc = allncs;
	for (int i = 0; i < ncIndex - 1; i++)
		nc = nc->next;
	dpHandle = pcap_open_live(nc->name, dataPackageLen, mode, overtime, errorBufffer);//��ָ�������ӿ�
	if (dpHandle == NULL)
	{
		MessageBox(_T("�����ӿ��޷���") + CString(nc->description));
		pcap_freealldevs(allncs);//�ͷ��豸�б�
		return -1;
	}

	//(3)����Ƿ�����̫��
	if (pcap_datalink(dpHandle) != DLT_EN10MB)
	{
		MessageBox(_T("����̫����"));
		pcap_freealldevs(allncs);//�ͷ��豸�б�
		return -1;
	}

	//(4)������������
	u_int netmask;//��������
	if (nc->addresses != NULL)
		netmask = ((struct sockaddr_in *)(nc->addresses->netmask))->sin_addr.S_un.S_addr;
	else//���ӿ�û�е�ַ������һ��C�������
		netmask = 0xffffff;

	//(5)���������
	struct bpf_program fcode;

	if (pcap_compile(dpHandle, &fcode, filter, 1, netmask) < 0)
	{
		MessageBox(_T("�޷����������"));
		pcap_freealldevs(allncs);//�ͷ��豸�б�
		return -1;
	}

	//(6)���ù�����
	if (pcap_setfilter(dpHandle, &fcode) < 0)
	{
		MessageBox(_T("���������ô���"));
		pcap_freealldevs(allncs);//�ͷ��豸�б�
		return -1;
	}

	pcap_freealldevs(allncs);//�ͷ��豸�б�	
	pcap_loop(dpHandle, 0, packet_handler, NULL);
	pcap_close(dpHandle);

	return 1;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	pcap_pkthdr *header2 = new pcap_pkthdr;
	u_char *pkt_data2 = new u_char[header->len];

	memcpy(header2,header,sizeof(pcap_pkthdr));
	memcpy(pkt_data2,pkt_data,header->len);

	//����Ϣ�������
	::PostMessage(hDlgHandle, M_MESSAGEWINPCAP, (WPARAM)header2, (LPARAM)pkt_data2);

}

//////////////////////2Э�����//////////////////////
//��ȡEthernet����
int CtxysnifferDlg::get_MacType(CString &eth_strType, u_short eth_Type, bool isFirst)
{
	if (isFirst)
		num_total++;

	switch (eth_Type)
	{
	case PROTO_ARP://ARP��
		eth_strType = TEXT("ARP");
		if (isFirst)
			num_arp++;
		break;
	case PROTO_IP://IP��
		eth_strType = TEXT("IP");
		if (isFirst)
			num_ip++;
		break;
	case PROTO_RARP:
		eth_strType = TEXT("RARP");
		break;
	case PROTO_PPP:
		eth_strType = TEXT("PPP");
		break;
	case PROTO_SNMP:
		eth_strType = TEXT("SNMP");
		break;
	default://������
		eth_strType = TEXT("other");
		break;
	}
	return 1;
}

//��ȡMac��ַ
int CtxysnifferDlg::get_MacAddress(TCHAR * eth_dMac, u_char eth_sMac[])
{
	swprintf_s(
		eth_dMac,
		18,
		TEXT("%02X-%02X-%02X-%02X-%02X-%02X"),
		eth_sMac[0],
		eth_sMac[1],
		eth_sMac[2],
		eth_sMac[3],
		eth_sMac[4],
		eth_sMac[5]);
	return 1;
}

//��ȡIP����
int CtxysnifferDlg::get_IPType(CString &ip_strIP, u_short ip_Type, bool isFirst)
{
	switch (ip_Type)
	{
	case PROTO_TCP:
		ip_strIP = TEXT("TCP");
		if (isFirst)
			num_tcp++;
		break;
	case PROTO_UDP:
		ip_strIP = TEXT("UDP");
		if (isFirst)
			num_udp++;
		break;
	case PROTO_ICMP:
		ip_strIP = TEXT("ICMP");
		if (isFirst)
			num_icmp++;
		break;
	default:
		ip_strIP = TEXT("other");
		break;
	}
	return 1;
}

//��ȡIP��ַ
int CtxysnifferDlg::get_IPAddress(TCHAR * ip_Address, ip_address *ip_addr)
{
	swprintf_s(
		ip_Address,
		16,
		TEXT("%d.%d.%d.%d"),
		ip_addr->byte1,
		ip_addr->byte2,
		ip_addr->byte3,
		ip_addr->byte4);
	return 1;
}

//////////////////////3����//////////////////////
//�������ݰ�ͳ��
int CtxysnifferDlg::txysniffer_updatePacket()
{
	CString strnum;
	strnum.Format(_T("%d"), num_arp);
	this->m_ARPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_ip);
	this->m_IPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_tcp);
	this->m_TCPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_udp);
	this->m_UDPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_icmp);
	this->m_ICMPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_http);
	this->m_HTTPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_ftp);
	this->m_elseedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), num_total);
	this->m_totaledit.SetWindowText(strnum);

	return 1;
}

//�����б�����Э�������������Ϣ��ʾ���б���
int CtxysnifferDlg::txysniffer_updateList()
{
	if (m_ALLcheck.GetCheck() == BST_CHECKED)//all
	{
		char * pstr = "";
		filter = pstr;
	}
	else if (m_IPcheck.GetCheck() == BST_CHECKED)//ip
	{
		char * pstr = "ip";
		filter = pstr;
	}
	else if (m_ARPcheck.GetCheck() == BST_CHECKED && m_IPcheck.GetCheck() == BST_UNCHECKED)//only arp
	{
		char * pstr = "arp";
		filter = pstr;
	}
	else if (m_ARPcheck.GetCheck() == BST_CHECKED && m_IPcheck.GetCheck() == BST_CHECKED)//ip and arp
	{
		char * pstr = "ip and arp";
		filter = pstr;
	}
	else if (m_TCPcheck.GetCheck() == BST_CHECKED && m_IPcheck.GetCheck() == BST_UNCHECKED)//only tcp 
	{
		char * pstr = "ip and tcp";
		filter = pstr;
	}
	else if (m_UDPcheck.GetCheck() == BST_CHECKED && m_IPcheck.GetCheck() == BST_UNCHECKED)//only udp
	{
		char * pstr = "ip and udp";
		filter = pstr;
	}
	else if (m_ICMPcheck.GetCheck() == BST_CHECKED && m_IPcheck.GetCheck() == BST_UNCHECKED)//noly icmp
	{
		char * pstr = "ip and icmp";
		filter = pstr;
	}

	UpdateData(true);  // �ѿؼ���ֵ������Ӧ�ı���
	UpdateData(false); // �ѱ�����ֵ���ݸ��ؼ�
	
	/*//�������ݰ��������汾�ػ��������
	u_char *data_packet_list;
	data_packet_list = (u_char*)malloc(data_header->len);
	memcpy(data_packet_list, pkt_data, data_header->len);

	this->m_localDataList.AddTail(data);
	this->m_netDataList.AddTail(data_packet_list);

	//��ȡ����
	data->len = data_header->len;
	//��ȡʱ��
	time_t local_tv_sec = data_header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	data->time[0] = ltime->tm_year + 1900;
	data->time[1] = ltime->tm_mon + 1;
	data->time[2] = ltime->tm_mday;
	data->time[3] = ltime->tm_hour;
	data->time[4] = ltime->tm_min;
	data->time[5] = ltime->tm_sec;

	//Ϊ�½��յ������ݰ����б�ؼ����½���
	CString buffer;
	buffer.Format(_T("%d"), this->packetNum);
	int nextItem = this->m_list.InsertItem(this->packetNum, buffer);

	//ʱ���
	CString timestr;
	timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
		data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
	this->m_list.SetItemText(nextItem, 1, timestr);

	//����
	buffer.Empty();
	buffer.Format(_T("%d"), data->len);
	this->m_list.SetItemText(nextItem, 2, buffer);

	//ԴMAC
	buffer.Empty();
	buffer.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
		data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
	this->m_list.SetItemText(nextItem, 3, buffer);

	//Ŀ��MAC
	buffer.Empty();
	buffer.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
		data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
	this->m_list.SetItemText(nextItem, 4, buffer);

	//Э��
	this->m_list.SetItemText(nextItem, 5, CString(data->type));

	//ԴIP
	buffer.Empty();
	if (data->ethh->type == PROTO_ARP) {
		buffer.Format(_T("%d.%d.%d.%d"), data->arph->src_ip[0],
			data->arph->src_ip[1], data->arph->src_ip[2], data->arph->src_ip[3]);
	}
	else if (data->ethh->type == PROTO_IP_V4) {
		struct  in_addr in;
		in.S_un.S_addr = data->ip4h->src_addr;
		buffer = CString(inet_ntoa(in));
	}
	else if (data->ethh->type == PROTO_IP_V6) {
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				buffer.AppendFormat(_T("%02x:"), data->ip6h->src_addr[i]);
			else
				buffer.AppendFormat(_T("%02x"), data->ip6h->src_addr[i]);
		}
	}
	this->m_list.SetItemText(nextItem, 6, buffer);

	//Ŀ��IP
	buffer.Empty();
	if (data->ethh->type == PROTO_ARP) {
		buffer.Format(_T("%d.%d.%d.%d"), data->arph->dest_ip[0],
			data->arph->dest_ip[1], data->arph->dest_ip[2], data->arph->dest_ip[3]);
	}
	else if (data->ethh->type == PROTO_IP_V4) {
		struct in_addr in;
		in.S_un.S_addr = data->ip4h->dest_addr;
		buffer = CString(inet_ntoa(in));
	}
	else if (data->ethh->type == PROTO_IP_V6) {
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				buffer.AppendFormat(_T("%02x:"), data->ip6h->dest_addr[i]);
			else
				buffer.AppendFormat(_T("%02x"), data->ip6h->dest_addr[i]);
		}
	}
	this->m_list.SetItemText(nextItem, 7, buffer);

	this->packetNum++;//������*/
	return 1;
}

//���±༭��
int CtxysnifferDlg::txysniffer_updateEdit(CEdit & medit, packet *pkt)
{
	const struct pcap_pkthdr *header = pkt->header;
	const u_char *pkt_data = pkt->pkt_data;
	u_int pkt_dataLen = header->len;//�õ�����Packet_Data���ݰ��ĳ���
	CString buffer = NULL;
	CString chrAppend = NULL;
	u_int row = 0;

	//���ݸ�ʽ����ʾ
	for (int i = 0; i < pkt_dataLen; i++)
	{
		CString strAppend = NULL;
		if ((i % 16) == 0)// ȡ�࣬����
		{
			row++;
			if (i == 0)
			{
				buffer += chrAppend;
				strAppend.Format(TEXT(" 0X%04X:   "), row);
				buffer += strAppend;
			}
			else
			{
				buffer += TEXT("==>> ") + chrAppend;
				strAppend.Format(TEXT("\x0d\x0a 0X%04X ->  "), row); //0x0d:�س�; 0x0a:����;0X:��ʾ16������ʾ;%04x��ʾ��4λ��16������ʾ����0����λ; eRows����ʾ������16���Ƹ�ʽ��ʾ��
				buffer += strAppend;
			}
			chrAppend = "";//reset
		}
		strAppend.Format(TEXT("%02x "), pkt_data[i]);
		buffer += strAppend;
		if (i>2 && pkt_data[i - 1] == 13 && pkt_data[i] == 10)//��������س������У���ֱ�Ӽ���������ʹ��ʾ�ַ�����
			continue;
		strAppend.Format(TEXT("%c"), pkt_data[i]);
		chrAppend += strAppend;
	}
	if (chrAppend != "")
		buffer += TEXT("==>> ") + chrAppend;

	medit.SetWindowTextW(buffer);

	return 1;
}

//�������ο�.��·��
int CtxysnifferDlg::txysniffer_updateTree_mac(HTREEITEM & hItem, const u_char * pkt_data)
{
	eth_header *mac_hdr = (eth_header *)pkt_data;
	hItem = m_tree.InsertItem(_T("��·��"));
	CString str = NULL;
	CString mac_strType = NULL;
	TCHAR mac_srcAddr[18];
	TCHAR mac_dstAddr[18];

	get_MacType(mac_strType, ntohs(mac_hdr->type), false);
	str.Format(_T("���ͣ�0x%02x"), mac_strType);
	m_tree.InsertItem(str, hItem);

	get_MacAddress(mac_srcAddr, mac_hdr->src);
	str.Format(_T("ԴMAC��"), mac_srcAddr);
	m_tree.InsertItem(str, hItem);

	get_MacAddress(mac_dstAddr, mac_hdr->dest);
	str.Format(_T("Ŀ��MAC��"), mac_dstAddr);
	m_tree.InsertItem(str, hItem);

	return 1;
}
	//�����
	/*//ARPͷ
	if (localData->ethh->type == PROTO_ARP)
	{
		HTREEITEM arp = this->m_tree.InsertItem(_T("ARPͷ"), data);
		str.Format(_T("Ӳ�����ͣ�%d"), localData->arph->hard);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("Э�����ͣ�0x%02x"), localData->arph->pro);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("Ӳ����ַ���ȣ�%d"), localData->arph->hard_len);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("Э���ַ���ȣ�%d"), localData->arph->pro_len);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("�����룺%d"), localData->arph->oper);
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("���ͷ�MAC��"));
		for (int i = 0; i < 6; i++) 
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), localData->arph->src_mac[i]);
			else
				str.AppendFormat(_T("%02x"), localData->arph->src_mac[i]);
		}
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("���ͷ�IP��"));
		for (int i = 0; i < 4; i++) 
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), localData->arph->src_ip[i]);
			else
				str.AppendFormat(_T("%d"), localData->arph->src_ip[i]);
		}
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("���շ�MAC��"));
		for (int i = 0; i < 6; i++) 
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), localData->arph->dest_mac[i]);
			else
				str.AppendFormat(_T("%02x"), localData->arph->dest_mac[i]);
		}
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("���շ�IP��"));
		for (int i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), localData->arph->dest_ip[i]);
			else
				str.AppendFormat(_T("%d"), localData->arph->dest_ip[i]);
		}
		this->m_tree.InsertItem(str, arp);
	}*/


int CtxysnifferDlg::txysniffer_updateTree_ip(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	hItem = m_tree.InsertItem(_T("�����"));
	CString str = NULL;

	str.Format(_T("�汾��%d"), ip_hdr->version);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("IPͷ����%d"), ip_hdr->ihl);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("�������ͣ�%d"), ip_hdr->tos);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("�ܳ��ȣ�%d"), ip_hdr->total_len);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("��ʶ��0x%02x"), ip_hdr->id);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("��ƫ�ƣ�%d"), ip_hdr->frag_off);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("�����ڣ�%d"), ip_hdr->ttl);
	m_tree.InsertItem(str, hItem);
	CString ip_strProtocol = NULL;
	get_IPType(ip_strProtocol, ip_hdr->proto, false);
	str.Format(_T("Э�飺%d"), ip_strProtocol);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("ͷ��У��ͣ�0x%02x"), ip_hdr->check);
	m_tree.InsertItem(str, hItem);
	TCHAR ip_srcAddr[16];
	TCHAR ip_dstAddr[16];
	get_IPAddress(ip_srcAddr, &ip_hdr->src_addr);
	get_IPAddress(ip_dstAddr, &ip_hdr->dest_addr);
	str.Format(_T("ԴIP��%s"), ip_srcAddr);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("Ŀ��IP��%s"), ip_dstAddr);
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_tcp(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4; //һ��4�ֽڣ��ʳ���4
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	hItem = m_tree.InsertItem(_T("TCPЭ��ͷ"));
	CString str = NULL;

	str.Format(_T("  Դ�˿�:%d"), ntohs(tcp_hdr->src_port));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  Ŀ�Ķ˿�:%d"), ntohs(tcp_hdr->dest_port));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  ���к�:0x%02x"), ntohl(tcp_hdr->seq));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  ȷ�Ϻ�:%d"), ntohl(tcp_hdr->ack_seq));
	m_tree.InsertItem(str, hItem);

	HTREEITEM flag = m_tree.InsertItem(_T(" +��־λ"), hItem);
	str.Format(_T("cwr %d"), tcp_hdr->cwr);
	m_tree.InsertItem(str, flag);
	str.Format(_T("ece %d"), tcp_hdr->ece);
	m_tree.InsertItem(str, flag);
	str.Format(_T("urg %d"), tcp_hdr->urg);
	m_tree.InsertItem(str, flag);
	str.Format(_T("ack %d"), tcp_hdr->ack);
	m_tree.InsertItem(str, flag);
	str.Format(_T("psh %d"), tcp_hdr->psh);
	m_tree.InsertItem(str, flag);
	str.Format(_T("rst %d"), tcp_hdr->rst);
	m_tree.InsertItem(str, flag);
	str.Format(_T("syn %d"), tcp_hdr->syn);
	m_tree.InsertItem(str, flag);
	str.Format(_T("fin %d"), tcp_hdr->fin);
	m_tree.InsertItem(str, flag);
	str.Format(_T("  ����ָ��:%d"), tcp_hdr->urg_ptr);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  У���:0x%02x"), tcp_hdr->check);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  ���ڴ�С:%d"), tcp_hdr->window);
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_udp(HTREEITEM & hItem, const u_char * pkt_data)
{
	//UDPͷ
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	udp_header *udp_hdr = (udp_header *)(pkt_data + 14 + ip_hdrLen);

	hItem = m_tree.InsertItem(_T("UDPЭ��ͷ"));
	CString str = NULL;

	str.Format(_T("Դ�˿�:%d"), ntohs(udp_hdr->sport));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("Ŀ�Ķ˿�:%d"), ntohs(udp_hdr->dport));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("�ܳ���:%d"), ntohs(udp_hdr->len));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("У���:0x%02x"), ntohs(udp_hdr->check));
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_icmp(HTREEITEM & hItem, const u_char * pkt_data)
{
	//ICMPͷ
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	icmp_header *icmp_hdr = (icmp_header *)(pkt_data + 14 + ip_hdrLen);
	
	hItem = m_tree.InsertItem(_T("ICMPv4ͷ"));
	CString str = NULL;
	str.Format(_T("����:%d"), icmp_hdr->type);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("����:%d"), icmp_hdr->code);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("���:%d"), icmp_hdr->seq);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("У���:%d"), ntohs(icmp_hdr->check));
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_http(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->doff * 4;

	u_char *http_pkt = (u_char *)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->total_len) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);
																			 //http_packet * http_pktHdr = new http_packet ;// HTTP packet's  struct
	vector<CString> strVecRequestHttp;//��������ͷ����
	vector<CString> strVecRespondHttp;//������Ӧͷ����
	CString chrVecTmp = NULL;//����������������ʱ�ַ�
	CString strVecTmp = NULL;//����������������ʱ�ַ���

	u_char * pchrHttpAllData = NULL;//����HTTPЭ�������ʼλ�ã���������ͷ����Ӧͷ����
	u_char * pchrHttpRequestPos = NULL;//����HTTPЭ���������ͷ����ʼλ��
	u_char * pchrHttpRespondPos = NULL;//����HTTPЭ�������Ӧͷ����ʼλ��
	pchrHttpAllData = http_pkt;//��ֵ�õ�HTTPЭ����Ŀ�ʼλ��

	CString strHttpALLData = NULL;//����HTTPЭ��������ݰ�,��������ͷ����Ӧͷ����
	CString strHttpRequestData = NULL;//����HTTPЭ���������ͷ������
	CString strHttpRespondData = NULL;//����HTTPЭ�������Ӧͷ������

	u_short httpAllPos = 0;
	u_short httpAllLen = 0;
	httpAllLen = http_pktLen;

	if (IsHTTP(pkt_data)) // check is http
	{
		// show request to tree
		hItem = m_tree.InsertItem(_T("HTTPͷ"));

		if (*pkt_data == 'H') // �����һ���ַ�ΪH����������HTTP��ͷ�ģ���Ϊ��Ӧͷ������ӦΪ����ͷ
		{
			for (int i = 0; i<httpAllLen; i++) // get http_Get data
			{
				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); // format
				strHttpRespondData += chrVecTmp;//��¼������HTTP��Ӧͷ������

				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); //��¼ÿһ�е����ݣ�����������ʱ�ַ�����
				strVecTmp += chrVecTmp;
				if (i>2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //���ݻس����з��жϣ�����ÿ�б�����vector������
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}

			HTREEITEM childhItem = m_tree.InsertItem(_T("Request Header:"), hItem);
			for (u_short irequest = 0; irequest<strVecRequestHttp.size(); irequest++)
				m_tree.InsertItem(strVecRequestHttp[irequest], childhItem);
		}
		else
		{
			for (int i = 0; i<httpAllLen; i++) // get http_Get data
			{
				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); // format
				strHttpRequestData += chrVecTmp;//��¼������HTTP��Ӧͷ������

				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); //��¼ÿһ�е����ݣ�����������ʱ�ַ�����
				strVecTmp += chrVecTmp;
				if (i>2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //���ݻس����з��жϣ�����ÿ�б�����vector������
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}

			HTREEITEM childhItem = m_tree.InsertItem(_T("Respond Header:"), hItem);
			for (u_short irespond = 0; irespond<strVecRespondHttp.size(); irespond++)
				m_tree.InsertItem(strVecRespondHttp[irespond], childhItem);
		}
	}
}

bool CtxysnifferDlg::IsHTTP(const u_char *pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->doff * 4;

	u_char *http_pkt = (u_char *)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->total_len) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	CString chrTmp = NULL;
	CString strTmp = NULL;
	CString strHttp = NULL;

	int httpPos = 0;

	if (ip_hdr->proto == 6)
	{
		for (int i = 0; i<http_pktLen; i++) // ����ȡ��һ���Ƿ���HTTP�ַ���
		{
			chrTmp.Format(_T("%c"), http_pkt[i]);
			strTmp += chrTmp;
			if (i>2 && http_pkt[i - 1] == 13 && http_pkt[i] == 10)
				break;
		}
		httpPos = strTmp.Find(_T("HTTP"), 0);

		if (httpPos != -1 && httpPos != 65535) // �����һ�к����ַ���HTTP����ΪHTTPЭ��
		{
			num_http++;
			return true;
		}
		else
			return false;
	}
	return false;
}

void CtxysnifferDlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	//�������
	this->packetNum = 1; //���¼���
	this->m_localDataList.RemoveAll();
	this->m_netDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));
	this->txysniffer_updatePacket();

	if (this->txysniffer_startCap() < 0)
		return;

	this->m_list.DeleteAllItems();
	this->m_tree.DeleteAllItems();
	this->m_edit.SetWindowText(_T(""));
	this->m_startbutton.EnableWindow(FALSE);
	this->m_stopbutton.EnableWindow(TRUE);
	this->m_clearbutton.EnableWindow(FALSE);
}


void CtxysnifferDlg::OnBnClickedButton2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	
	if (this->m_ThreadHandle == NULL)
		return;
	if (TerminateThread(this->m_ThreadHandle, -1) == 0) 
	{
		MessageBox(_T("�̹߳رմ������Ժ�����"));
		return;
	}
	this->m_ThreadHandle = NULL;
	this->m_startbutton.EnableWindow(TRUE);
	this->m_stopbutton.EnableWindow(FALSE);
	this->m_clearbutton.EnableWindow(TRUE);
}


void CtxysnifferDlg::OnBnClickedButton3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//�������
	this->m_list.DeleteAllItems();
	this->packetNum = 1;
	this->m_localDataList.RemoveAll();
	this->m_netDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));

}


void CtxysnifferDlg::OnBnClickedButton4()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void CtxysnifferDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	POSITION pos = m_list.GetFirstSelectedItemPosition();
	int index = m_list.GetNextSelectedItem(pos); //��ȡ�б�ؼ���ǰѡ����к�
	if (index != -1) 
	{
		this->txysniffer_updateEdit(index);//���¶�Ӧ�еı༭��
		this->txysniffer_updateTree(index);//���¶�Ӧ�е����ο�
	}
	*pResult = 0;
}
