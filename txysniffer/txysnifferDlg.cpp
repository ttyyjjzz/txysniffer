
// txysnifferDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "txysniffer.h"
#include "txysnifferDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include "protocol.h"
#include "analysis.h"

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

//////////////////////1����ʼ��winpcap//////////////////////
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

//////////////////////2�����ݰ�ץȡ//////////////////////
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

//////////////////////�������ݰ�//////////////////////
int CtxysnifferDlg::txysniffer_updatePacket()
{
	CString strnum;
	strnum.Format(_T("%d"), this->packetCount.num_arp);
	this->m_ARPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_ip4);
	this->m_IPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_ip6);
	this->m_IPv6edit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_tcp);
	this->m_TCPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_udp);
	this->m_UDPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_icmp4);
	this->m_ICMPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_icmp6);
	this->m_IPv6edit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_http);
	this->m_HTTPedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_other);
	this->m_elseedit.SetWindowText(strnum);

	strnum.Format(_T("%d"), this->packetCount.num_total);
	this->m_totaledit.SetWindowText(strnum);

	return 1;
}

//�����б�
int CtxysnifferDlg::txysniffer_updateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data)
{
	//�������ݰ��������汾�ػ��������
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

	this->packetNum++;//������
	return 1;
}

//////////////////////�����̺߳���//////////////////////
DWORD WINAPI txysniffer_capThread(LPVOID lpParameter)
{
	int flag;
	struct pcap_pkthdr *data_header;//���ݰ�ͷ
	const u_char *pkt_data = NULL;//�յ����ֽ�������

	CtxysnifferDlg *pthis = (CtxysnifferDlg*)lpParameter;
	if (pthis->m_ThreadHandle == NULL) 
	{
		MessageBox(NULL, _T("�߳̾������"),_T( "��ʾ"), MB_OK);
		return -1;
	}
	while ((flag = pcap_next_ex(pthis->dpHandle, &data_header, &pkt_data)) >= 0)//���ݰ�����
	{
		if (flag == 0)//��ʱ
			continue;
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));
		if (data == NULL)
		{
			MessageBox(NULL, _T("�ռ��������޷������µ����ݰ�"), _T("Error"), MB_OK);
			return -1;
		}

		//������������������ݰ����ڴ���Χ��
		if (analyse_data_frame(pkt_data, data, &(pthis->packetCount)) < 0)
			continue;

		//�����ݰ����浽�򿪵��ļ���
		if (pthis->dumpFile != NULL)
			pcap_dump((unsigned char*)pthis->dumpFile, data_header, pkt_data);

		pthis->txysniffer_updatePacket();
		pthis->txysniffer_updateList(data_header, data, pkt_data);
	}
	return 1;
}

//���ݸ�ʽ����ʾ
void CtxysnifferDlg::print_packet_hex(const u_char* packet, int packet_size, CString *buffer)
{
	//��������16������ʽ��ʾ
	for (int i = 0; i < packet_size; i += 16) 
	{
		buffer->AppendFormat(_T("%04x:  "), (u_int)i);
		int row = (packet_size - i) > 16 ? 16 : (packet_size - i);
		for (int j = 0; j < row; j++)
			buffer->AppendFormat(_T("%02x  "), (u_int)packet[i + j]);
		if (row < 16)//����16ʱ���ÿո���
			for (int j = row; j < 16; j++)
				buffer->AppendFormat(_T("            "));

		//���������ַ���ʽ��ʾ
		for (int j = 0; j < row; j++) {
			u_char ch = packet[i + j];
			ch = isprint(ch) ? ch : '.';
			buffer->AppendFormat(_T("%c"), ch);
		}
		buffer->Append(_T("\r\n"));
		if (row < 16)
			return;
	}
}

//���±༭��
int CtxysnifferDlg::txysniffer_updateEdit(int index)
{
	POSITION localPos = this->m_localDataList.FindIndex(index);
	POSITION netPos = this->m_netDataList.FindIndex(index);

	struct data_packet* localData = (struct data_packet*)(this->m_localDataList.GetAt(localPos));
	u_char * netData = (u_char*)(this->m_netDataList.GetAt(netPos));

	CString buffer;
	this->print_packet_hex(netData, localData->len, &buffer);
	this->m_edit.SetWindowText(buffer);
	return 1;
}

//�������ο�
int CtxysnifferDlg::txysniffer_updateTree(int index)
{
	this->m_tree.DeleteAllItems();
	POSITION localPos = this->m_localDataList.FindIndex(index);
	struct data_packet* localData = (struct data_packet*)(this->m_localDataList.GetAt(localPos));

	CString str;
	str.Format(_T("��%d�����ݰ�"), index + 1);
	HTREEITEM root = this->m_tree.GetRootItem();
	HTREEITEM data = this->m_tree.InsertItem(str, root);

	//��·��
	HTREEITEM frame = this->m_tree.InsertItem(_T("��·��"), data);

	str.Format(_T("ԴMAC��"));
	for (int i = 0; i < 6; i++) 
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), localData->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"), localData->ethh->src[i]);
	}
	this->m_tree.InsertItem(str, frame);

	str.Format(_T("Ŀ��MAC��"));
	for (int i = 0; i < 6; i++) 
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), localData->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"), localData->ethh->dest[i]);
	}
	this->m_tree.InsertItem(str, frame);

	str.Format(_T("���ͣ�0x%02x"), localData->ethh->type);
	this->m_tree.InsertItem(str, frame);

	//�����
	//ARPͷ
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
	}

	//IPv4ͷ
	if (localData->ethh->type == PROTO_IP_V4) 
	{
		HTREEITEM ip = this->m_tree.InsertItem(_T("IPv4ͷ"), data);

		str.Format(_T("�汾��%d"), localData->ip4h->version);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("IPͷ����%d"), localData->ip4h->ihl);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("�������ͣ�%d"), localData->ip4h->tos);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("�ܳ��ȣ�%d"), localData->ip4h->total_len);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("��ʶ��0x%02x"), localData->ip4h->id);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("��ƫ�ƣ�%d"), localData->ip4h->frag_off);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("�����ڣ�%d"), localData->ip4h->ttl);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("Э�飺%d"), localData->ip4h->proto);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("ͷ��У��ͣ�0x%02x"), localData->ip4h->check);
		this->m_tree.InsertItem(str, ip);

		str.Format(_T("ԴIP��"));
		struct in_addr in;
		in.S_un.S_addr = localData->ip4h->src_addr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_tree.InsertItem(str, ip);

		str.Format(_T("Ŀ��IP��"));
		in.S_un.S_addr = localData->ip4h->dest_addr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_tree.InsertItem(str, ip);

		//ICMPv4ͷ
		if (localData->ip4h->proto == V4_PROTO_ICMP_V4)
		{
			HTREEITEM icmp = this->m_tree.InsertItem(_T("ICMPv4ͷ"), data);

			str.Format(_T("����:%d"), localData->icmp4h->type);
			this->m_tree.InsertItem(str, icmp);
			str.Format(_T("����:%d"), localData->icmp4h->code);
			this->m_tree.InsertItem(str, icmp);
			str.Format(_T("���:%d"), localData->icmp4h->seq);
			this->m_tree.InsertItem(str, icmp);
			str.Format(_T("У���:%d"), localData->icmp4h->check);
			this->m_tree.InsertItem(str, icmp);
		}

		//TCPͷ
		if (localData->ip4h->proto == V4_PROTO_TCP)
		{
			HTREEITEM tcp = this->m_tree.InsertItem(_T("TCPЭ��ͷ"), data);

			str.Format(_T("  Դ�˿�:%d"), localData->tcph->src_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  Ŀ�Ķ˿�:%d"), localData->tcph->dest_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ���к�:0x%02x"), localData->tcph->seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ȷ�Ϻ�:%d"), localData->tcph->ack_seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ͷ������:%d"), localData->tcph->doff);

			HTREEITEM flag = this->m_tree.InsertItem(_T(" +��־λ", tcp));
			str.Format(_T("cwr %d"), localData->tcph->cwr);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("ece %d"), localData->tcph->ece);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("urg %d"), localData->tcph->urg);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("ack %d"), localData->tcph->ack);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("psh %d"), localData->tcph->psh);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("rst %d"), localData->tcph->rst);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("syn %d"), localData->tcph->syn);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("fin %d"), localData->tcph->fin);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("  ����ָ��:%d"), localData->tcph->urg_ptr);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  У���:0x%02x"), localData->tcph->check);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ѡ��:%d"), localData->tcph->opt);
			this->m_tree.InsertItem(str, tcp);
		}

		//UDPͷ
		if (localData->ip4h->proto == V4_PROTO_UDP) 
		{
			HTREEITEM udp = this->m_tree.InsertItem(_T("UDPЭ��ͷ", data));

			str.Format(_T("Դ�˿�:%d"), localData->udph->sport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("Ŀ�Ķ˿�:%d"), localData->udph->dport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("�ܳ���:%d"), localData->udph->len);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("У���:0x%02x"), localData->udph->check);
			this->m_tree.InsertItem(str, udp);
		}
	}

	//IPv6ͷ
	if (localData->ethh->type == PROTO_IP_V6) 
	{
		HTREEITEM ip6 = this->m_tree.InsertItem(_T("IPv6ͷ"), data);

		str.Format(_T("�汾:%d"), localData->ip6h->flowtype);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("������:%d"), localData->ip6h->version);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("����ǩ:%d"), localData->ip6h->flowid);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("��Ч�غɳ���:%d"), localData->ip6h->plen);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("��һ���ײ�:0x%02x"), localData->ip6h->next_head);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("������:%d"), localData->ip6h->hop_limit);
		this->m_tree.InsertItem(str, ip6);

		str.Format(_T("Դ��ַ:"));
		for (int i = 0; i < 8; i++) 
		{
			if (i <= 6)
				str.AppendFormat(_T("%02x:"), localData->ip6h->src_addr[i]);
			else
				str.AppendFormat(_T("%02x"), localData->ip6h->src_addr[i]);
		}
		this->m_tree.InsertItem(str, ip6);

		str.Format(_T("Ŀ�ĵ�ַ:"));
		for (int i = 0; i < 8; i++) 
		{
			if (i <= 6)
				str.AppendFormat(_T("%02x:"), localData->ip6h->src_addr[i]);
			else
				str.AppendFormat(_T("%02x"), localData->ip6h->src_addr[i]);
		}
		this->m_tree.InsertItem(str, ip6);

		//ICMPv6ͷ
		if (localData->ip6h->next_head == V6_PROTO_ICMP_V6) 
		{
			HTREEITEM icmp6 = this->m_tree.InsertItem(_T("ICMPv6Э��ͷ"), data);

			str.Format(_T("����:%d"), localData->icmp6h->type);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("����:%d"), localData->icmp6h->code);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("���:%d"), localData->icmp6h->seq);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("У���:%d"), localData->icmp6h->check);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("ѡ��-����:%d"), localData->icmp6h->op_type);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("ѡ��-����%d"), localData->icmp6h->op_len);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("ѡ��-��·���ַ:"));

			for (int i = 0; i < 6; i++)
			{
				if (i <= 4)
					str.AppendFormat(_T("%02x-"), localData->icmp6h->op_eth_addr[i]);
				else
					str.AppendFormat(_T("%02x"), localData->icmp6h->op_eth_addr[i]);
			}
			this->m_tree.InsertItem(str, icmp6);
		}

		//TCPͷ
		if (localData->ip6h->next_head == V6_PROTO_TCP) 
		{
			HTREEITEM tcp = this->m_tree.InsertItem(_T("TCPЭ��ͷ", data));

			str.Format(_T("  Դ�˿�:%d"), localData->tcph->src_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  Ŀ�Ķ˿�:%d"), localData->tcph->dest_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ���к�:0x%02x"), localData->tcph->seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ȷ�Ϻ�:%d"), localData->tcph->ack_seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ͷ������:%d"), localData->tcph->doff);

			HTREEITEM flag = this->m_tree.InsertItem(_T("��־λ"), tcp);

			str.Format(_T("cwr %d"), localData->tcph->cwr);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("ece %d"), localData->tcph->ece);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("urg %d"), localData->tcph->urg);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("ack %d"), localData->tcph->ack);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("psh %d"), localData->tcph->psh);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("rst %d"), localData->tcph->rst);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("syn %d"), localData->tcph->syn);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("fin %d"), localData->tcph->fin);
			this->m_tree.InsertItem(str, flag);
			str.Format(_T("  ����ָ��:%d"), localData->tcph->urg_ptr);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  У���:0x%02x"), localData->tcph->check);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  ѡ��:%d"), localData->tcph->opt);
			this->m_tree.InsertItem(str, tcp);
		}

		//UDPͷ
		if (localData->ip6h->next_head == V6_PROTO_UDP) 
		{
			HTREEITEM udp = this->m_tree.InsertItem(_T("UDPЭ��ͷ"), data);

			str.Format(_T("Դ�˿�:%d"), localData->udph->sport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("Ŀ�Ķ˿�:%d"), localData->udph->dport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("�ܳ���:%d"), localData->udph->len);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("У���:0x%02x"), localData->udph->check);
			this->m_tree.InsertItem(str, udp);
		}
	}

	return 1;
}

void CtxysnifferDlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	
	//���������ݣ���ʾ��������
	if (this->m_localDataList.IsEmpty() == FALSE)
		if (MessageBox(_T("ȷ�ϲ��������ݣ�"), _T("����"), MB_YESNO) == IDNO)
			this->txysniffer_saveFile();

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
