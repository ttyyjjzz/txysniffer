
// txysnifferDlg.cpp : 实现文件
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


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

#define M_MESSAGEWINPCAP (WM_USER+50)
char *filter;
static HWND hDlgHandle;
DWORD WINAPI txysniffer_capThread(LPVOID lpParameter);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CtxysnifferDlg 对话框



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
	DDX_Control(pDX, IDC_EDIT12, m_edit);//数据包内容显示
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


// CtxysnifferDlg 消息处理程序

//界面初始化设置
BOOL CtxysnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
    
	//数据包列表表项
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list.InsertColumn(0, _T("编号"), 2, 50);//2居中
	m_list.InsertColumn(1, _T("时间"), 2, 200);
	m_list.InsertColumn(2, _T("长度"), 2, 100);
	m_list.InsertColumn(3, _T("源MAC地址"), 2, 200);
	m_list.InsertColumn(4, _T("目的MAC地址"), 2, 200);
	m_list.InsertColumn(5, _T("协议"), 2, 100);
	m_list.InsertColumn(6, _T("源IP地址"), 2, 150);
	m_list.InsertColumn(7, _T("目的IP地址"), 2, 150);

	//下拉框
	m_netcardComboBox.AddString(_T("请选择网卡(必选)"));
	txysniffer_initCap();//获取所有网卡显示到下拉框中
		return FALSE;
	m_netcardComboBox.SetCurSel(0);//默认显示

	//协议选择CheckBox
	m_ALLcheck.GetCheck() == BST_CHECKED;
	m_ARPcheck.GetCheck() == BST_UNCHECKED;
	m_IPcheck.GetCheck() == BST_UNCHECKED;
	m_TCPcheck.GetCheck() == BST_UNCHECKED;
	m_UDPcheck.GetCheck() == BST_UNCHECKED;
	m_ICMPcheck.GetCheck() == BST_UNCHECKED;
	m_HTTPcheck.GetCheck() == BST_UNCHECKED;
	m_FTPcheck.GetCheck() == BST_UNCHECKED;

	return TRUE;// 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CtxysnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CtxysnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//////////////////////1、初始化winpcap//////////////////////
void CtxysnifferDlg::txysniffer_initCap()
{
	pcap_if_t *allncs;//网卡列表
	pcap_if_t *nc;//网卡
	int ncCount;//网卡计数
	char errorBufffer[PCAP_ERRBUF_SIZE];//错误缓冲区

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

//////////////////////2、数据包抓取//////////////////////
DWORD WINAPI txysniffer_capThread(LPVOID lpParameter)
{
	pcap_if_t *allncs;//网卡列表
	pcap_if_t *nc;//网卡
	pcap_t *dpHandle;//捕获
	char errorBufffer[PCAP_ERRBUF_SIZE];//错误缓冲区

	CtxysnifferDlg *pthis = (CtxysnifferDlg*)lpParameter;

	//(1)网卡的选择设置
	int ncIndex;//网卡索引

	ncIndex = pthis->m_netcardComboBox.GetCurSel();
	if (ncIndex == 0 || ncIndex == CB_ERR)
	{
		MessageBox(_T("请选择合适的网卡接口"));
		return -1;
	}

	//(2)获得选中网卡
	int dataPackageLen = 65536;//数据包长度
	int mode = 1;//网卡模式标志
	int overtime = 1000;//读超时时间

	nc = allncs;
	for (int i = 0; i < ncIndex - 1; i++)
		nc = nc->next;
	dpHandle = pcap_open_live(nc->name, dataPackageLen, mode, overtime, errorBufffer);//打开指定网卡接口
	if (dpHandle == NULL)
	{
		MessageBox(_T("网卡接口无法打开") + CString(nc->description));
		pcap_freealldevs(allncs);//释放设备列表
		return -1;
	}

	//(3)检查是否是以太网
	if (pcap_datalink(dpHandle) != DLT_EN10MB)
	{
		MessageBox(_T("非以太网！"));
		pcap_freealldevs(allncs);//释放设备列表
		return -1;
	}

	//(4)设置子网掩码
	u_int netmask;//子网掩码
	if (nc->addresses != NULL)
		netmask = ((struct sockaddr_in *)(nc->addresses->netmask))->sin_addr.S_un.S_addr;
	else//若接口没有地址，假设一个C类的掩码
		netmask = 0xffffff;

	//(5)编译过滤器
	struct bpf_program fcode;

	if (pcap_compile(dpHandle, &fcode, filter, 1, netmask) < 0)
	{
		MessageBox(_T("无法编译过滤器"));
		pcap_freealldevs(allncs);//释放设备列表
		return -1;
	}

	//(6)设置过滤器
	if (pcap_setfilter(dpHandle, &fcode) < 0)
	{
		MessageBox(_T("过滤器设置错误"));
		pcap_freealldevs(allncs);//释放设备列表
		return -1;
	}

	pcap_freealldevs(allncs);//释放设备列表	
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

	//把消息放入队列
	::PostMessage(hDlgHandle, M_MESSAGEWINPCAP, (WPARAM)header2, (LPARAM)pkt_data2);

}

//////////////////////更新数据包//////////////////////
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

//更新列表
int CtxysnifferDlg::txysniffer_updateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data)
{
	//建立数据包链表，保存本地化后的数据
	u_char *data_packet_list;
	data_packet_list = (u_char*)malloc(data_header->len);
	memcpy(data_packet_list, pkt_data, data_header->len);

	this->m_localDataList.AddTail(data);
	this->m_netDataList.AddTail(data_packet_list);

	//获取长度
	data->len = data_header->len;
	//获取时间
	time_t local_tv_sec = data_header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	data->time[0] = ltime->tm_year + 1900;
	data->time[1] = ltime->tm_mon + 1;
	data->time[2] = ltime->tm_mday;
	data->time[3] = ltime->tm_hour;
	data->time[4] = ltime->tm_min;
	data->time[5] = ltime->tm_sec;

	//为新接收到的数据包在列表控件中新建项
	CString buffer;
	buffer.Format(_T("%d"), this->packetNum);
	int nextItem = this->m_list.InsertItem(this->packetNum, buffer);

	//时间戳
	CString timestr;
	timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
		data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
	this->m_list.SetItemText(nextItem, 1, timestr);

	//长度
	buffer.Empty();
	buffer.Format(_T("%d"), data->len);
	this->m_list.SetItemText(nextItem, 2, buffer);

	//源MAC
	buffer.Empty();
	buffer.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
		data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
	this->m_list.SetItemText(nextItem, 3, buffer);

	//目的MAC
	buffer.Empty();
	buffer.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
		data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
	this->m_list.SetItemText(nextItem, 4, buffer);

	//协议
	this->m_list.SetItemText(nextItem, 5, CString(data->type));

	//源IP
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

	//目的IP
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

	this->packetNum++;//包计数
	return 1;
}

//////////////////////接收线程函数//////////////////////
DWORD WINAPI txysniffer_capThread(LPVOID lpParameter)
{
	int flag;
	struct pcap_pkthdr *data_header;//数据包头
	const u_char *pkt_data = NULL;//收到的字节流数据

	CtxysnifferDlg *pthis = (CtxysnifferDlg*)lpParameter;
	if (pthis->m_ThreadHandle == NULL) 
	{
		MessageBox(NULL, _T("线程句柄错误"),_T( "提示"), MB_OK);
		return -1;
	}
	while ((flag = pcap_next_ex(pthis->dpHandle, &data_header, &pkt_data)) >= 0)//数据包捕获
	{
		if (flag == 0)//超时
			continue;
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));
		if (data == NULL)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyse_data_frame(pkt_data, data, &(pthis->packetCount)) < 0)
			continue;

		//将数据包保存到打开的文件中
		if (pthis->dumpFile != NULL)
			pcap_dump((unsigned char*)pthis->dumpFile, data_header, pkt_data);

		pthis->txysniffer_updatePacket();
		pthis->txysniffer_updateList(data_header, data, pkt_data);
	}
	return 1;
}

//数据格式化显示
void CtxysnifferDlg::print_packet_hex(const u_char* packet, int packet_size, CString *buffer)
{
	//将数据以16进制形式显示
	for (int i = 0; i < packet_size; i += 16) 
	{
		buffer->AppendFormat(_T("%04x:  "), (u_int)i);
		int row = (packet_size - i) > 16 ? 16 : (packet_size - i);
		for (int j = 0; j < row; j++)
			buffer->AppendFormat(_T("%02x  "), (u_int)packet[i + j]);
		if (row < 16)//不足16时，用空格补足
			for (int j = row; j < 16; j++)
				buffer->AppendFormat(_T("            "));

		//将数据以字符形式显示
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

//更新编辑框
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

//更新树形框
int CtxysnifferDlg::txysniffer_updateTree(int index)
{
	this->m_tree.DeleteAllItems();
	POSITION localPos = this->m_localDataList.FindIndex(index);
	struct data_packet* localData = (struct data_packet*)(this->m_localDataList.GetAt(localPos));

	CString str;
	str.Format(_T("第%d个数据包"), index + 1);
	HTREEITEM root = this->m_tree.GetRootItem();
	HTREEITEM data = this->m_tree.InsertItem(str, root);

	//链路层
	HTREEITEM frame = this->m_tree.InsertItem(_T("链路层"), data);

	str.Format(_T("源MAC："));
	for (int i = 0; i < 6; i++) 
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), localData->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"), localData->ethh->src[i]);
	}
	this->m_tree.InsertItem(str, frame);

	str.Format(_T("目的MAC："));
	for (int i = 0; i < 6; i++) 
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), localData->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"), localData->ethh->dest[i]);
	}
	this->m_tree.InsertItem(str, frame);

	str.Format(_T("类型：0x%02x"), localData->ethh->type);
	this->m_tree.InsertItem(str, frame);

	//网络层
	//ARP头
	if (localData->ethh->type == PROTO_ARP)
	{
		HTREEITEM arp = this->m_tree.InsertItem(_T("ARP头"), data);
		str.Format(_T("硬件类型：%d"), localData->arph->hard);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), localData->arph->pro);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), localData->arph->hard_len);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), localData->arph->pro_len);
		this->m_tree.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), localData->arph->oper);
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("发送方MAC："));
		for (int i = 0; i < 6; i++) 
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), localData->arph->src_mac[i]);
			else
				str.AppendFormat(_T("%02x"), localData->arph->src_mac[i]);
		}
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("发送方IP："));
		for (int i = 0; i < 4; i++) 
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), localData->arph->src_ip[i]);
			else
				str.AppendFormat(_T("%d"), localData->arph->src_ip[i]);
		}
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("接收方MAC："));
		for (int i = 0; i < 6; i++) 
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), localData->arph->dest_mac[i]);
			else
				str.AppendFormat(_T("%02x"), localData->arph->dest_mac[i]);
		}
		this->m_tree.InsertItem(str, arp);

		str.Format(_T("接收方IP："));
		for (int i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), localData->arph->dest_ip[i]);
			else
				str.AppendFormat(_T("%d"), localData->arph->dest_ip[i]);
		}
		this->m_tree.InsertItem(str, arp);
	}

	//IPv4头
	if (localData->ethh->type == PROTO_IP_V4) 
	{
		HTREEITEM ip = this->m_tree.InsertItem(_T("IPv4头"), data);

		str.Format(_T("版本：%d"), localData->ip4h->version);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("IP头长：%d"), localData->ip4h->ihl);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), localData->ip4h->tos);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("总长度：%d"), localData->ip4h->total_len);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("标识：0x%02x"), localData->ip4h->id);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("段偏移：%d"), localData->ip4h->frag_off);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("生存期：%d"), localData->ip4h->ttl);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("协议：%d"), localData->ip4h->proto);
		this->m_tree.InsertItem(str, ip);
		str.Format(_T("头部校验和：0x%02x"), localData->ip4h->check);
		this->m_tree.InsertItem(str, ip);

		str.Format(_T("源IP："));
		struct in_addr in;
		in.S_un.S_addr = localData->ip4h->src_addr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_tree.InsertItem(str, ip);

		str.Format(_T("目的IP："));
		in.S_un.S_addr = localData->ip4h->dest_addr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_tree.InsertItem(str, ip);

		//ICMPv4头
		if (localData->ip4h->proto == V4_PROTO_ICMP_V4)
		{
			HTREEITEM icmp = this->m_tree.InsertItem(_T("ICMPv4头"), data);

			str.Format(_T("类型:%d"), localData->icmp4h->type);
			this->m_tree.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), localData->icmp4h->code);
			this->m_tree.InsertItem(str, icmp);
			str.Format(_T("序号:%d"), localData->icmp4h->seq);
			this->m_tree.InsertItem(str, icmp);
			str.Format(_T("校验和:%d"), localData->icmp4h->check);
			this->m_tree.InsertItem(str, icmp);
		}

		//TCP头
		if (localData->ip4h->proto == V4_PROTO_TCP)
		{
			HTREEITEM tcp = this->m_tree.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), localData->tcph->src_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), localData->tcph->dest_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), localData->tcph->seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), localData->tcph->ack_seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), localData->tcph->doff);

			HTREEITEM flag = this->m_tree.InsertItem(_T(" +标志位", tcp));
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
			str.Format(_T("  紧急指针:%d"), localData->tcph->urg_ptr);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), localData->tcph->check);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), localData->tcph->opt);
			this->m_tree.InsertItem(str, tcp);
		}

		//UDP头
		if (localData->ip4h->proto == V4_PROTO_UDP) 
		{
			HTREEITEM udp = this->m_tree.InsertItem(_T("UDP协议头", data));

			str.Format(_T("源端口:%d"), localData->udph->sport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), localData->udph->dport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), localData->udph->len);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), localData->udph->check);
			this->m_tree.InsertItem(str, udp);
		}
	}

	//IPv6头
	if (localData->ethh->type == PROTO_IP_V6) 
	{
		HTREEITEM ip6 = this->m_tree.InsertItem(_T("IPv6头"), data);

		str.Format(_T("版本:%d"), localData->ip6h->flowtype);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("流类型:%d"), localData->ip6h->version);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("流标签:%d"), localData->ip6h->flowid);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("有效载荷长度:%d"), localData->ip6h->plen);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("下一个首部:0x%02x"), localData->ip6h->next_head);
		this->m_tree.InsertItem(str, ip6);
		str.Format(_T("跳限制:%d"), localData->ip6h->hop_limit);
		this->m_tree.InsertItem(str, ip6);

		str.Format(_T("源地址:"));
		for (int i = 0; i < 8; i++) 
		{
			if (i <= 6)
				str.AppendFormat(_T("%02x:"), localData->ip6h->src_addr[i]);
			else
				str.AppendFormat(_T("%02x"), localData->ip6h->src_addr[i]);
		}
		this->m_tree.InsertItem(str, ip6);

		str.Format(_T("目的地址:"));
		for (int i = 0; i < 8; i++) 
		{
			if (i <= 6)
				str.AppendFormat(_T("%02x:"), localData->ip6h->src_addr[i]);
			else
				str.AppendFormat(_T("%02x"), localData->ip6h->src_addr[i]);
		}
		this->m_tree.InsertItem(str, ip6);

		//ICMPv6头
		if (localData->ip6h->next_head == V6_PROTO_ICMP_V6) 
		{
			HTREEITEM icmp6 = this->m_tree.InsertItem(_T("ICMPv6协议头"), data);

			str.Format(_T("类型:%d"), localData->icmp6h->type);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("代码:%d"), localData->icmp6h->code);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("序号:%d"), localData->icmp6h->seq);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("校验和:%d"), localData->icmp6h->check);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("选项-类型:%d"), localData->icmp6h->op_type);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("选项-长度%d"), localData->icmp6h->op_len);
			this->m_tree.InsertItem(str, icmp6);
			str.Format(_T("选项-链路层地址:"));

			for (int i = 0; i < 6; i++)
			{
				if (i <= 4)
					str.AppendFormat(_T("%02x-"), localData->icmp6h->op_eth_addr[i]);
				else
					str.AppendFormat(_T("%02x"), localData->icmp6h->op_eth_addr[i]);
			}
			this->m_tree.InsertItem(str, icmp6);
		}

		//TCP头
		if (localData->ip6h->next_head == V6_PROTO_TCP) 
		{
			HTREEITEM tcp = this->m_tree.InsertItem(_T("TCP协议头", data));

			str.Format(_T("  源端口:%d"), localData->tcph->src_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), localData->tcph->dest_port);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), localData->tcph->seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), localData->tcph->ack_seq);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), localData->tcph->doff);

			HTREEITEM flag = this->m_tree.InsertItem(_T("标志位"), tcp);

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
			str.Format(_T("  紧急指针:%d"), localData->tcph->urg_ptr);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), localData->tcph->check);
			this->m_tree.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), localData->tcph->opt);
			this->m_tree.InsertItem(str, tcp);
		}

		//UDP头
		if (localData->ip6h->next_head == V6_PROTO_UDP) 
		{
			HTREEITEM udp = this->m_tree.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), localData->udph->sport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), localData->udph->dport);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), localData->udph->len);
			this->m_tree.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), localData->udph->check);
			this->m_tree.InsertItem(str, udp);
		}
	}

	return 1;
}

void CtxysnifferDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	
	//若已有数据，提示保存数据
	if (this->m_localDataList.IsEmpty() == FALSE)
		if (MessageBox(_T("确认不保存数据？"), _T("警告"), MB_YESNO) == IDNO)
			this->txysniffer_saveFile();

	//清空数据
	this->packetNum = 1; //重新计数
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
	// TODO: 在此添加控件通知处理程序代码
	
	if (this->m_ThreadHandle == NULL)
		return;
	if (TerminateThread(this->m_ThreadHandle, -1) == 0) 
	{
		MessageBox(_T("线程关闭错误，请稍后重试"));
		return;
	}
	this->m_ThreadHandle = NULL;
	this->m_startbutton.EnableWindow(TRUE);
	this->m_stopbutton.EnableWindow(FALSE);
	this->m_clearbutton.EnableWindow(TRUE);
}


void CtxysnifferDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	//清空数据
	this->m_list.DeleteAllItems();
	this->packetNum = 1;
	this->m_localDataList.RemoveAll();
	this->m_netDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));

}


void CtxysnifferDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CtxysnifferDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	POSITION pos = m_list.GetFirstSelectedItemPosition();
	int index = m_list.GetNextSelectedItem(pos); //获取列表控件当前选择的行号
	if (index != -1) 
	{
		this->txysniffer_updateEdit(index);//更新对应行的编辑框
		this->txysniffer_updateTree(index);//更新对应行的树形框
	}
	*pResult = 0;
}
