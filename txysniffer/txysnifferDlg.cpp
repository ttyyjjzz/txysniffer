
// txysnifferDlg.cpp : 实现文件
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

//////////////////////1.1初始化winpcap//////////////////////
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

//////////////////////1.2数据包抓取//////////////////////
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

//////////////////////2协议分析//////////////////////
//获取Ethernet类型
int CtxysnifferDlg::get_MacType(CString &eth_strType, u_short eth_Type, bool isFirst)
{
	if (isFirst)
		num_total++;

	switch (eth_Type)
	{
	case PROTO_ARP://ARP包
		eth_strType = TEXT("ARP");
		if (isFirst)
			num_arp++;
		break;
	case PROTO_IP://IP包
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
	default://其他包
		eth_strType = TEXT("other");
		break;
	}
	return 1;
}

//获取Mac地址
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

//获取IP类型
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

//获取IP地址
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

//////////////////////3交互//////////////////////
//更新数据包统计
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

//更新列表，设置协议过滤器并把信息显示在列表中
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

	UpdateData(true);  // 把控件的值传给对应的变量
	UpdateData(false); // 把变量的值传递给控件
	
	/*//建立数据包链表，保存本地化后的数据
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

	this->packetNum++;//包计数*/
	return 1;
}

//更新编辑框
int CtxysnifferDlg::txysniffer_updateEdit(CEdit & medit, packet *pkt)
{
	const struct pcap_pkthdr *header = pkt->header;
	const u_char *pkt_data = pkt->pkt_data;
	u_int pkt_dataLen = header->len;//得到单个Packet_Data数据包的长度
	CString buffer = NULL;
	CString chrAppend = NULL;
	u_int row = 0;

	//数据格式化显示
	for (int i = 0; i < pkt_dataLen; i++)
	{
		CString strAppend = NULL;
		if ((i % 16) == 0)// 取余，换行
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
				strAppend.Format(TEXT("\x0d\x0a 0X%04X ->  "), row); //0x0d:回车; 0x0a:换行;0X:表示16进制显示;%04x表示以4位的16进制显示并以0填充空位; eRows即显示行数（16进制格式显示）
				buffer += strAppend;
			}
			chrAppend = "";//reset
		}
		strAppend.Format(TEXT("%02x "), pkt_data[i]);
		buffer += strAppend;
		if (i>2 && pkt_data[i - 1] == 13 && pkt_data[i] == 10)//如果遇到回车、换行，则直接继续，以免使显示字符换行
			continue;
		strAppend.Format(TEXT("%c"), pkt_data[i]);
		chrAppend += strAppend;
	}
	if (chrAppend != "")
		buffer += TEXT("==>> ") + chrAppend;

	medit.SetWindowTextW(buffer);

	return 1;
}

//更新树形框.链路层
int CtxysnifferDlg::txysniffer_updateTree_mac(HTREEITEM & hItem, const u_char * pkt_data)
{
	eth_header *mac_hdr = (eth_header *)pkt_data;
	hItem = m_tree.InsertItem(_T("链路层"));
	CString str = NULL;
	CString mac_strType = NULL;
	TCHAR mac_srcAddr[18];
	TCHAR mac_dstAddr[18];

	get_MacType(mac_strType, ntohs(mac_hdr->type), false);
	str.Format(_T("类型：0x%02x"), mac_strType);
	m_tree.InsertItem(str, hItem);

	get_MacAddress(mac_srcAddr, mac_hdr->src);
	str.Format(_T("源MAC："), mac_srcAddr);
	m_tree.InsertItem(str, hItem);

	get_MacAddress(mac_dstAddr, mac_hdr->dest);
	str.Format(_T("目的MAC："), mac_dstAddr);
	m_tree.InsertItem(str, hItem);

	return 1;
}
	//网络层
	/*//ARP头
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
	}*/


int CtxysnifferDlg::txysniffer_updateTree_ip(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	hItem = m_tree.InsertItem(_T("网络层"));
	CString str = NULL;

	str.Format(_T("版本：%d"), ip_hdr->version);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("IP头长：%d"), ip_hdr->ihl);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("服务类型：%d"), ip_hdr->tos);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("总长度：%d"), ip_hdr->total_len);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("标识：0x%02x"), ip_hdr->id);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("段偏移：%d"), ip_hdr->frag_off);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("生存期：%d"), ip_hdr->ttl);
	m_tree.InsertItem(str, hItem);
	CString ip_strProtocol = NULL;
	get_IPType(ip_strProtocol, ip_hdr->proto, false);
	str.Format(_T("协议：%d"), ip_strProtocol);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("头部校验和：0x%02x"), ip_hdr->check);
	m_tree.InsertItem(str, hItem);
	TCHAR ip_srcAddr[16];
	TCHAR ip_dstAddr[16];
	get_IPAddress(ip_srcAddr, &ip_hdr->src_addr);
	get_IPAddress(ip_dstAddr, &ip_hdr->dest_addr);
	str.Format(_T("源IP：%s"), ip_srcAddr);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("目的IP：%s"), ip_dstAddr);
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_tcp(HTREEITEM & hItem, const u_char * pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4; //一行4字节，故乘以4
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	hItem = m_tree.InsertItem(_T("TCP协议头"));
	CString str = NULL;

	str.Format(_T("  源端口:%d"), ntohs(tcp_hdr->src_port));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  目的端口:%d"), ntohs(tcp_hdr->dest_port));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  序列号:0x%02x"), ntohl(tcp_hdr->seq));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  确认号:%d"), ntohl(tcp_hdr->ack_seq));
	m_tree.InsertItem(str, hItem);

	HTREEITEM flag = m_tree.InsertItem(_T(" +标志位"), hItem);
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
	str.Format(_T("  紧急指针:%d"), tcp_hdr->urg_ptr);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  校验和:0x%02x"), tcp_hdr->check);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("  窗口大小:%d"), tcp_hdr->window);
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_udp(HTREEITEM & hItem, const u_char * pkt_data)
{
	//UDP头
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	udp_header *udp_hdr = (udp_header *)(pkt_data + 14 + ip_hdrLen);

	hItem = m_tree.InsertItem(_T("UDP协议头"));
	CString str = NULL;

	str.Format(_T("源端口:%d"), ntohs(udp_hdr->sport));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("目的端口:%d"), ntohs(udp_hdr->dport));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("总长度:%d"), ntohs(udp_hdr->len));
	m_tree.InsertItem(str, hItem);
	str.Format(_T("校验和:0x%02x"), ntohs(udp_hdr->check));
	m_tree.InsertItem(str, hItem);

	return 1;
}

int CtxysnifferDlg::txysniffer_updateTree_icmp(HTREEITEM & hItem, const u_char * pkt_data)
{
	//ICMP头
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	icmp_header *icmp_hdr = (icmp_header *)(pkt_data + 14 + ip_hdrLen);
	
	hItem = m_tree.InsertItem(_T("ICMPv4头"));
	CString str = NULL;
	str.Format(_T("类型:%d"), icmp_hdr->type);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("代码:%d"), icmp_hdr->code);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("序号:%d"), icmp_hdr->seq);
	m_tree.InsertItem(str, hItem);
	str.Format(_T("校验和:%d"), ntohs(icmp_hdr->check));
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
	vector<CString> strVecRequestHttp;//定义请求头容器
	vector<CString> strVecRespondHttp;//定义响应头容器
	CString chrVecTmp = NULL;//声明存入容器的临时字符
	CString strVecTmp = NULL;//声明存入容器的临时字符串

	u_char * pchrHttpAllData = NULL;//定义HTTP协议包的起始位置，包括请求头或响应头都可
	u_char * pchrHttpRequestPos = NULL;//定义HTTP协议包的请求头的起始位置
	u_char * pchrHttpRespondPos = NULL;//定义HTTP协议包的响应头的起始位置
	pchrHttpAllData = http_pkt;//赋值得到HTTP协议包的开始位置

	CString strHttpALLData = NULL;//定义HTTP协议包的数据包,包括请求头或响应头都可
	CString strHttpRequestData = NULL;//定义HTTP协议包的请求头的数据
	CString strHttpRespondData = NULL;//定义HTTP协议包的响应头的数据

	u_short httpAllPos = 0;
	u_short httpAllLen = 0;
	httpAllLen = http_pktLen;

	if (IsHTTP(pkt_data)) // check is http
	{
		// show request to tree
		hItem = m_tree.InsertItem(_T("HTTP头"));

		if (*pkt_data == 'H') // 如果第一个字符为H，即可能以HTTP开头的，则为响应头，否则应为请求头
		{
			for (int i = 0; i<httpAllLen; i++) // get http_Get data
			{
				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); // format
				strHttpRespondData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if (i>2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //根据回车换行符判断，并把每行保存在vector数组中
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
				strHttpRequestData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(_T("%c"), pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if (i>2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //根据回车换行符判断，并把每行保存在vector数组中
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
		for (int i = 0; i<http_pktLen; i++) // 仅提取第一行是否含有HTTP字符串
		{
			chrTmp.Format(_T("%c"), http_pkt[i]);
			strTmp += chrTmp;
			if (i>2 && http_pkt[i - 1] == 13 && http_pkt[i] == 10)
				break;
		}
		httpPos = strTmp.Find(_T("HTTP"), 0);

		if (httpPos != -1 && httpPos != 65535) // 如果第一行含有字符串HTTP，则为HTTP协议
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
	// TODO: 在此添加控件通知处理程序代码

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
