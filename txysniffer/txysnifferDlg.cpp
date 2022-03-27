
// txysnifferDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "txysniffer.h"
#include "txysnifferDlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

DWORD WINAPI txysniffer_CapThread(LPVOID lpParameter);

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
	DDX_Control(pDX, IDC_BUTTON3, m_savebutton);
	DDX_Control(pDX, IDC_BUTTON4, m_readbutton);
	DDX_Control(pDX, IDC_COMBO1, m_netcardComboBox);
	DDX_Control(pDX, IDC_COMBO2, m_rulefilterComboBox);
	DDX_Control(pDX, IDC_EDIT1, m_TCPedit);
	DDX_Control(pDX, IDC_EDIT2, m_UDPedit);
	DDX_Control(pDX, IDC_EDIT3, m_HTTPedit);
	DDX_Control(pDX, IDC_EDIT4, m_ARPedit);
	DDX_Control(pDX, IDC_EDIT5, m_IPv4edit);
	DDX_Control(pDX, IDC_EDIT6, m_IPv6edit);
	DDX_Control(pDX, IDC_EDIT7, m_ICMPv4edit);
	DDX_Control(pDX, IDC_EDIT9, m_ICMPv6edit);
	DDX_Control(pDX, IDC_EDIT10, m_elseedit);
	DDX_Control(pDX, IDC_EDIT11, m_totaledit);
	DDX_Control(pDX, IDC_EDIT12, m_edit);
	DDX_Control(pDX, IDC_LIST1, m_list);
	DDX_Control(pDX, IDC_TREE1, m_tree);
}

BEGIN_MESSAGE_MAP(CtxysnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CtxysnifferDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CtxysnifferDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CtxysnifferDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CtxysnifferDlg::OnBnClickedButton4)
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
	m_netcardComboBox.AddString(_T("请选择网卡"));
	m_rulefilterComboBox.AddString(_T("请选择过滤规则"));
	if (txysniffer_initCap() < 0) //初始化WinPcap
		return FALSE;
	for (nc = allncs; nc; nc = nc->next) //将可用网卡添加到下拉网卡候选栏
		if (nc->description)
			m_netcardComboBox.AddString(CString(nc->description));

	m_rulefilterComboBox.AddString(CString("TCP"));
	m_rulefilterComboBox.AddString(CString("UDP"));
	m_rulefilterComboBox.AddString(CString("IP"));
	m_rulefilterComboBox.AddString(CString("ICMP"));
	m_rulefilterComboBox.AddString(CString("ARP"));

	m_netcardComboBox.SetCurSel(0);//默认显示
	m_rulefilterComboBox.SetCurSel(0);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

//1、初始化winpcap
int CtxysnifferDlg::txysniffer_initCap()
{
	ncCount = 0;
	if (pcap_findalldevs(&allncs, errorBufffer) == -1)
		return -1;
	for (nc = allncs; nc; nc = nc->next)//网卡数
		ncCount++;
	return 0;
}

//2、数据包抓取
int CtxysnifferDlg::txysniffer_startCap()
{
	int ncIndex;//网卡索引
	int filterIndex;//协议过滤器索引
	int dataPackageLen = 65536;//数据包长度
	int mode = 1;//网卡模式标志
	int overtime = 1000;//超时时间
	u_int netmask;//子网掩码
	struct bpf_program fcode;
	CFileFind file;


	//(1)网卡和规则过滤的选择设置
	ncIndex = this->m_netcardComboBox.GetCurSel();
	filterIndex = this->m_rulefilterComboBox.GetCurSel();
	if (ncIndex == 0 || ncIndex == -1)
	{
		MessageBox(_T("请选择合适的网卡接口"));
		return -1;
	}
	if (filterIndex == -1)
	{
		MessageBox(_T("过滤器选择错误"));
		return -1;
	}

	//(2)获得选中网卡
	nc = allncs;
	for (int i = 0; i < ncIndex - 1; i++)
		nc = nc->next;
	dpHandle = pcap_open_live(nc->name, dataPackageLen, mode, overtime, errorBufffer);
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
	if (nc->addresses != NULL)
		netmask = ((struct sockaddr_in *)(nc->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	//(5)编译过滤器
	if (filterIndex == 0)
	{
		char filter[] = "";
		if (pcap_compile(dpHandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("无法编译过滤器"));
			pcap_freealldevs(allncs);//释放设备列表
			return -1;
		}
	}
	else
	{
		CString str;
		int len;
		char *filter;
		this->m_rulefilterComboBox.GetLBText(filterIndex, str);
		len = str.GetLength + 1;
		for (int i = 0; i < len; i++)
			filter[i] = str.GetAt(i);
		if (pcap_compile(dpHandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("无法编译过滤器"));
			pcap_freealldevs(allncs);//释放设备列表
			return -1;
		}
	}

	//(6)设置过滤器
	if (pcap_setfilter(dpHandle, &fcode) < 0)
	{
		MessageBox(_T("过滤器设置错误"));
		pcap_freealldevs(allncs);//释放设备列表
		return -1;
	}

	//(7)数据包存储路径
	struct tm *ltime;
	time_t stime;
	char thistime[30];
	time(&stime);
	ltime = localtime(&stime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);

	if (!file.FindFile(_T("SaveData")))
		CreateDirectory(_T("SaveData"), NULL);
	memset(filePath, 0, sizeof(filePath));
	memset(fileName, 0, sizeof(fileName));
	strcpy(filePath, "SaveData\\");
	strcat(fileName, thistime);
	strcat(fileName, ".txy");
	strcat(filePath, fileName);
	dumpFile = pcap_dump_open(dpHandle, filePath);
	if (dumpFile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}

	//(8)接收数据，创建线程
	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, txysniffer_CapThread, this, 0, threadCap);
	if (m_ThreadHandle == NULL) {
		CString str;
		str.Format(_T("创建线程错误，代码为：%d."), GetLastError());
		MessageBox(str);
		return -1;
	}
	return 1;
}

//接收线程函数111111111111111111111111111111111111111111111111
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
	while ((flag = pcap_next_ex(pthis->dpHandle, &data_header, &pkt_data)) >= 0)
	{
		if (flag == 0)//超时
			continue;
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));
		if (data == NULL) {
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyse_data_frame(pkt_data, data, &(pthis->packetCount)) < 0)
			continue;

		//将数据包保存到打开的文件中
		if (pthis->dumpFile != NULL)
			pcap_dump((unsigned char*)pthis->dumpFile, data_header, pkt_data);

		/********************更新控件*********************/
		pthis->Sniffer_updatePacket();
		pthis->Sniffer_updateList(data_header, data, pkt_data);
	}
	return 1;
}

void CtxysnifferDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CtxysnifferDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CtxysnifferDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CtxysnifferDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
}
