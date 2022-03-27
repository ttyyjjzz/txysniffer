
// txysnifferDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "txysniffer.h"
#include "txysnifferDlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

DWORD WINAPI txysniffer_CapThread(LPVOID lpParameter);

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
	m_netcardComboBox.AddString(_T("��ѡ������"));
	m_rulefilterComboBox.AddString(_T("��ѡ����˹���"));
	if (txysniffer_initCap() < 0) //��ʼ��WinPcap
		return FALSE;
	for (nc = allncs; nc; nc = nc->next) //������������ӵ�����������ѡ��
		if (nc->description)
			m_netcardComboBox.AddString(CString(nc->description));

	m_rulefilterComboBox.AddString(CString("TCP"));
	m_rulefilterComboBox.AddString(CString("UDP"));
	m_rulefilterComboBox.AddString(CString("IP"));
	m_rulefilterComboBox.AddString(CString("ICMP"));
	m_rulefilterComboBox.AddString(CString("ARP"));

	m_netcardComboBox.SetCurSel(0);//Ĭ����ʾ
	m_rulefilterComboBox.SetCurSel(0);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

//1����ʼ��winpcap
int CtxysnifferDlg::txysniffer_initCap()
{
	ncCount = 0;
	if (pcap_findalldevs(&allncs, errorBufffer) == -1)
		return -1;
	for (nc = allncs; nc; nc = nc->next)//������
		ncCount++;
	return 0;
}

//2�����ݰ�ץȡ
int CtxysnifferDlg::txysniffer_startCap()
{
	int ncIndex;//��������
	int filterIndex;//Э�����������
	int dataPackageLen = 65536;//���ݰ�����
	int mode = 1;//����ģʽ��־
	int overtime = 1000;//��ʱʱ��
	u_int netmask;//��������
	struct bpf_program fcode;
	CFileFind file;


	//(1)�����͹�����˵�ѡ������
	ncIndex = this->m_netcardComboBox.GetCurSel();
	filterIndex = this->m_rulefilterComboBox.GetCurSel();
	if (ncIndex == 0 || ncIndex == -1)
	{
		MessageBox(_T("��ѡ����ʵ������ӿ�"));
		return -1;
	}
	if (filterIndex == -1)
	{
		MessageBox(_T("������ѡ�����"));
		return -1;
	}

	//(2)���ѡ������
	nc = allncs;
	for (int i = 0; i < ncIndex - 1; i++)
		nc = nc->next;
	dpHandle = pcap_open_live(nc->name, dataPackageLen, mode, overtime, errorBufffer);
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
	if (nc->addresses != NULL)
		netmask = ((struct sockaddr_in *)(nc->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	//(5)���������
	if (filterIndex == 0)
	{
		char filter[] = "";
		if (pcap_compile(dpHandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("�޷����������"));
			pcap_freealldevs(allncs);//�ͷ��豸�б�
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
			MessageBox(_T("�޷����������"));
			pcap_freealldevs(allncs);//�ͷ��豸�б�
			return -1;
		}
	}

	//(6)���ù�����
	if (pcap_setfilter(dpHandle, &fcode) < 0)
	{
		MessageBox(_T("���������ô���"));
		pcap_freealldevs(allncs);//�ͷ��豸�б�
		return -1;
	}

	//(7)���ݰ��洢·��
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
		MessageBox(_T("�ļ���������"));
		return -1;
	}

	//(8)�������ݣ������߳�
	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, txysniffer_CapThread, this, 0, threadCap);
	if (m_ThreadHandle == NULL) {
		CString str;
		str.Format(_T("�����̴߳��󣬴���Ϊ��%d."), GetLastError());
		MessageBox(str);
		return -1;
	}
	return 1;
}

//�����̺߳���111111111111111111111111111111111111111111111111
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
	while ((flag = pcap_next_ex(pthis->dpHandle, &data_header, &pkt_data)) >= 0)
	{
		if (flag == 0)//��ʱ
			continue;
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));
		if (data == NULL) {
			MessageBox(NULL, _T("�ռ��������޷������µ����ݰ�"), _T("Error"), MB_OK);
			return -1;
		}

		//������������������ݰ����ڴ���Χ��
		if (analyse_data_frame(pkt_data, data, &(pthis->packetCount)) < 0)
			continue;

		//�����ݰ����浽�򿪵��ļ���
		if (pthis->dumpFile != NULL)
			pcap_dump((unsigned char*)pthis->dumpFile, data_header, pkt_data);

		/********************���¿ؼ�*********************/
		pthis->Sniffer_updatePacket();
		pthis->Sniffer_updateList(data_header, data, pkt_data);
	}
	return 1;
}

void CtxysnifferDlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void CtxysnifferDlg::OnBnClickedButton2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void CtxysnifferDlg::OnBnClickedButton3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void CtxysnifferDlg::OnBnClickedButton4()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}
