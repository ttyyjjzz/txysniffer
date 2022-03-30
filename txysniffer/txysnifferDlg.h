#pragma warning(disable:4996)
// txysnifferDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "pcap.h"


// CtxysnifferDlg 对话框
class CtxysnifferDlg : public CDialogEx
{
// 构造
public:
	CtxysnifferDlg(CWnd* pParent = NULL);	// 标准构造函数

	void txysniffer_initCap();//初始化Winpcap

	char filePath[1024];//文件路径
	char fileName[1024];//文件名称
	pcap_dumper_t *dumpFile;//存储网络数据的文件描述符

	int txysniffer_updatePacket();//更新数据包
	int txysniffer_updateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data);//更新列表

	HANDLE m_ThreadHandle;//接收数据线程
	struct packet_count packetCount;//各类包计数器
	CPtrList m_localDataList;//保存本地化的数据包
	CPtrList m_netDataList;//保存网络中获取的数据包
	int packetNum;//包统计

	int txysniffer_saveFile();//保存文件
	int txysniffer_readFile(CString path);//读取文件
	void print_packet_hex(const u_char* packet, int packet_size, CString *bufffer);//编辑框数据格式化显示
	int txysniffer_updateEdit(int index);//更新编辑框
	int txysniffer_updateTree(int index);//更新树形框


// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TXYSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CButton m_startbutton;
	CButton m_stopbutton;
	CButton m_clearbutton;
	CButton m_exitbutton;
	CComboBox m_netcardComboBox;
	CComboBox m_rulefilterComboBox;
	CEdit m_TCPedit;
	CEdit m_UDPedit;
	CEdit m_HTTPedit;
	CEdit m_ARPedit;
	CEdit m_IPedit;
	CEdit m_IPv6edit;
	CEdit m_ICMPedit;
	CEdit m_ICMPv6edit;
	CEdit m_elseedit;
	CEdit m_totaledit;
	CEdit m_edit;
	CListCtrl m_list;
	CTreeCtrl m_tree;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	CButton m_ALLcheck;
	CButton m_ARPcheck;
	CButton m_IPcheck;
	CButton m_TCPcheck;
	CButton m_UDPcheck;
	CButton m_ICMPcheck;
	CButton m_HTTPcheck;
	CButton m_FTPcheck;
};
