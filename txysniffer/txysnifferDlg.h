
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

	int txysniffer_initCap();//初始化Winpcap
	int txysniffer_startCap();//开始捕获

	int ncCount;//网卡计数
	char errorBufffer[PCAP_ERRBUF_SIZE];//错误缓冲区
	pcap_if_t *allncs;//网卡列表
	pcap_if_t *nc;//网卡
	pcap_t *dpHandle;//捕获
	char filePath[1024];//文件路径
	char fileName[1024];//文件名称
	pcap_dumper_t *dumpFile;//存储网络数据的文件描述符

	HANDLE m_ThreadHandle;//接收数据线程


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
	CButton m_savebutton;
	CButton m_readbutton;
	CComboBox m_netcardComboBox;
	CComboBox m_rulefilterComboBox;
	CEdit m_TCPedit;
	CEdit m_UDPedit;
	CEdit m_HTTPedit;
	CEdit m_ARPedit;
	CEdit m_IPv4edit;
	CEdit m_IPv6edit;
	CEdit m_ICMPv4edit;
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
};
