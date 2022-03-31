#pragma warning(disable:4996)
// txysnifferDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"

#include "mypcap.h"


// CtxysnifferDlg 对话框
class CtxysnifferDlg : public CDialogEx
{
// 构造
public:
	CtxysnifferDlg(CWnd* pParent = NULL);	// 标准构造函数
	
	//pcap_dumper_t *dumpFile;//存储网络数据的文件描述符

	HANDLE m_ThreadHandle;//接收数据线程
	MyPcap tmpMyPcap;//实例化自定义类对象
	//CPtrList m_localDataList;//保存本地化的数据包
	//CPtrList m_netDataList;//保存网络中获取的数据包
	//int packetNum;//包统计

	void txysniffer_initCap();//列出所有网卡
	pcap_if_t* get_nc(int incNo, int iTotalncs);//选中网卡
	int get_MacType(CString &eth_strType, u_short eth_Type, bool isFirst);//获取Ethernet类型
	int get_MacAddress(TCHAR * eth_dMac, u_char eth_sMac[]);//获取Mac地址
	int get_IPType(CString &ip_strIP, u_short ip_Type, bool isFirst);//获取IP类型
	int get_IPAddress(TCHAR * ip_Address, ip_address *ip_addr);//获取IP地址
	int txysniffer_updatePacket();//更新数据包
	int txysniffer_updateList(packet *tmp_pkt);//更新列表
	int txysniffer_filterList();
	int txysniffer_updateEdit(CEdit & medit, packet *pkt);//更新编辑框
	int txysniffer_updateTree_mac(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_ip(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_tcp(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_udp(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_icmp(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_http(HTREEITEM & hItem, const u_char * pkt_data);
	bool IsHTTP(const u_char *pkt_data);


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
	afx_msg LRESULT Message_Pcap(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	CButton m_startbutton;
	CButton m_stopbutton;
	CButton m_refreshbutton;
	CButton m_exitbutton;
	CComboBox m_netcardComboBox;
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
	afx_msg void OnNMDblclkList1(NMHDR *pNMHDR, LRESULT *pResult);
	CButton m_ALLcheck;
	CButton m_ARPcheck;
	CButton m_IPcheck;
	CButton m_TCPcheck;
	CButton m_UDPcheck;
	CButton m_ICMPcheck;
	CButton m_HTTPcheck;
	CButton m_FTPcheck;

private:
	int num_arp;//ARP
	int num_ip;//IP
	int num_udp;//UDP
	int num_tcp;//TCP
	int num_icmp;//ICMP
	int num_http;//HTTP
	int num_ftp;//ftp
	int num_total;//总计
};
