#pragma warning(disable:4996)
// txysnifferDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"

#include "mypcap.h"


// CtxysnifferDlg �Ի���
class CtxysnifferDlg : public CDialogEx
{
// ����
public:
	CtxysnifferDlg(CWnd* pParent = NULL);	// ��׼���캯��
	
	//pcap_dumper_t *dumpFile;//�洢�������ݵ��ļ�������

	HANDLE m_ThreadHandle;//���������߳�
	MyPcap tmpMyPcap;//ʵ�����Զ��������
	//CPtrList m_localDataList;//���汾�ػ������ݰ�
	//CPtrList m_netDataList;//���������л�ȡ�����ݰ�
	//int packetNum;//��ͳ��

	void txysniffer_initCap();//�г���������
	pcap_if_t* get_nc(int incNo, int iTotalncs);//ѡ������
	int get_MacType(CString &eth_strType, u_short eth_Type, bool isFirst);//��ȡEthernet����
	int get_MacAddress(TCHAR * eth_dMac, u_char eth_sMac[]);//��ȡMac��ַ
	int get_IPType(CString &ip_strIP, u_short ip_Type, bool isFirst);//��ȡIP����
	int get_IPAddress(TCHAR * ip_Address, ip_address *ip_addr);//��ȡIP��ַ
	int txysniffer_updatePacket();//�������ݰ�
	int txysniffer_updateList(packet *tmp_pkt);//�����б�
	int txysniffer_filterList();
	int txysniffer_updateEdit(CEdit & medit, packet *pkt);//���±༭��
	int txysniffer_updateTree_mac(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_ip(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_tcp(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_udp(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_icmp(HTREEITEM & hItem, const u_char * pkt_data);
	int txysniffer_updateTree_http(HTREEITEM & hItem, const u_char * pkt_data);
	bool IsHTTP(const u_char *pkt_data);


// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TXYSNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
	int num_total;//�ܼ�
};
