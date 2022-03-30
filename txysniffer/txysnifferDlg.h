#pragma warning(disable:4996)
// txysnifferDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include "pcap.h"


// CtxysnifferDlg �Ի���
class CtxysnifferDlg : public CDialogEx
{
// ����
public:
	CtxysnifferDlg(CWnd* pParent = NULL);	// ��׼���캯��

	void txysniffer_initCap();//��ʼ��Winpcap

	char filePath[1024];//�ļ�·��
	char fileName[1024];//�ļ�����
	pcap_dumper_t *dumpFile;//�洢�������ݵ��ļ�������

	int txysniffer_updatePacket();//�������ݰ�
	int txysniffer_updateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data);//�����б�

	HANDLE m_ThreadHandle;//���������߳�
	struct packet_count packetCount;//�����������
	CPtrList m_localDataList;//���汾�ػ������ݰ�
	CPtrList m_netDataList;//���������л�ȡ�����ݰ�
	int packetNum;//��ͳ��

	int txysniffer_saveFile();//�����ļ�
	int txysniffer_readFile(CString path);//��ȡ�ļ�
	void print_packet_hex(const u_char* packet, int packet_size, CString *bufffer);//�༭�����ݸ�ʽ����ʾ
	int txysniffer_updateEdit(int index);//���±༭��
	int txysniffer_updateTree(int index);//�������ο�


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
