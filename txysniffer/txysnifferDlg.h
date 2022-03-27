
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

	int txysniffer_initCap();//��ʼ��Winpcap
	int txysniffer_startCap();//��ʼ����

	int ncCount;//��������
	char errorBufffer[PCAP_ERRBUF_SIZE];//���󻺳���
	pcap_if_t *allncs;//�����б�
	pcap_if_t *nc;//����
	pcap_t *dpHandle;//����
	char filePath[1024];//�ļ�·��
	char fileName[1024];//�ļ�����
	pcap_dumper_t *dumpFile;//�洢�������ݵ��ļ�������

	HANDLE m_ThreadHandle;//���������߳�


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
