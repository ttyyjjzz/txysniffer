
// txysniffer.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CtxysnifferApp: 
// �йش����ʵ�֣������ txysniffer.cpp
//

class CtxysnifferApp : public CWinApp
{
public:
	CtxysnifferApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CtxysnifferApp theApp;