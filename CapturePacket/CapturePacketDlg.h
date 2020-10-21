#include"pcap.h"
#include"data.h"
// CapturePacketDlg.h: 头文件
//

#pragma once

#define WM_PACKET WM_USER+1

// CCapturePacketDlg 对话框
class CCapturePacketDlg : public CDialogEx
{
// 构造
public:
	CCapturePacketDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CAPTUREPACKET_DIALOG };
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
	afx_msg void OnBnClickedcapture();
	afx_msg void OnBnClickedstop();
	afx_msg void OnBnClickedreturn();
	afx_msg void OnBnClickedgetif();
	afx_msg void OnLbnSelchangeIfs();
	afx_msg LRESULT OnPacket(WPARAM wparam, LPARAM lparam);
	DECLARE_MESSAGE_MAP()

private:
	void displayAllIF();
	void displayDetail();
	void dataToH(Data_t* data);
	void getMAC(CString& str, BYTE* MAC);
	void getIP(CString& str, ULONG IP);
	void getHexe(CString& str, WORD num);
	char* IFname;
	char errbuf[PCAP_ERRBUF_SIZE];
	WORD calcChecksum(Data_t* data);
	CButton captureButton;
	CListBox IF;
	CListBox pkt;
	CListBox detail;
	pcap_if_t* alldevs;
	CWinThread* captureThread;

public:
	bool threadBegin;
	pcap_t* pt;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
};

UINT Capturer(PVOID hWnd);
