
// CapturePacketDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "CapturePacket.h"
#include "CapturePacketDlg.h"
#include "afxdialogex.h"
#include "data.h"
#include <iostream>
#include <string>

using namespace std;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

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


// CCapturePacketDlg 对话框



CCapturePacketDlg::CCapturePacketDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_CAPTUREPACKET_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCapturePacketDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_IFs, IF);
	DDX_Control(pDX, IDC_dtl, detail);
	DDX_Control(pDX, IDC_pkt, pkt);
	DDX_Control(pDX, IDC_capture, captureButton);
}

BEGIN_MESSAGE_MAP(CCapturePacketDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_capture, &CCapturePacketDlg::OnBnClickedcapture)
	ON_BN_CLICKED(IDC_stop, &CCapturePacketDlg::OnBnClickedstop)
	ON_BN_CLICKED(IDC_return, &CCapturePacketDlg::OnBnClickedreturn)
	ON_BN_CLICKED(IDC_getIF, &CCapturePacketDlg::OnBnClickedgetif)
	ON_LBN_SELCHANGE(IDC_IFs, &CCapturePacketDlg::OnLbnSelchangeIfs)
	ON_MESSAGE(WM_PACKET, &CCapturePacketDlg::OnPacket)
END_MESSAGE_MAP()


// CCapturePacketDlg 消息处理程序

BOOL CCapturePacketDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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
	threadBegin = false;

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CCapturePacketDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CCapturePacketDlg::OnPaint()
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
HCURSOR CCapturePacketDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//显示所有接口的名称
void CCapturePacketDlg::displayAllIF()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)	//通过pcap_findalldevs_ex函数获取所有接口
	{
		MessageBox(L"获取以太网接口失败");
		return;
	};
	for (pcap_if_t* d = alldevs; d; d = d->next)	//遍历每个接口显示名称
	{
		size_t len = strlen(d->name) + 1;
		wchar_t* name = (wchar_t *)malloc(sizeof(wchar_t) * len);
		size_t converted = 0;
		mbstowcs_s(&converted, name, len, d->name, _TRUNCATE);
		IF.AddString(name);
	}
}

//数据包捕获工作者线程
UINT Capturer(PVOID hWnd)
{
	CCapturePacketDlg* c = (CCapturePacketDlg*)hWnd;
	int res = 0;
	//利用pcap_next_ex()函数捕获数据包
	while (c->threadBegin && (res = pcap_next_ex(c->pt, &c->header, &c->pkt_data)) >= 0)
	{
		if (res == 0)
			continue;
		AfxGetApp()->m_pMainWnd->PostMessageW(WM_PACKET, 0, 0);	//利用窗口的PostMessageW函数发送消息
	}
	if (res == -1)
		return -1;
	return 0;
}

//鼠标点击捕获报文按钮消息处理函数
void CCapturePacketDlg::OnBnClickedcapture()
{
	// TODO: 在此添加控件通知处理程序代码
	if (IFname == NULL) return;
	if ((pt = pcap_open(IFname, 100, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL)	//pcap_open函数返回NULL，调用出错
	{
		size_t len = strlen(errbuf) + 1;
		wchar_t* err = (wchar_t*)malloc(sizeof(wchar_t) * len);
		size_t convert = 0;
		mbstowcs_s(&convert, err, len, errbuf, _TRUNCATE);
		MessageBox(err);
		return;
	}
	//开始监听
	captureButton.EnableWindow(0);
	CString str;
	str = "监听";
	str += IFname;
	pkt.AddString(str);
	//创建数据包捕获工作者线程
	threadBegin = true;
	captureThread = AfxBeginThread(Capturer, this, THREAD_PRIORITY_NORMAL);
}

//鼠标点击停止捕获按钮消息处理函数
void CCapturePacketDlg::OnBnClickedstop()
{
	// TODO: 在此添加控件通知处理程序代码
	captureButton.EnableWindow(1);
	threadBegin = false;
	WaitForSingleObject(captureThread, 100);
}

//鼠标点击返回按钮消息处理函数
void CCapturePacketDlg::OnBnClickedreturn()
{
	// TODO: 在此添加控件通知处理程序代码
	captureButton.EnableWindow(1);
	threadBegin = false;
	WaitForSingleObject(captureThread, 100);
	pkt.ResetContent();
}

//鼠标点击获取接口按钮消息处理函数
void CCapturePacketDlg::OnBnClickedgetif()
{
	// TODO: 在此添加控件通知处理程序代码
	IF.ResetContent();
	detail.ResetContent();
	displayAllIF();
}

//显示选择接口的具体信息
void CCapturePacketDlg::displayDetail()
{
	int num = IF.GetCurSel();
	int i = 0;
	pcap_if_t* d;
	for (d = alldevs; i < num && d; i += 1, d = d->next);
	IFname = d->name;
	size_t nlen = strlen(d->name) + 1;
	size_t dlen = strlen(d->description) + 1;
	wchar_t* name = (wchar_t*)malloc(sizeof(wchar_t) * nlen);
	wchar_t* des = (wchar_t*)malloc(sizeof(wchar_t) * dlen);
	size_t nconvert = 0;
	size_t dconvert = 0;
	mbstowcs_s(&nconvert, name, nlen, d->name, _TRUNCATE);
	mbstowcs_s(&dconvert, des, dlen, d->description, _TRUNCATE);
	detail.AddString(name);
	detail.AddString(des);
}

//将网络序转换为主机序
void CCapturePacketDlg::dataToH(Data_t *data)
{
	data->FrameHeader.FrameType = ntohs(data->FrameHeader.FrameType);
	data->IPHeader.Checksum = ntohs(data->IPHeader.Checksum);
	data->IPHeader.DstIP = ntohl(data->IPHeader.DstIP);
	data->IPHeader.FLAG_Segment = ntohs(data->IPHeader.FLAG_Segment);
	data->IPHeader.ID = ntohs(data->IPHeader.ID);
	data->IPHeader.SrcIP = ntohl(data->IPHeader.SrcIP);
	data->IPHeader.TotalLen = ntohs(data->IPHeader.TotalLen);
}

//将二进制的MAC地址值转换为十六进制
void CCapturePacketDlg::getMAC(CString& str, BYTE* MAC)
{
	for (int i = 0; i < 6; i++)
	{
		int a = (int)MAC[i];
		int h = a >> 4;
		int l = a & 0xf;
		if (h < 10)
		{
			str += (char)('0' + h);
		}
		else
			str += (char)('A' + h - 10);
		if (l < 10)
		{
			str += (char)('0' + l);
		}
		else
			str += (char)('A' + l - 10);
		if (i < 5)
			str += '-';
	}
}

//将二进制的IP地址转换成A.B.C.D的十进制形式
void CCapturePacketDlg::getIP(CString& str, ULONG IP)
{
	ULONG ip;

	for (int i = 3; i >= 0; i--)
	{
		ip = (IP >> (i * 8)) % 256;
		str += to_string(ip).c_str();
		if (i > 0)
			str += '.';
	}
}

//将字转换为十六进制
void CCapturePacketDlg::getHexe(CString& str, WORD num)
{
	WORD flag;
	for (int i = 3; i >= 0; i--)
	{
		flag = (num >> (4 * i)) % 16;
		if (flag < 10)
			str += (char)('0' + flag);
		else
			str += (char)('A' + flag - 10);
	}
}

//计算头部校验和
WORD CCapturePacketDlg::calcChecksum(Data_t* data)
{
	UINT sum = 0;
	WORD a[9];
	ULONG b;
	b = data->IPHeader.DstIP >> 16;
	a[0] = b;
	a[1] = (data->IPHeader.DstIP % 65536);
	b = data->IPHeader.SrcIP >> 16;
	a[2] = b;
	a[3] = (data->IPHeader.SrcIP % 65536);
	a[4] = data->IPHeader.FLAG_Segment;
	a[5] = data->IPHeader.ID;
	a[6] = data->IPHeader.TotalLen;
	a[7] = data->IPHeader.Ver_HLen;
	a[7] <<= 8;
	a[7] += data->IPHeader.TOS;
	a[8] = data->IPHeader.TTL;
	a[8] <<= 8;
	a[8] += data->IPHeader.Protocol;
	for (int i = 0; i < 9; i++)
		sum += a[i];
	WORD result;
	result = (sum >> 16) + sum % 65536;
	result = ~result;
	return result;
}

//鼠标选择列表框中的接口消息处理函数
void CCapturePacketDlg::OnLbnSelchangeIfs()
{
	// TODO: 在此添加控件通知处理程序代码
	detail.ResetContent();
	displayDetail();
}

//线程捕获数据包后发送的消息的处理函数
LRESULT CCapturePacketDlg::OnPacket(WPARAM wparam, LPARAM lparam)
{
	pkt.AddString(L"-----------------------------------------------------------------------------------------------------------");
	Data_t* IPPacket;
	WORD RecvChecksum;
	IPPacket = (Data_t*)pkt_data;
	dataToH(IPPacket);
	CString str;

	str = "源MAC地址：";
	getMAC(str, IPPacket->FrameHeader.SrcMAC);
	str += "  目的MAC地址：";
	getMAC(str, IPPacket->FrameHeader.DesMAC);
	if (IPPacket->FrameHeader.FrameType < 0x0800)	//以太帧的长度/类型字段小于0800H时表示帧的长度
	{
		str += "  帧长度：";
		str += to_string((int)IPPacket->FrameHeader.FrameType).c_str();
	}
	else
	{
		if (IPPacket->FrameHeader.FrameType == 0x0800)	//以太帧的长度/类型字段等于0800H时说明使用的IP协议
		{
			str += "  帧类型：";
			str += "IP";
		}
		else if (IPPacket->FrameHeader.FrameType == 0x0806)	//以太帧的长度/类型字段等于0806H时说明使用的ARP协议
		{
			str += "  帧类型：";
			str += "ARP";
		}
	}	
	pkt.AddString(str);

	if (IPPacket->FrameHeader.FrameType != 0x0800)	//不是IP协议时返回
		return 0;

	str = "源IP地址：";
	getIP(str, IPPacket->IPHeader.SrcIP);
	str += "  目的IP地址：";
	getIP(str, IPPacket->IPHeader.DstIP);
	pkt.AddString(str);

	str = "长度：";
	str += to_string((int)IPPacket->IPHeader.TotalLen).c_str();
	str += "  标识：";
	getHexe(str, IPPacket->IPHeader.ID);
	str += "  头部校验和：";
	getHexe(str, IPPacket->IPHeader.Checksum);
	str += "  计算出的头部校验和：";
	WORD ccm = calcChecksum(IPPacket);
	getHexe(str, ccm);
	pkt.AddString(str);

	return 0;
}
