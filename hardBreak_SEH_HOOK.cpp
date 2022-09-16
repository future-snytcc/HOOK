#include "SEHHook.h"

//  *****此文件为dll文件*****

/// <summary>
/// 获取目标线程
/// </summary>

HANDLE tarThreadID;
DWORD mHookAddr = 0x0040B09F;		//要HOOK的目标地址
DWORD OriginalAddr = 0x0040B0A7;	//mHookAddr地址执行完的下一条地址

typedef HANDLE(*pOpenThread) (_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwThreadId);

typedef int (*pMessageBoxW) (_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType);

pOpenThread mOpenThread;
pMessageBoxW mMessageBox;


/// <summary>
/// 在此函数内修改当前线程上下文，即HOOK想要hook的数据、代码..
/// </summary>
/// <param name="context"></param>
void ChangeContextHOOK(PCONTEXT context)
{
	DWORD addr = context->Ebp + 0x5560;		//保存阳光数量的地址
	DWORD dwOldProtect = 0;
	VirtualProtect((DWORD*)addr,4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(DWORD*)addr = 0x1000;			//更改阳光数为0x1000
	VirtualProtect((DWORD*)addr, 4, dwOldProtect, 0);
	OutputDebugString(L"ChangeContextHOOK");
}

BOOL getTarThread()
{
	DWORD dwCount = 0;
	THREADENTRY32 te32;
	TCHAR buf[256] = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	HMODULE hker = LoadLibrary(L"kernel32.dll");
	if (!hker) {
		OutputDebugString(L"get kernel32.dll error!\r\n");
		return false;
	}
	mOpenThread = (pOpenThread)GetProcAddress(hker, "OpenThread");
	if (Thread32First(hSnapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == GetCurrentProcessId())
			{
				dwCount++;
				if (1 == dwCount) {			//判断是否为要注入的目标线程，第一个一般为主线程，此值根据x32dbg线程窗口的序号来，这里要hook的线程是主线程，所以判断是否等于1
					wsprintf(buf,L"find tar thread ID:%x", te32.th32ThreadID);
					OutputDebugString(buf);
					tarThreadID = mOpenThread(		//打开目标线程
						THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
						false,
						te32.th32ThreadID);
					if (!tarThreadID) {
						OutputDebugString(L"OpenThread error!\r\n");
						return false;
					}
					wsprintf(buf, L"thread handle:%x", (DWORD)tarThreadID);
					OutputDebugString(buf);
					return true;
				}
			}
		} while (Thread32Next(hSnapshot, &te32));
	}
	CloseHandle(hSnapshot);
	return true;
}

/// <summary>
/// 异常处理函数
/// </summary>
/// <param name="pExceptionInfor"></param>
/// <returns></returns>
LONG WINAPI mExceptionFunc(PEXCEPTION_POINTERS pExceptionInfor)
{
	if (pExceptionInfor->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {			//判断是否是单步异常
		OutputDebugString(L"search exception");
		if ((DWORD)pExceptionInfor->ExceptionRecord->ExceptionAddress == mHookAddr) {		//判断异常位置是否为自定义的硬件断点异常
			PCONTEXT pContext = pExceptionInfor->ContextRecord;		//定义当前线程上下文的指针，后面将更改此指针内的值
			ChangeContextHOOK(pContext);				//在此函数内修改当前线程上下文，即HOOK想要hook的位置
			OutputDebugString(L"ChangeContext success");
			pContext->Eip = OriginalAddr;				//执行完异常后继续要执行的地址，不能再是HOOK地址了，否则会无限循环，应该是hook地址的下一条指令的地址
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;		//寻找下一个异常
}

/// <summary>
/// 设置异常处理函数
/// </summary>
void setUnhandleException()
{

	SetUnhandledExceptionFilter(mExceptionFunc);		//先创建一个异常处理函数

	CONTEXT threadContext = {CONTEXT_DEBUG_REGISTERS};
	OutputDebugString(L"set dr0");
	threadContext.Dr0 = mHookAddr;			//设置HOOK的目标地址，用硬件断点来触发异常，在异常函数中判断发生异常的地址是否是自定义的异常地址
	threadContext.Dr7 = 1;					//DR7 = 1,局部有效
	SetThreadContext(tarThreadID,&threadContext);
	CloseHandle(tarThreadID);
}

void setSEHHOOK()
{
	if (!getTarThread()) {
		return;
	}
	setUnhandleException();
}
