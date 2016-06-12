#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#define STEAM_API_NODLL
#include "steam/steam_api.h"
#include "steam/isteammatchmaking.h"
#include "steam/ISteamGameServer.h"
#include "steam/steam_gameserver.h"
#include "steam/isteamnetworking.h"

#include <iostream>
#include <string>
#include <sstream>

/* GLOBAL */
CSteamID g_ServerSteamID;
CSteamID g_AdminSteamID;

void hexdump(void *data, int size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for (n = 1; n <= size; n++) {
        if (n % 16 == 1) {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", ((unsigned int)p - 
                        (unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - 
                    strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - 
                    strlen(charstr) - 1);
        if (n % 16 == 0) {
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0) {
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr) - 
                        strlen(hexstr)-1);
            strncat_s(charstr, sizeof(charstr), " ", sizeof(charstr) - 
                        strlen(charstr)-1);
        }
        p++;
    }

    if (strlen(hexstr) > 0) {
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    
}

enum EMessage
{
    // Server messages
    k_EMsgServerBegin = 0,
    k_EMsgServerSendInfo = k_EMsgServerBegin + 1,
    k_EMsgServerFailAuthentication = k_EMsgServerBegin + 2,
    k_EMsgServerPassAuthentication = k_EMsgServerBegin + 3,
    k_EMsgServerUpdateWorld = k_EMsgServerBegin + 4,
    k_EMsgServerExiting = k_EMsgServerBegin + 5,
    k_EMsgServerPingResponse = k_EMsgServerBegin + 6,
    k_EMsgServerPlayerStatusUpdate = k_EMsgServerBegin + 7,
    // Client messages
    k_EMsgClientBegin = 500,
    k_EMsgClientInitiateConnection = k_EMsgClientBegin + 1,
    k_EMsgClientBeginAuthentication = k_EMsgClientBegin + 2,
    k_EMsgClientSendLocalUpdate = k_EMsgClientBegin + 3,
    k_EMsgClientLeavingServer = k_EMsgClientBegin + 4,
    k_EMsgClientPing = k_EMsgClientBegin + 5,
    // P2P authentication messages
    k_EMsgP2PBegin = 600,
    k_EMsgP2PSendingTicket = k_EMsgP2PBegin + 1,
    // voice chat messages
    k_EMsgVoiceChatBegin = 700, 
    k_EMsgVoiceChatPing = k_EMsgVoiceChatBegin + 1,	// just a keep alive message
    k_EMsgVoiceChatData = k_EMsgVoiceChatBegin + 2,	// voice data from another player
    // force 32-bit size enum so the wire protocol doesn't get outgrown later
    k_EForceDWORD  = 0x7fffffff, 
};

class ServerList : public ISteamMatchmakingServerListResponse
{
public:
    ServerList()
    {
    
    }
    virtual void ServerResponded(HServerListRequest hRequest, int iServer)
    {
        gameserveritem_t *pServer = SteamMatchmakingServers()->GetServerDetails(hRequest, iServer);
        printf("[+] ServerResponded\n");
        if (pServer) {
            printf("[+] Name: %s (%i/%i) at %s ping(%d)\n", pServer->GetName(), 
                    pServer->m_nPlayers, pServer->m_nMaxPlayers, 
                    pServer->m_NetAdr.GetConnectionAddressString(), 
                    pServer->m_nPing);
            printf("[+] ServerSteamID: %llu (0x%I64x)\n", pServer->m_steamID.ConvertToUint64(), 
            pServer->m_steamID.ConvertToUint64());
            if (pServer->m_bPassword == FALSE) {
                g_ServerSteamID = pServer->m_steamID;
            }
            else {
                printf("[+] password protected!\n");
            }
        }
        printf("---------------\n");
    } 
    virtual void ServerFailedToRespond(HServerListRequest hRequest, int iServer)
    {
        (void)hRequest;
        (void)iServer;
        printf("[+] ServerFailedToRespond\n");
    }

    virtual void RefreshComplete(HServerListRequest hRequest, EMatchMakingServerResponse response)
    {
        (void)hRequest;
        (void)response;
        printf("[+] RefreshComplete\n");
        SteamAPI_Shutdown();
        ExitProcess(42);
    }
};

class PingServerList : public ISteamMatchmakingPingResponse
{
public:
    PingServerList()
    {
    
    }
    virtual void ServerResponded(gameserveritem_t &server)
    {
        printf("[+] ServerResponded\n");
        printf("%s %llu (%i/%i) at %s ping(%d)\n", server.GetName(), server.m_steamID.ConvertToUint64(), server.m_nPlayers, server.m_nMaxPlayers, server.m_NetAdr.GetConnectionAddressString(), server.m_nPing);
        g_ServerSteamID = server.m_steamID;
    }
    virtual void ServerFailedToRespond()
    {
        printf("[+] ServerFailedToRespond\n");
    }
    virtual void RefreshComplete(HServerListRequest hRequest, EMatchMakingServerResponse response) 
    {
        (void)hRequest;
        (void)response;
        printf("[+] RefreshComplete\n");
        SteamAPI_Shutdown();
        ExitProcess(42);
    }
};

VOID ListGame(VOID)
{
    ServerList response;
    HServerListRequest m_hServerListRequest;
    MatchMakingKeyValuePair_t pFilters[1];
    ISteamMatchmakingServers *servers = SteamMatchmakingServers();
    MatchMakingKeyValuePair_t *pFilter = pFilters;
    
    
    strncpy(pFilters[0].m_szKey, "gamedir", 0x100);
    strncpy(pFilters[0].m_szValue, "HOMM3", 0x100);
    m_hServerListRequest = servers->RequestInternetServerList(SteamUtils()->GetAppID(), &pFilter, 1, &response);
    while (servers->IsRefreshing(m_hServerListRequest)) {
        Sleep(1000);
        SteamAPI_RunCallbacks();
        if (g_ServerSteamID.GetAccountID() != 0) {
            break;
        }
    }
}

VOID CheckFriendParty(VOID)
{
    ISteamMatchmakingServers *servers = SteamMatchmakingServers();
    ISteamFriends *friends = SteamFriends();
    FriendGameInfo_t pFriendGameInfo;
    CSteamID FSteamID;
    PingServerList pingrep;
    HServerQuery m_hServerQuery;
    
    printf("[+] friends->GetFriendCount() : 0x%08X\n", friends->GetFriendCount(0xFFFF));
    FSteamID = friends->GetFriendByIndex(0, 0xFFFF);
    printf("[+] FSteamID  : %llu (0x%I64x)\n", FSteamID.ConvertToUint64(), FSteamID.ConvertToUint64());
    printf("[+] Nick      : %s\n", friends->GetFriendPersonaName(FSteamID));
    friends->GetFriendGamePlayed(FSteamID, &pFriendGameInfo);
    printf("[+] m_gameID     : %llu\n", pFriendGameInfo.m_gameID.ToUint64());
    printf("[+] m_unGameIP   : %08X\n", pFriendGameInfo.m_unGameIP);
    printf("[+] m_usGamePort : 0x%04X (%d)\n", pFriendGameInfo.m_usGamePort, pFriendGameInfo.m_usGamePort);
    printf("[+] m_usQueryPort: 0x%04X (%d)\n", pFriendGameInfo.m_usQueryPort, pFriendGameInfo.m_usQueryPort);
    while (g_ServerSteamID.GetAccountID() == 0) {
        m_hServerQuery = servers->PingServer(pFriendGameInfo.m_unGameIP, pFriendGameInfo.m_usQueryPort, &pingrep);
        Sleep(500);
        SteamAPI_RunCallbacks();
    }
}

VOID HandleMsgServerSendInfo(char *pchRecvBuf)
{
    uint64 SteamIDServer;
    BYTE bIsVACSecure;
    char rgchToken[0x400] = {0};
    uint32 unTokenLen = 0;
    char answer[0x500] = {0};
    DWORD answer_len = 0;
    DWORD opcode;
    uint64 MySteamID;
    HAuthTicket m_hAuthTicket;
    
    SteamIDServer = *(uint64*)(pchRecvBuf + 4);
    bIsVACSecure = *(BYTE*)(pchRecvBuf + 4 + 8);
    printf("[+] 0x01: MSG SERVER BEGIN\n");                                     
    printf("[+] SteamIDServer : %llu (0x%I64x)\n", SteamIDServer, SteamIDServer);
    printf("[+] bIsVACSecure  : %02X\n", bIsVACSecure);
    printf("[+] SessionName   : %s\n", pchRecvBuf + 4 + 8 + 1);

    memset(rgchToken, 0, 0x400);
    m_hAuthTicket = SteamUser()->GetAuthSessionTicket(rgchToken, sizeof (rgchToken), &unTokenLen);
    opcode = k_EMsgClientBeginAuthentication;
    memcpy(answer + answer_len, &opcode, sizeof (opcode));
    answer_len += sizeof (opcode);
    memcpy(answer + answer_len, &unTokenLen, sizeof (unTokenLen));
    answer_len += sizeof (unTokenLen);
    memcpy(answer + answer_len, rgchToken, unTokenLen);
    answer_len += 0x400;
    MySteamID = SteamUser()->GetSteamID().ConvertToUint64();
    memcpy(answer + answer_len, &MySteamID, sizeof (MySteamID));
    answer_len += sizeof (MySteamID);
    if (!SteamNetworking()->SendP2PPacket(g_ServerSteamID, answer, answer_len, k_EP2PSendUnreliable)) {
        printf("[-] HandleMsgServerSendInfo - SendP2PPacket failed\n");
    }    
}

VOID HandleMsgServerPlayerStatusUpdate(char *pchRecvBuf)
{
    printf("[+] 0x07: MSG PLAYER STATUS UPDATE\n");
    if (*((DWORD *)pchRecvBuf + 6) >= 8) {
        printf("[-] MAX_PLAYERS_PER_SERVER reached!\n");
        SteamAPI_Shutdown();
        ExitProcess(42);
    }            
    if (*((DWORD *)pchRecvBuf + 1) == 8) {
        printf("[+] Player %d left\n", *((DWORD *)pchRecvBuf + 6));
    }
    else if (*((DWORD *)pchRecvBuf + 1) == 7) {
        printf("[+] Player %d joined\n", *((DWORD *)pchRecvBuf + 6));
        if (*((DWORD *)pchRecvBuf + 6) == 0) {
            g_AdminSteamID.SetFromUint64(*((int64*)((char*)pchRecvBuf + 0x8)));
            printf("[+] g_AdminSteamID : %llu (0x%I64x)\n", g_AdminSteamID.ConvertToUint64(), g_AdminSteamID.ConvertToUint64());
        }
    }
}

int HandleMessage(char *pchRecvBuf, unsigned int len)
{
    DWORD opcode;

    if (len < 4) {
        return 0;
    }
    opcode = *(DWORD*)pchRecvBuf;
    switch (opcode) {
    
        case k_EMsgServerSendInfo:
            if (len != 0x8D) {
                printf("[-] BAD MSG SERVER BEGIN LENGTH!\n");
                break;
            }
            HandleMsgServerSendInfo(pchRecvBuf);
            break;
    
        case k_EMsgServerPlayerStatusUpdate:
            HandleMsgServerPlayerStatusUpdate(pchRecvBuf);
            break;
        
        case k_EMsgServerPassAuthentication:
            printf("[+] 0x%02X: MSG SERVER PASS AUTHENTIFICATION\n", k_EMsgServerPassAuthentication);
            if (!SteamNetworking()->SendP2PPacket(g_ServerSteamID, "\xF9\x01\x00\x00", 4, k_EP2PSendUnreliable)) {
                printf("[-] HandleMessage - SendP2PPacket failed\n");
            }
            break;
        case k_EMsgServerPingResponse:
            printf("[+] 0x%02X: MSG SERVER PING RESPONSE\n", k_EMsgServerPingResponse);
            return 42;
            break;            
        default:
            printf("[-] opcode 0x%08X not handled!\n", opcode);
            break;
    }
    return 0;
}

DWORD ReceiveMessage(VOID)
{
    unsigned int cubMsgSize;
    char pchRecvBuf[0x400];
    CSteamID steamIDRemote;
    
    while (!SteamNetworking()->IsP2PPacketAvailable(&cubMsgSize)) {
    
    }
    if (!SteamNetworking()->ReadP2PPacket(pchRecvBuf, cubMsgSize, &cubMsgSize, &steamIDRemote)) {
        printf("[-] ReadP2PPacket failed\n");
        SteamAPI_Shutdown();
        ExitProcess(42);
    }
    hexdump(pchRecvBuf, cubMsgSize);
    return HandleMessage(pchRecvBuf, cubMsgSize);
}

VOID CraftClientSendLocalUpdate(BYTE *buf, DWORD SizeData)
{
    DWORD opcode = 0x1F7;
    BYTE msg[0x200] = {0};
    DWORD pos = 0;
    uint64 MySteamID = SteamUser()->GetSteamID().ConvertToUint64();
    
    *(DWORD*)(msg + pos) = opcode;
    pos += 4;
    *(DWORD*)(msg + pos) = SizeData;
    pos += 4;
    *(DWORD*)(msg + pos) = 0x41424344;  // LEAKED POINTER
    pos += 4;
    *(DWORD*)(msg + pos) = 0;           // TO
    pos += 4;
    memcpy(msg + pos, &MySteamID, 8);
    pos += 8;
    memcpy(msg + pos, buf, SizeData);
    pos += SizeData;
    printf("[+] Sending 0x%08X (%d)\n", pos, pos);
    hexdump(msg, pos);
    if (!SteamNetworking()->SendP2PPacket(g_AdminSteamID, msg, pos, k_EP2PSendUnreliable)) {
        printf("[-] CraftClientSendLocalUpdate - SendP2PPacket failed\n");
    }
}

VOID JoinServer(VOID)
{
    DWORD FlagAndSize = 0;
    BYTE msg[0x200] = {0};
    DWORD pos = 0;

    FlagAndSize = (((0x20 * (0x6C - 0x0C) | 0x04 & 0x1F) << 7) | 0x45);
    *(DWORD*)(msg + pos) = FlagAndSize;
    pos += 4;
    *(DWORD*)(msg + pos) = 0xEEEEEEEE;
    pos += 4;
    *(DWORD*)(msg + pos) = 0;
    pos += 4;
    memcpy(msg + pos, "3DO/HEROES3/1", strlen("3DO/HEROES3/1"));
    pos += 0x20;
    memcpy(msg + pos, "pseudo", strlen("pseudo"));
    pos += 0x20;
    memcpy(msg + pos, "", strlen(""));
    pos += 0x20;
    CraftClientSendLocalUpdate(msg, pos);
}

VOID AuthServer(VOID)
{
    char msg[0x100];
    unsigned int opcode_init = 0x01F5;
    
    *(DWORD*)(msg) = opcode_init;
    if (!SteamNetworking()->SendP2PPacket(g_ServerSteamID, &msg, 4, k_EP2PSendUnreliable)) {
        printf("[-] SendP2PPacket failed\n");
        return;
    }
    while (ReceiveMessage() != 42) {

    }
    printf("[+] Auth ok! Now \n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    ISteamUser *SUser = NULL;
    
    if (!SteamAPI_Init()) {
        printf("[-] SteamAPI_Init failed\n");
        return 1;
    }
    SUser = SteamUser();
    if (!SUser) {
        printf("[-] SteamUser failed\n");
        return 1;
    }
    if (!SUser->BLoggedOn()) {
        printf("[-] Steam user not logged in\n");
        return 1;
    }
    printf("\n\n\n[+] SteamUserID is %llu (0x%I64x)\n", SteamUser()->GetSteamID().ConvertToUint64(), SteamUser()->GetSteamID().ConvertToUint64());
    ListGame();
    //CheckFriendParty();
    if (!g_ServerSteamID.IsValid()) {
        printf("[-] g_ServerSteamID invalid\n");
        return 1;
    }
    printf("[+] Autentification to server in progress...\n");
    AuthServer();
    printf("[+] Joining server...\n");
    JoinServer();
    while (ReceiveMessage() != 42) {

    }
    SteamAPI_Shutdown();
    return 0;
}