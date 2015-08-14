#include <stdio.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#include "utils.h"

HANDLE              hReceiveThread		= NULL;	// Recieve flag
HANDLE              hPlayerEvent		= NULL;	// Event flag
HANDLE				hKillEvent			= NULL;
DWORD               idReceiveThread		= 0;	// The id of the recieve thread

void send_chat_message(SOCKET *sock, SOCKADDR_IN *sout, int size_name, int size_text);

DWORD WINAPI ReceiveThread(LPVOID lpParameter)
{
    HANDLE      eventHandles[2];
    eventHandles[0] = hPlayerEvent;
    eventHandles[1] = hKillEvent;
	SOCKET		sock;
	BYTE		buf[0x800];
	sockaddr_in incAddr;
	char hostname[NI_MAXHOST];
	char servInfo[NI_MAXSERV];

	sock = (SOCKET)lpParameter;
    //while (WaitForMultipleObjects(2, eventHandles, FALSE,
    //            INFINITE) == WAIT_OBJECT_0)
	for (;;)
    {
		int incAddrLen = sizeof(sockaddr_in);
		int size = recvfrom(sock, (char*)buf, 0x800, 0, (sockaddr*)&incAddr, &incAddrLen);
		int e = WSAGetLastError();
		
		if (size > 0 && e == 0)
		{
			switch (*buf)
			{
			case 0x2:
				//printf("From (%s:%s) Type : 0x2 Size : %X\n", hostname, servInfo, *(DWORD*)(buf + 1));
				//printf("From (%s:%s)\n", hostname, servInfo);
				//printf("Message\n");
				//hex_dump(buf, size);
				break;
			case 0xA:
				getnameinfo((sockaddr*)&incAddr, sizeof (struct sockaddr), hostname,
							NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
				printf("From (%s:%s) Type : 0xA Size : %X\n", hostname, servInfo, *(DWORD*)(buf + 1));
				printf("Message\n");
				hex_dump(buf, size);
				break;
			default:
				getnameinfo((sockaddr*)&incAddr, sizeof (struct sockaddr), hostname,
							NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
				printf("From (%s:%s) Type : 0x%02X Size1 : %X, SizeSocket : %X\n", hostname, servInfo, *(buf),*(DWORD*)(buf + 1), size);
				printf("Unknow Type : %02X\n", (unsigned char)*buf);
				hex_dump(buf, size);
				break;
			}
		}
		//ReceiveMessages();
    }
	printf("BYE BYE\n");
    ExitThread(0);
    return (0);
}

void craft_message(SOCKET *sock, SOCKADDR_IN *sout)
{
	int i;
	int j;

	for (i = 1; i * 2 < 0xFF; i++)
		for (j = 1; j * 2 < 0xFF; j++)
			send_chat_message(sock, sout, i, j * 2);
}

void send_chat_message(SOCKET *sock, SOCKADDR_IN *sout, int size_name, int size_text)
{
	char buf[0x1000];
	int length_message = 0;
	int i;

	// TypeMessage
	*buf = 0x0A;
	length_message += 1;

	// Total Length will be setup at the end
	*(DWORD*)(buf + length_message) = 0x0;
	length_message += 4;

	// RESERVED
	*(DWORD*)(buf + length_message) = 0x00040804;
	length_message += 4;

	// RESERVED
	*(DWORD*)(buf + length_message) = 0x00010000;
	if (size_name + size_text >= 0x100)
	{
		length_message += 4;
		*(buf + length_message) = size_text + size_name;
		length_message += 4;
	}
	else
	{
		length_message += 3;
		*(buf + length_message) = (size_text + size_name + 2 + 2) * 2;
		length_message += 1;
	}

	// NAME START
	*(buf + length_message) = 0x02;
	length_message += 1;
	*(buf + length_message) = size_name * 2;
	length_message += 1;

	// NAME
	memset(buf + length_message, 'A', size_name);
	length_message += size_name;

	// NAME STOP
	*(buf + length_message) = 0x03;
	length_message += 1;

	// SIZE TEXT
	*(buf + length_message) = size_text * 2;
	length_message += 1;

	// TEXT
	memset(buf + length_message, 'A', size_text);
	for (i = 0; i < size_text; i++)
	{
		if (i % 2)
			*(buf + length_message + i) = 0;
	}
	length_message += size_text;

	// STOP TEXT
	*(WORD*)(buf + length_message) = 0x0;
	length_message += 2;

	// END MESSAGE
	*(DWORD*)(buf + length_message) = 0x00050002;
	length_message += 4;

	// NOW WE CAN SETUP LENGTH
	// -1 for TYPE
	// -1 for DWORD SIZE
	//printf("Length message = %X\n", length_message);
	*(DWORD*)(buf + 1) = length_message - 4 - 1;

	hex_dump(buf, length_message);
	if (sendto(*sock, (const char *)buf, length_message, 0, (SOCKADDR*)sout, sizeof(SOCKADDR_IN)) < 0)
	{
		perror("sendto()");
	}
}

int main()
{
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);
	SOCKET sock;
	SOCKADDR_IN sin;
	SOCKADDR_IN	sout;
	u_long optval;
    MSG					msg;
	char lpSendBuffer[0x100] = {0x0A,0xFF,0xFF,0xF0,0x00,0x04,0x08,0x04,0x00,0x00,0x00,0x01,0x1E,0x02,0x0A,0x57,
								0x49,0x4E,0x52,0x45,0x03,0x0C,0x42,0x00,0x42,0x00,0x42,0x00,0x42,0x00,0x00,0x00,0x02,0x00,
								0x05,0x00};
	DWORD bufferSize = 0x100;

	sin.sin_addr.s_addr	= inet_addr("192.168.15.1");/*0;*/
	sin.sin_family		= AF_INET;
	sin.sin_port		= htons(8889);	/* 0x22B9 */

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	bind(sock, (SOCKADDR *)&sin, sizeof(sin));

	optval = 1;

	if (ioctlsocket(sock, FIONBIO, &optval) == -1)
	{
		printf("[-] ioctlsocket\n");
		return 0;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *)&optval, 4))
	{
		printf("[-] setsockopt\n");
		return 0;
	}

	hPlayerEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	hKillEvent = CreateEvent( NULL, FALSE, FALSE, NULL);

	hReceiveThread = CreateThread(NULL,
                                   0,
                                   ReceiveThread,
                                   (LPVOID)sock,
                                   0,
                                   &idReceiveThread);

	sout.sin_family = AF_INET;
	sout.sin_addr.s_addr = inet_addr("255.255.255.255");
	sout.sin_port = htons(8889);

	craft_message(&sock, &sout);

	char buf[] = {0x02, 0xFE, 0x82, 0x02, 0x41};

	if (sendto(sock, (const char *)buf, 5, 0, (SOCKADDR*)&sout, sizeof(SOCKADDR_IN)) < 0)
	{
		perror("sendto()");
	}
	while (1)
	{
		/*if (sendto(sock, (const char *)buf, 5, 0, (SOCKADDR*)&sout, sizeof(SOCKADDR_IN)) < 0)
		{
			perror("sendto()");
		//exit(errno);
		}*/

    	/*if (PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE))
    	{
            if (!GetMessage(&msg, NULL, 0, 0))
        	{
            	return msg.wParam;
        	}
        	TranslateMessage(&msg);
        	DispatchMessage(&msg);
    	}*/
	}

    WSACleanup();
    return 0;
}