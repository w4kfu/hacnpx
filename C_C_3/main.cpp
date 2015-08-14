#include <stdio.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#include "utils.h"

HANDLE              hReceiveThread		= NULL;	// Recieve flag
DWORD               idReceiveThread		= 0;	// The id of the recieve thread

DWORD	Compute_CRC(BYTE *Buf, DWORD dwLen)
{
	DWORD	dwCrc;
	DWORD	dwCount;

	dwCrc = 0;
	for (dwCount = 0; dwCount < dwLen; dwCount++)
	{
		dwCrc = (dwCrc >> 31) + Buf[dwCount] + 2 * dwCrc;
	}
	return dwCrc;
}

VOID	Crypt_Message(BYTE *Buf, DWORD dwLen)
{
	DWORD dwKey;
	DWORD dwCount;

	dwKey = 0x38D9B7D4;
	for (dwCount = 0; dwCount < dwLen; dwCount += 4)
	{
		*(DWORD*)(Buf + dwCount) = htonl(dwKey ^ *(DWORD*)(Buf + dwCount));
		dwKey -= 0x7F39C50E;
	}
}

VOID	Decrypt_Message(BYTE *Buf, DWORD dwLen)
{
	DWORD dwKey;
	DWORD dwCount;

	dwKey = 0x38D9B7D4;
	for (dwCount = 0; dwCount < dwLen; dwCount += 4)
	{
		*(DWORD*)(Buf + dwCount) = dwKey ^ htonl(*(DWORD*)(Buf + dwCount));
		dwKey -= 0x7F39C50E;
	}
}

DWORD WINAPI ReceiveThread(LPVOID lpParameter)
{
    //HANDLE      eventHandles[2];
    //eventHandles[0] = hPlayerEvent;
    //eventHandles[1] = hKillEvent;
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
			Decrypt_Message(buf, size);
			if (Compute_CRC(buf + 4, size - 4) != *(DWORD*)(buf))
			{
				hex_dump(buf, size);
				printf("CRC Mismatch %X\n", Compute_CRC(buf + 4, size - 4));
				system("pause");
			}
			else
			{
				hex_dump(buf, size);
				printf("\n ----- \n");
			}
		}
	}

}

VOID send_message(SOCKET *sock)
{


}

int main()
{
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);
	SOCKET sock;
	SOCKADDR_IN sin;
	SOCKADDR_IN	sout;
	u_long optval;

	sin.sin_addr.s_addr	= inet_addr("192.168.15.1");/*0;*/
	sin.sin_family		= AF_INET;
	sin.sin_port		= htons(0xA21F96);

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
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

	hReceiveThread = CreateThread(NULL,
                                   0,
                                   ReceiveThread,
                                   (LPVOID)sock,
                                   0,
                                   &idReceiveThread);

	sout.sin_family = AF_INET;
	sout.sin_addr.s_addr = inet_addr("255.255.255.255");
	sout.sin_port = htons(0xA21F96);

	//BYTE buf[0x200];

	DWORD i;
	DWORD j;

	/*for (j = 0; j <= 0x20; j++)
	{
	for (i = 0; i <= 0xFF; i++)
	{*/
		/*memset(buf, i, sizeof (buf));
		*(DWORD*)(buf + 4) = 0x2;
		*(DWORD*)(buf + 0x44) = 0x0;
		*(DWORD*)(buf) = Compute_CRC(buf + 4, sizeof (buf) - 4);
		Crypt_Message(buf, sizeof (buf));
		if (sendto(sock, (const char *)buf, sizeof (buf), 0, (SOCKADDR*)&sout, sizeof(SOCKADDR_IN)) < 0)
		{
			perror("sendto()");
		}

		Sleep(80);

		memset(buf, i, sizeof (buf));
		*(DWORD*)(buf + 4) = j;
		*(DWORD*)(buf + 0x44) = 0x0;
		*(DWORD*)(buf) = Compute_CRC(buf + 4, sizeof (buf) - 4);
		Crypt_Message(buf, sizeof (buf));
		if (sendto(sock, (const char *)buf, sizeof (buf), 0, (SOCKADDR*)&sout, sizeof(SOCKADDR_IN)) < 0)
		{
			perror("sendto()");
		}
			}
	}*/
	BYTE buf[] = {0xCF, 0xD1, 0xED, 0x82, 0x0, 0x00, 0x00, 0x00, 0x77, 0x00, 0x34, 0x00, 0x6B, 0x00, 0x66, 0x00,
					0x75, 0x00, 0x5B, 0x00, 0x5D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00,
					0x57, 0x00, 0x43, 0x00, 0x30, 0x00, 0x41, 0x00, 0x38, 0x00, 0x30, 0x00, 0x46, 0x00, 0x38, 0x00,
					0x30, 0x00, 0x39, 0x00, 0x45, 0x00, 0x32, 0x00, 0x39, 0x00, 0x32, 0x00, 0x37, 0x00, 0x35, 0x00,
					0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6D, 0x6D, 0x61, 0x70, 0x5F, 0x6D, 0x70, 0x5F, 0x32, 0x5F,
					0x73, 0x69, 0x6D, 0x6F, 0x6E, 0x00, 0x02, 0x81, 0xA1, 0x83, 0x57, 0xBF, 0x00, 0x00, 0x00, 0x00,
					0x9E, 0x29, 0x27, 0x50, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x27, 0x10,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x2F, 0x33, 0x43, 0x4E, 0x43, 0x33,
					0x00, 0x00, 0x00, 0x50, 0x77, 0x00, 0x34, 0x00, 0x6B, 0x00, 0x66, 0x00, 0x75, 0x00, 0x5B, 0x00,
					0x5D, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x0F, 0x80, 0x1F, 0x96,
					0x03, 0x01, 0xFF, 0xFF, 0x00, 0x01, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	BYTE buf_vuln[476];
	BYTE save;
	DWORD z;

	/*for (z = 0; z < 0x14; z++)
	{
		for (i = 8; i < 0xd0; i++)
		{
			for (j = 0; j < 0xd0 - i; j++)
			{
				memcpy(buf_vuln, buf, 476);
				memset(&buf_vuln[i], 0xFF, j);
				*(DWORD*)(buf_vuln + 4) = z;
				*(DWORD*)(buf_vuln) = Compute_CRC(buf_vuln + 4, sizeof (buf_vuln) - 4);	
				Crypt_Message(buf_vuln, sizeof (buf_vuln));
				//Sleep(300);
				if (sendto(sock, (const char *)buf_vuln, sizeof (buf_vuln), 0, (SOCKADDR*)&sout, sizeof(SOCKADDR_IN)) < 0)
				{
					perror("sendto()");
				}
			}
		}
	}*/


		/*for (j = 0; j < 0xFF; j++)
		{
			save = buf[i];
			buf[i] = j;

			Sleep(100);

			*(DWORD*)(buf) = Compute_CRC(buf + 4, sizeof (buf) - 4);	
			Crypt_Message(buf, sizeof (buf));
			if (sendto(sock, (const char *)buf, sizeof (buf), 0, (SOCKADDR*)&sout, sizeof(SOCKADDR_IN)) < 0)
			{
				perror("sendto()");
			}
			buf[i] = save;

		}*/

	while (1)
	{

	}

    WSACleanup();
	return 0;
}