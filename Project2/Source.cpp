
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")
using namespace std;
#define DEFAULT_PACKET_SIZE 40
typedef struct ICMPheader
{
	unsigned char	byType;
	unsigned char	byCode;
	unsigned short	nChecksum;
	unsigned short	nId;
	unsigned short	nSequence;
} ICMPHeader, *PICMPHeader;

void error(const char *msg)
{
	perror(msg);
	exit(0);
}

USHORT calcCheckSum(USHORT *packet) {
	ULONG checksum = 0;
	int size = sizeof(ICMPHeader);
	while (size > 1) {
		checksum += *(packet++);
		size -= sizeof(USHORT);
	}
	if (size) checksum += *(UCHAR *)packet;
	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (USHORT)(checksum);
}

void initPingPacket(PICMPHeader sendHdr, byte seq) {
	sendHdr->byType = 8;
	sendHdr->byCode = 0;
	sendHdr->nChecksum = 0;
	sendHdr->nId = 1;
	sendHdr->nSequence = seq;

	sendHdr->nChecksum = calcCheckSum((USHORT *)sendHdr);
}
int sendPingReq(SOCKET traceSckt, PICMPHeader sendBuf, const struct sockaddr_in *dest)
{
	int sendRes = sendto(traceSckt, (char *)sendBuf, DEFAULT_PACKET_SIZE, 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in));

	if (sendRes == SOCKET_ERROR) return sendRes;
	return 0;
}
int main(int argc, char *argv[])
{


	ICMPheader sendHdr;

	int iResult = 0;
	int err;
	WSADATA wsaData;
	WORD DLLVersion = MAKEWORD(2, 2);
	if (WSAStartup(DLLVersion, &wsaData) != 0) {
		std::cout << "error" << std::endl;
		exit(1);
	}
	//struct addrinfo hints, *result;

	PCTSTR adrtemp = "8.8.8.8";
	UINT destAddr = inet_addr(adrtemp); // getting the IP addr from cmd params
	printf(adrtemp);
	//getaddrinfo(adrtemp, NULL, &hints, &result);


	SOCKADDR_IN dest,source;
	PICMPHeader sendBuf = (PICMPHeader)malloc(DEFAULT_PACKET_SIZE);
	SOCKET sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);
	if (sock == INVALID_SOCKET) {
		wprintf(L"socket failed with error %d\n", WSAGetLastError());
		return 1;
	}

	dest.sin_addr.s_addr = destAddr;
	dest.sin_family = AF_INET;

	int ttl = 0;


	byte seq = 10;
	int rc;
	int len;
	char buffer[1024];
	len = sizeof(sockaddr_in);

	int hops = 30;

	cout << "start listening..." << endl;
	do
	{
		ttl++;
		setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(int));
		initPingPacket(sendBuf,seq);
		sendPingReq(sock, sendBuf, &dest);
		rc = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr *)&source, &len);
		if (rc == -1)
		{
			cout << "Error in recvfrom(): " << WSAGetLastError();
			cin >> err;
		}
		cout << "received from : " << inet_ntoa(dest.sin_addr) << endl;
		seq++;
		hops--;
	} while (hops != 0);



		

			
			
		
		system("pause");


}