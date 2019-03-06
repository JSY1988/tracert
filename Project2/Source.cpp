
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
typedef struct IPHeader {
	BYTE ver_n_len;
	BYTE srv_type;
	USHORT total_len;
	USHORT pack_id;
	USHORT flags : 3;
	USHORT offset : 13;
	BYTE TTL;
	BYTE proto;
	USHORT checksum;
	UINT source_ip;
	UINT dest_ip;
} IPHeader, *PIPHeader;
typedef struct _tag_PacketDetails {
	struct sockaddr_in *source;
	DWORD ping;
} PacketDetails, *PPacketDetails;

USHORT calcCheckSum(USHORT *packet) {
	ULONG checksum = 0;
	int size = 40;
	while (size > 1) {
		checksum += *(packet++);
		size -= sizeof(USHORT);
	}
	if (size) checksum += *(UCHAR *)packet;

	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (USHORT)(~checksum);
}

void initPingPacket(PICMPHeader sendHdr, byte seq) {
	sendHdr->byType = 8;
	sendHdr->byCode = 0;
	sendHdr->nChecksum = 0;
	sendHdr->nId = 1;
	sendHdr->nSequence = seq;

	sendHdr->nChecksum = calcCheckSum((USHORT *)sendHdr);
}
int sendPingReq(SOCKET sock, PICMPHeader sendBuf, const struct sockaddr_in *dest)
{
	int Res = sendto(sock, (char *)sendBuf, DEFAULT_PACKET_SIZE, 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in));

	if (Res == SOCKET_ERROR) 
		return Res;
	return 0;
}
int decodeReply(PIPHeader ipHdr, struct sockaddr_in *source, USHORT seq, ULONG sendingTime, PPacketDetails decodeResult)
{
	DWORD arrivalTime = GetTickCount();

	unsigned short ipHdrLen = (ipHdr->ver_n_len & 0x0F) * 4;
	PICMPHeader icmpHdr = (PICMPHeader)((char *)ipHdr + ipHdrLen);

	if (icmpHdr->byType == 11) {//ttl Expired
		PIPHeader requestIPHdr = (PIPHeader)((char *)icmpHdr + 8);
		unsigned short requestIPHdrLen = (requestIPHdr->ver_n_len & 0x0F) * 4;

		PICMPHeader requestICMPHdr = (PICMPHeader)((char *)requestIPHdr + requestIPHdrLen);

		if  (requestICMPHdr->nSequence == seq) {
			decodeResult->source = source;
			decodeResult->ping = arrivalTime - sendingTime;
			return 1;
		}
	}

	if (icmpHdr->byType == 0) {//last hop 
		if  (icmpHdr->nSequence == seq) {
			decodeResult->source = source;
			decodeResult->ping = arrivalTime - sendingTime;
			return 2;
		}
	}

	return -1;
}
int recvPing(SOCKET sock, PIPHeader recvBuf, struct sockaddr_in *source)
{
	int srcLen = sizeof(struct sockaddr_in);

	fd_set singleSocket;
	singleSocket.fd_count = 1;
	singleSocket.fd_array[0] = sock;
	struct timeval timeToWait = { 2, 0 };

	int selectRes;
	if ((selectRes = select(0, &singleSocket, NULL, NULL, &timeToWait)) == 0) return 0; // time-out
	if (selectRes == SOCKET_ERROR) return 1;

	return recvfrom(sock, (char *)recvBuf, 1024, 0, (struct sockaddr *)source, &srcLen);
}
void printPackInfo(PPacketDetails details, BOOL printIP)
{
	printf("%6d", details->ping);

	if (printIP) {
		char *srcAddr = inet_ntoa(details->source->sin_addr);
		if (srcAddr != NULL) {
			printf("\t%s", srcAddr);
		}
	}
}

int main(int argc, char *argv[])
{

	setlocale(LC_ALL, "Russian");
	ICMPheader sendHdr;

	int iResult = 0;
	int err;
	WSADATA wsaData;
	WORD DLLVersion = MAKEWORD(2, 2);
	if (WSAStartup(DLLVersion, &wsaData) != 0) {
		std::cout << "error" << std::endl;
		exit(1);
	}

	PCTSTR adrtemp = "216.58.207.46";
	UINT destAddr = inet_addr(adrtemp); // getting the IP addr from cmd params

	SOCKADDR_IN dest,source;
	PICMPHeader sendBuf = (PICMPHeader)malloc(DEFAULT_PACKET_SIZE);
	PIPHeader recvBuf = (PIPHeader)malloc(1024);
	SOCKET sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);
	if (sock == INVALID_SOCKET) {
		wprintf(L"socket failed with error %d\n", WSAGetLastError());
		return 1;
	}
	dest.sin_addr.s_addr = destAddr;
	dest.sin_family = AF_INET;
	PacketDetails details;
	int ttl = 0;
	int number = 1;
	byte seq = 1;
	ULONG sendingTime;

	int hops = 30;
	BOOL traceEnd = FALSE, error = FALSE, printIP;
	cout << "Трассировка маршрута к " << adrtemp <<  endl;
	cout << "с максимальным числом прыжков 30:" << endl;
	do
	{
		ttl++;
		setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(int));

		printIP = FALSE;
		printf("%3d.", number++);
		
		
		for (int i = 1; i <= 3; i++) {
			if (i == 3) printIP = TRUE;
			initPingPacket(sendBuf, seq);
			sendingTime = GetTickCount();
			sendPingReq(sock, sendBuf, &dest);
			int recvRes = 2;
			int decodeRes = -1; // error;

			recvRes = recvPing(sock, recvBuf, &source);
			if (recvRes == 0) {
				printf(" *");
			}
			else {
				decodeRes = decodeReply(recvBuf, &source, seq, sendingTime, &details);
			}
			
			if (recvRes > 1) {
				if (decodeRes == -1) {
					printf("*");
				}
				else {
					if (decodeRes == 2) {
						traceEnd = TRUE;
					}
					printPackInfo(&details, printIP);
				}
			}
		}
		printf("\n");
	} while (!traceEnd && (ttl != hops));
		system("pause");
}