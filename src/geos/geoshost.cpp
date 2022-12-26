#include "dosbox.h"



#ifdef C_GEOSHOST

#include "mem.h"
#include "bios.h"
#include "regs.h"
#include "cpu.h"
#include "callback.h"
#include "inout.h"
#include "pic.h"
#include "hardware.h"
#include "joystick.h"
#include "mouse.h"
#include "setup.h"
#include "serialport.h"
#include "cpu.h"


//#include <android/log.h>
#include "SDL_net.h"
#include "SDL.h"

extern "C" {
#include "tlse.h"
}

struct SocketState {
	bool used;
	bool open;
	bool blocking;
	TCPsocket socket;
	SDLNet_SocketSet socketSet;
	char* recvBuf;
	int recvBufUsed;
	bool receiveDone;
	bool done;
	bool ssl;
	bool sslInitialEnd;

	SocketState()
	        : used(false),
	          recvBuf(NULL),
	          recvBufUsed(0),
	          receiveDone(false),
	          done(false),
	          ssl(false),
	          sslInitialEnd(false)
	{}
};

static const int MaxSockets = 256;

static SocketState NetSockets[MaxSockets];


static Bitu call_geoshost;
static bool G_callbackPending = false;
static bool G_receiveCallbackInit = false;
static uint16_t G_receiveCallbackSeg;
static uint16_t G_receiveCallbackOff;

static RealPt G_retrievalCallback;
static Bitu G_callRetrieval;
static bool G_receiveCallActive = false;

static bool SDLNetInited = false;

enum GeosHostCommands {
	GHC_CHECK = 1,
	GHC_SET_RECEIVE_HANDLE = 2,

	GHC_NETWORKING_BASE = 1000,
	GHC_NC_RESOLVE_ADDR = GHC_NETWORKING_BASE,
	GHC_NC_ALLOC_CONNECTION = GHC_NETWORKING_BASE + 1,
	GHC_NC_CONNECT_REQUEST = GHC_NETWORKING_BASE + 2,
	GHC_NC_SEND_DATA = GHC_NETWORKING_BASE + 3,
	GHC_NC_NEXT_RECV_SIZE = GHC_NETWORKING_BASE + 4,
	GHC_NC_RECV_NEXT = GHC_NETWORKING_BASE + 5,
	GHC_NC_RECV_NEXT_CLOSED = GHC_NETWORKING_BASE + 6,
	GHC_NC_CLOSE = GHC_NETWORKING_BASE + 7,
	GHC_NETWORKING_END = 1199,
	GHC_SSL_BASE = 1200,
	GHC_SSL_SSLV2_CLIENT_METHOD = GHC_SSL_BASE, 
	GHC_SSL_SSLEAY_ADD_SSL_ALGORITHMS = GHC_SSL_BASE + 1, 
	GHC_SSL_SSL_CTX_NEW = GHC_SSL_BASE + 2, 
	GHC_SSL_SSL_CTX_FREE = GHC_SSL_BASE  + 3,
	GHC_SSL_SSL_NEW = GHC_SSL_BASE + 4, 
	GHC_SSL_SSL_FREE = GHC_SSL_BASE +  5, 
	GHC_SSL_SSL_SET_FD = GHC_SSL_BASE + 6, 
	GHC_SSL_SSL_CONNECT = GHC_SSL_BASE + 7, 
	GHC_SSL_SSL_SHUTDOWN = GHC_SSL_BASE + 8, 
	GHC_SSL_SSL_READ = GHC_SSL_BASE + 9, 
	GHC_SSL_SSL_WRITE = GHC_SSL_BASE + 10, 
	GHC_SSL_SSLV23_CLIENT_METHOD = GHC_SSL_BASE + 11, 
	GHC_SSL_SSLV3_CLIENT_METHOD = GHC_SSL_BASE + 12, 
	GHC_SSL_SSL_GET_SSL_METHOD = GHC_SSL_BASE + 13,
	GHC_SSL_SET_CALLBACK = GHC_SSL_BASE + 14
};

enum NetworkingCommands {

	NC_OPEN,
	NC_OPEN_NON_BLOCKING,
	NC_CLOSE,
	NC_SEND,
	NC_RECV,
};



enum GeosHostInterfaces {
	GHI_NETWORKING = 1,
	GHI_SSL = 2 
};

enum GeosHostError {
	GHE_SUCCESS,
	GHE_UNAVAILABLE_INTERFACE
};

static void NetStartReceiver(int handle);


static void NetSetReceiveHandle() {

	uint16_t pseg = SegValue(es);
	uint16_t pofs = reg_bx;

	if ((pseg == 0) && (pofs == 0)) {
		G_receiveCallbackInit = false;
	}
	else {
		G_receiveCallbackInit = true;
		G_receiveCallbackSeg = pseg;
		G_receiveCallbackOff = pofs;
	}

}


// GHC_CHECK
// Parameters:
// al = GHC_CHECK
// ds:si - pointer to null terminated string to connect to. Will get passed to DNS resolver.
// cx - interface
//			GHI_NETWORKING
// Return value:
// ax - error code (0 = success)
// bx - interface command base


static void GeosHostCheckInterface() {

	//__android_log_print(ANDROID_LOG_DEBUG, "GeosHost", "GeosHostCheckInterface");

	switch (reg_cx) {

	case GHI_NETWORKING:
		reg_bx = GHC_NETWORKING_BASE;
		reg_ax = GHE_SUCCESS;
		return;

	case GHI_SSL:
		reg_bx = GHC_SSL_BASE;
		reg_ax = GHE_SUCCESS;
		return;

	default:
		reg_ax = GHE_UNAVAILABLE_INTERFACE;
		return;
	}
}

static void NetResolveAddr() {

	char host[256];

	// TODO check buffer size

	MEM_StrCopy(SegPhys(ds) + reg_si, host, reg_cx); // 1024 toasts the stack
	host[reg_cx] = 0;
	LOG_MSG("NetResolveAddr %s", host);

	IPaddress ipaddress;
	int result = SDLNet_ResolveHost(&ipaddress, host, 1234);
	if (result == 0) {

		reg_dx = (ipaddress.host >> 16) & 0xFFFF;
		reg_ax = ipaddress.host & 0xFFFF;
		reg_flags &= ~FLAG_CF;
		reg_bx = 0;

		LOG_MSG("NetResolveAddr success %x", ipaddress.host);
		return;
	}

	reg_flags |= FLAG_CF;
	reg_bx = 1;
}

static void NetAllocConnection() {

	int socketHandle = -1;

	//__android_log_print(ANDROID_LOG_DEBUG, "GeosHost", "NetAllocConnection");

	for (int i = 1; i < MaxSockets; i++) {
		if (!NetSockets[i].used) {
			socketHandle = i;
			break;
		}
	}

	if (socketHandle < 0) { // no free sockets
		LOG_MSG("ERROR No free sockets");
		reg_ax = -1;
		reg_bx = 0xFFFF;
		return;
	}

	LOG_MSG("Opening socket handle %d\n", socketHandle);
	SocketState &sock = NetSockets[socketHandle];

	sock.used = true;
	sock.open = false;
	sock.blocking = false;

	reg_ax = socketHandle;
	reg_bx = 0;
}

// GHC_NC_CONNECT_REQUEST
// Parameters:
// al = GHC_NC_CONNECT_REQUEST
// ds:si - ip addr to connect to
// cx - interface
// bx - socket handle
// dx - remote port
//			GHI_NETWORKING
// Return value:
// ax - error code (0 = success)
// bx - interface command base

static void NetConnectRequest() {

	LOG_MSG("NetConnectRequest port: %u  sock: %u  addr: %u.%u.%u.%u", reg_dx, reg_bx,
			reg_si & 0xFF,
			(reg_si >> 8) & 0xFF,
			reg_di & 0xFF,
			(reg_di >> 8) & 0xFF
	);

	IPaddress ip;
	ip.host = ((((int)reg_di) << 16) & 0xFFFF0000) | (reg_si & 0xFFFF);
	ip.port = ((reg_dx & 0xFF) << 8) | ((reg_dx >> 8) & 0xFF);

	LOG_MSG("NetConnectRequest Socket handle: %d", reg_bx);

	int socketHandle = reg_bx;
	SocketState &sock = NetSockets[reg_bx];

	if (!(sock.socket = SDLNet_TCP_Open(&ip))) {
		//__android_log_print(ANDROID_LOG_DEBUG, "GeosHost", "TCP Open failed %x\n", ip.host);
		//if (!sock.blocking) {
		//	SDLNet_FreeSocketSet(sock.socketSet);
		//}
		reg_ax = -3;
		LOG_MSG("NetConnectRequest failed");
		return;
	}

	//SDLNet_TCP_AddSocket(sock.socketSet, sock.socket);

	//__android_log_print(ANDROID_LOG_DEBUG, "GeosHost", "Socket opened!\n");

	sock.open = true;

	// connected, for testing start receive thread now
	NetStartReceiver(reg_bx);
	//PIC_ActivateIRQ(5);
}

static int ReceiveThread(void* sockPtr)
{
	LOG_MSG("\nReceive thread started...");

	SocketState* sock = (SocketState*)sockPtr;
	do {
		// wait for data buffer to be supplied by dos request, or cancelled
		if (((SocketState *)sock)->ssl) 
		{
			((SocketState *)sock)->receiveDone = true;
			((SocketState *)sock)->sslInitialEnd = true;

			 return 0;
		}


		if ((sock->recvBufUsed <= 0)
			&& !G_receiveCallActive)
			{

			LOG_MSG("\nReceived get");
			if (sock->recvBuf == NULL) {
				LOG_MSG("\nReceived new buf");
				sock->recvBuf = new char[512];
			}

			int result = SDLNet_TCP_Recv(((SocketState*)sock)->socket, sock->recvBuf, 512);
			LOG_MSG("\nReceived data %d", result);
			if ((!sock->done) && (result > 0)) {

				// pass data to DOS
				sock->recvBufUsed = result;
				G_callbackPending = true;
				//PIC_ActivateIRQ(5);
			}
			else {

				// handle receive error
				LOG_MSG("\nReceived done");
				SDL_Delay(5000);
				((SocketState*)sock)->receiveDone = true;
				((SocketState *)sock)->sslInitialEnd = true;
				return 0;
			}
		}
		else {

			// pending, wait some time and retry
			SDL_Delay(50);
		}


	} while (true);
}


static void NetStartReceiver(int handle) {

	// start receiver thread
	SDL_Thread *thread;
	int         threadReturnValue;

	LOG_MSG("\nSimple SDL_CreateThread test:");

	SocketState &sock = NetSockets[handle];

	// Simply create a thread
	thread = SDL_CreateThread(ReceiveThread, "ReceiveThread", (void *)&sock);

	if (NULL == thread) {
		LOG_MSG("\nSDL_CreateThread failed: %s\n", SDL_GetError());
	}
	else {
		//SDL_WaitThread(thread, &threadReturnValue);
		//printf("\nThread returned value: %d", threadReturnValue);
	}
}


// GHC_NC_SEND_DATA
// Parameters:
// al = GHC_NC_SEND_DATA
// es:si - ip addr to connect to
// cx - data size
// bx - socket handle
// Return value:
// ax - error code (0 = success)
// bx - interface command base

static void NetSendData() {

	//__android_log_print(ANDROID_LOG_DEBUG, "GeosHost", "NetSendData");

	int socketHandle = reg_bx;
	LOG_MSG("NetSendData Socket handle: %d", socketHandle);

	if (socketHandle < 0 || socketHandle >= MaxSockets) {
		reg_ax = -1;
		return;
	}
	SocketState &sock = NetSockets[socketHandle];

	PhysPt dosBuff = SegPhys(es) + reg_si;
	int size = reg_cx;
	LOG_MSG("NetSendData data size: %d", size);

	char *buffer = new char[size + 1];
	for (int i = 0; i < size; i++) {
		buffer[i] = mem_readb(dosBuff + i);
	}
	buffer[size] = 0;
	LOG_MSG("Sending %d bytes: %s\n", size, buffer);


	int sockhandle = reg_bx;
	int sent = SDLNet_TCP_Send(sock.socket, buffer, size);
	if (sent < size) {

		LOG_MSG("NetSendData send failed: %d %d", sent, socketHandle);
	}
	else {

		LOG_MSG("NetSendData send success");
	}
	reg_ax = 0;

	delete[] buffer;
}

static void NetNextRecvSize() {

	//PIC_DeActivateIRQ(11);

	// init, return value with no bug pending
	reg_cx = 0;

	for (int i = 0; i < MaxSockets; i++) {
		
		if (NetSockets[i].used) {
			
			if (!NetSockets[i].done) {
				// check if received data pending
				if (NetSockets[i].recvBufUsed > 0) {

					// return size;
					reg_cx = NetSockets[i].recvBufUsed;
					break;
				}
			}
		}
	}
	if (reg_cx > 0) {
		LOG_MSG("NetNextRecvSize: %d", reg_cx);
	}
}

static void NetClose() {

	LOG_MSG("NetCLOSE: %d", reg_cx);
	SocketState &sock = NetSockets[reg_cx];

	if (sock.used) {

		sock.done = true;
		//SDLNet_TCP_Close(sock.socket);
	}
}


static void NetRecvNextClosed() {

	for (int i = 0; i < MaxSockets; i++) {

		if (NetSockets[i].used) {

			if (!NetSockets[i].done) {
				if (NetSockets[i].receiveDone) {

					NetSockets[i].receiveDone = false;
					reg_cx = i;
					if (reg_cx > 0) {
						LOG_MSG("NetRecvNextClosed: %d", reg_cx);
					}
					return;
				}
			}
		}
	}
	reg_cx = 0;
}

static void NetRecvNext() {

	// find available socket with 
	for (int i = 0; i < MaxSockets; i++) {

		if (NetSockets[i].used) {

			if (!NetSockets[i].done) {
				// check if recived data pending
				LOG_MSG("RECEIVENEXT: %x %x",
				        NetSockets[i].recvBufUsed, reg_cx);

				int buf_size = reg_cx;
				if (NetSockets[i].recvBufUsed == reg_cx) {

					// found buffer of right size
					// copy it
					PhysPt dosBuff = SegPhys(es) + reg_di;
					int size = reg_cx;


					LOG_MSG("RECEIVENEXT: %x %x", SegPhys(es), reg_di);
					for (int i2 = 0; i2 < size; i2++) {
						mem_writeb(dosBuff + i2, NetSockets[i].recvBuf[i2]);
					}

					// mark unused, so continue receiving
					NetSockets[i].recvBufUsed = 0;

					reg_dx = i;
					break;
				}
			}
		}
	}
}


static void SSLV2ClientMethod() {
	LOG_MSG("!!!SSLV2ClientMethod");
}

static void	SSLeayAddSslAlgorithms() {
	LOG_MSG("!!!SSLeayAddSslAlgorithms");
}

#define MAX_HANDLES 20

static void* handles[MAX_HANDLES];

static int AllocHandle(void* ptr) {

	int handle = 0;
	while (handle < MAX_HANDLES) {
	
		if (handles[handle] == NULL) {
		
			handles[handle] = ptr;
			return handle + 1;
		}
		handle++;
	}

	return 0;
}

int SSLSocketRecv(int socket, void *buffer, size_t length, int flags)
{
	LOG_MSG("!!!SSLSocketRecv");
	SocketState &sock = NetSockets[socket];

	while (!sock.sslInitialEnd) {
	};

	if (sock.recvBufUsed) {
		int recvSize = sock.recvBufUsed;
		memcpy(buffer, sock.recvBuf, recvSize);
		sock.recvBufUsed = 0;
		return recvSize;
	}

	return SDLNet_TCP_Recv(sock.socket, buffer, length);
}

int SSLSocketSend(int socket, const void *buffer, size_t length, int flags)
{
	LOG_MSG("!!!SSLSocketSend");
	SocketState &sock = NetSockets[socket];

	sock.ssl = true;

	return SDLNet_TCP_Send(sock.socket, buffer, length);
}


static void SSLContextNew() {
	LOG_MSG("!!!SSLContextNew");

	int method = 0;	// client method
	
	int handle = AllocHandle(tls_create_context(method, TLS_V12));

	SSL_set_io(reinterpret_cast<struct TLSContext *>(handles[handle - 1]),
	           SSLSocketRecv, SSLSocketSend);


	reg_ax = handle & 0xFFFF;
	reg_dx = (handle >> 16) & 0xFFFF;
	LOG_MSG("!!!SSLContextNew context %x", handle);
}

static void SSLContextFree() {
	LOG_MSG("!!!SSLContextFree");
}

static void SSLNew() {
	LOG_MSG("!!!SSLNew");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLNew context %x", context);

	void *result = reinterpret_cast<void *>(context);
	reg_ax = reinterpret_cast<int>(result) & 0xFFFF;
	reg_dx = (reinterpret_cast<int>(result) >> 16) & 0xFFFF;

	int method = 0; // client method

	int handle = AllocHandle(tls_create_context(method, TLS_V13));

	SSL_set_io(reinterpret_cast<struct TLSContext *>(handles[handle - 1]),
	           SSLSocketRecv,
	           SSLSocketSend);

	reg_ax = handle & 0xFFFF;
	reg_dx = (handle >> 16) & 0xFFFF;

	LOG_MSG("!!!SSLNew result %x", result);
}

#define TLS_MALLOC(size) malloc(size)


static void	SSLSetFD() {
	LOG_MSG("!!!SSLSetFD");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLSetFD %x", context);


	LOG_MSG("!!!SSLSetFD2 %x", reg_di);

	struct TLSContext *ctx = reinterpret_cast<struct TLSContext *>(handles[context - 1]);

	int socket = (reg_di & 0xFFFF) /* | (reg_dx << 16) */;
	LOG_MSG("!!!SSLSetFD3 %x", socket);

	int result = SSL_set_fd(ctx, socket);

	reg_ax = result & 0xFFFF;
	reg_dx = (result >> 16) & 0xFFFF;
}

static void SSLConnect() {
	LOG_MSG("!!!SSLConnect");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLSetFD %x", context);

	struct TLSContext *ctx = reinterpret_cast<struct TLSContext *>(
	        handles[context - 1]);

	int result = SSL_connect(ctx);

	reg_ax = result & 0xFFFF;
	reg_dx = (result >> 16) & 0xFFFF;
}

static void SSLShutdown() {
	LOG_MSG("!!!SSLShutdown");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLShutdown %x", context);

	struct TLSContext *ctx = reinterpret_cast<struct TLSContext *>(
	        handles[context - 1]);

	int result = SSL_shutdown(ctx);

	reg_ax = result & 0xFFFF;
	reg_dx = (result >> 16) & 0xFFFF;
}

static void SSLFree()
{
	LOG_MSG("!!!SSLFree");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLFree %x", context);

	struct TLSContext *ctx = reinterpret_cast<struct TLSContext *>(
	        handles[context - 1]);

	SSL_free(ctx);

	handles[context - 1] = NULL;
}


static void SSLRead()
{
	LOG_MSG("!!!SSLRead");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLRead %x", context);

	struct TLSContext *ctx = reinterpret_cast<struct TLSContext *>(
	        handles[context - 1]);

	// CX:DX = DOS addr of buffer
	// DI size
	PhysPt dosBuff = (reg_dx << 4) + reg_cx;
	int size       = reg_di;

	char *buffer = new char[size + 1];

	int result = SSL_read(ctx, buffer, size);
	if (result > 0) {
		for (int i2 = 0; i2 < result; i2++) {
			mem_writeb(dosBuff + i2, buffer[i2]);
		}
	
	}

	delete[] buffer;

	reg_ax = result & 0xFFFF;
	reg_dx = (result >> 16) & 0xFFFF;
}

static void SSLWrite() {
	LOG_MSG("!!!SSLWrite");

	int context = reg_si | (reg_bx << 16);
	LOG_MSG("!!!SSLWrite %x", context);

	struct TLSContext *ctx = reinterpret_cast<struct TLSContext *>(
	        handles[context - 1]);

	// CX:DX = DOS addr of buffer
	// DI size
	PhysPt dosBuff = (reg_dx << 4) + reg_cx;
	int size       = reg_di;
	LOG_MSG("SSL write data size: %d", size);

	char *buffer = new char[size + 1];
	for (int i = 0; i < size; i++) {
		buffer[i] = mem_readb(dosBuff + i);
	}
	buffer[size] = 0;
	LOG_MSG("Sending %d bytes: %s\n", size, buffer);

	int sent = SSL_write(ctx, buffer, size);

	if (sent < size) {
		LOG_MSG("NetSendData send failed: %d", sent);
	} else {
		LOG_MSG("NetSendData send success");
	}
	reg_ax = 0;

	delete[] buffer;


	int result = sent;

	reg_ax = result & 0xFFFF;
	reg_dx = (result >> 16) & 0xFFFF;
}


static void SSLV23ClientMethod() {
	LOG_MSG("!!!SSLV23ClientMethod");
}

static void SSLV3ClientMethod() {
	LOG_MSG("!!!SSLV3ClientMethod");
}

static void SSLGetSslMethod() {
	LOG_MSG("!!!SSLGetSslMethod");
}

static void SSLSetCallback()
{
	LOG_MSG("!!!SSLSetCallback");
}

static Bitu INTB0_Handler(void) {

	if (!SDLNetInited) {
		SDLNet_Init();
		SDLNetInited = true;
	}

	if (reg_ax == GHC_CHECK) {

		GeosHostCheckInterface();
	}
	else if (reg_ax == GHC_SET_RECEIVE_HANDLE) {

		NetSetReceiveHandle();
	}
	else if (reg_ax == GHC_NC_RESOLVE_ADDR) {

		NetResolveAddr();
	}
	else if (reg_ax == GHC_NC_ALLOC_CONNECTION) {

		NetAllocConnection();
	}
	else if (reg_ax == GHC_NC_CONNECT_REQUEST) {

		NetConnectRequest();
	}
	else if (reg_ax == GHC_NC_SEND_DATA) {

		NetSendData();
	}
	else if (reg_ax == GHC_NC_NEXT_RECV_SIZE) {

		NetNextRecvSize();
	}
	else if (reg_ax == GHC_NC_RECV_NEXT) {

		NetRecvNext();
	}
	else if (reg_ax == GHC_NC_RECV_NEXT_CLOSED) {

		NetRecvNextClosed();
	}
	else if (reg_ax == GHC_NC_CLOSE) {

		NetClose();
	} 
	else if (reg_ax == GHC_SSL_SSLV2_CLIENT_METHOD) {

		SSLV2ClientMethod();
	} 
	else if (reg_ax == GHC_SSL_SSLEAY_ADD_SSL_ALGORITHMS) {
	
		SSLeayAddSslAlgorithms();
	} 
	else if (reg_ax == GHC_SSL_SSL_CTX_NEW) {

		SSLContextNew();
	} 
	else if (reg_ax == GHC_SSL_SSL_CTX_NEW) {
	
		SSLContextFree();
	} 
	else if (reg_ax == GHC_SSL_SSL_NEW) {
	
		SSLNew();
	} 
	else if (reg_ax == GHC_SSL_SSL_SET_FD) {
	
		SSLSetFD();
	} 
	else if (reg_ax == GHC_SSL_SSL_CONNECT) {
		
		SSLConnect();
	} 
	else if (reg_ax == GHC_SSL_SSL_SHUTDOWN) {
	
		SSLShutdown();
	} 
	else if (reg_ax == GHC_SSL_SSL_FREE) {
	
		SSLFree();
	} else if (reg_ax == GHC_SSL_SSL_READ) {
	
		SSLRead();
	} 
	else if (reg_ax == GHC_SSL_SSL_WRITE) {
	
		SSLWrite();
	} 
	else if (reg_ax == GHC_SSL_SSLV23_CLIENT_METHOD) {
		
		SSLV23ClientMethod();
	} 
	else if (reg_ax == GHC_SSL_SSLV3_CLIENT_METHOD) {
	
		SSLV3ClientMethod();
	} 
	else if (reg_ax == GHC_SSL_SSL_GET_SSL_METHOD) {
	
		SSLGetSslMethod();
	} 
	else if (reg_ax == GHC_SSL_SET_CALLBACK) {
	
		SSLSetCallback();
	} else if ((reg_ax >= GHC_NETWORKING_BASE) && (reg_ax < GHC_NETWORKING_END)) {


	}

	switch (reg_ax) {
	case GHC_CHECK:
		break;
		/*case NC_OPEN:
		NetOpen(true);
		break;
		case NC_OPEN_NON_BLOCKING:
		NetOpen(false);
		break;
		case NC_CLOSE:
		NetClose();
		break;
		case NC_SEND:
		NetSend();
		break;
		case NC_RECV:
		NetRecv();
		break;*/
	}
	return CBRET_NONE;
}

static Bitu RetrievalCallback_Handler(void) {
	LOG_MSG("RetrievalCallback_Handler");
	G_receiveCallActive = false;
	return CBRET_NONE;
}


static void CALLBACK_Poller(void) {

	if (G_callbackPending) {

		if (G_receiveCallbackInit && !G_receiveCallActive) {
			LOG_MSG("CALLBACK_Poller");

			G_receiveCallActive = true;
			CALLBACK_RunRealFar(G_receiveCallbackSeg, G_receiveCallbackOff);
			G_callbackPending = false;
			G_receiveCallActive = false;
			LOG_MSG("CALLBACK_Poller2");
		}
	}
}


void GeosHost_Init(Section* /*sec*/) {

	memset(NetSockets, 0, sizeof(SocketState)*MaxSockets);

	G_callRetrieval = CALLBACK_Allocate();
	CALLBACK_Setup(G_callRetrieval, &RetrievalCallback_Handler, CB_RETF, "retrieval callback");
	G_retrievalCallback = CALLBACK_RealPointer(G_callRetrieval);


	TIMER_AddTickHandler(CALLBACK_Poller);

	/* Setup the INT B0 vector */
	call_geoshost = CALLBACK_Allocate();
	CALLBACK_Setup(call_geoshost, &INTB0_Handler, CB_IRET, "Geoshost");
	RealSetVec(0xB0, CALLBACK_RealPointer(call_geoshost));
	//__android_log_print(ANDROID_LOG_DEBUG, "GeosHost", "GeosHost_Init");
	LOG_MSG("Geoshost initialized\n");
}


#endif // C_GEOSHOST



