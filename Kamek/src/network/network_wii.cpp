/*-------------------------------------------------------------

network_wii.c -- Wii network subsystem

Copyright (C) 2008 bushing

This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any
damages arising from the use of this software.

Permission is granted to anyone to use this software for any
purpose, including commercial applications, and to alter it and
redistribute it freely, subject to the following restrictions:

1.	The origin of this software must not be misrepresented; you
must not claim that you wrote the original software. If you use
this software in a product, an acknowledgment in the product
documentation would be appreciated but is not required.

2.	Altered source versions must be plainly marked as such, and
must not be misrepresented as being the original software.

3.	This notice may not be removed or altered from any source
distribution.

-------------------------------------------------------------*/

// based on https://github.com/MrBean35000vr/netslug-wii/blob/master/src/network_wii.c
// and https://github.com/MrBean35000vr/netslug-wii/blob/master/modules/netslug_main/network_wii.c

/* ^^^^^^^^^^^^^ was altered to work in NSMBW! ^^^^^^^^^^^^^^*/

#include <IOS.h>



u32 errno;

//extern "C" int iosCreateHeap(void* unk, u32 size);
extern "C" int iosFree(s32 heapID, u8* unk);
extern "C" void* __iosAlloc(s32 heapID, u32 size, u32 align);
void* iosAlloc(s32 heapID, u32 size) {
	return __iosAlloc(heapID, size, 32);
}
extern "C" u32 strnlen(const char *string, u32 maxlen);
extern "C" char* strchr(const char * str, int character); 
char *strndup(const char *s, size_t n) {
    // Find the length of the string up to n characters
    size_t len = strnlen(s, n);

    // Allocate memory for the new string, adding 1 for the null terminator
    char *new_str = (char*)AllocFromGameHeap1(len + 1);
    if (!new_str) {
        return NULL; // Allocation failed
    }

    // Copy up to len characters from the original string
    strncpy(new_str, s, len);

    // Null-terminate the new string
    new_str[len] = '\0';

    return new_str;
}


#define MAX_IP_RETRIES		100
#define MAX_INIT_RETRIES	20


void debug_printf(const char *format, ...) {
    if (false) {
        OSReport(format);
    }
}

/*#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <ogc/ipc.h>
#include <ogc/machine/processor.h>
#include <ogcsys.h>*/

#include "network/network.h"
#include "network/ssl.h"

#define SYS_BASE_CACHED					(0x80000000)
#define SYS_BASE_UNCACHED				(0xC0000000)

#define MEM_VIRTUAL_TO_PHYSICAL(x)		(((u32)(x)) & ~SYS_BASE_UNCACHED)									/*!< Cast virtual address to physical address, e.g. 0x8xxxxxxx -> 0x0xxxxxxx */
#define MEM_PHYSICAL_TO_K0(x)			(void*)((u32)(x) + SYS_BASE_CACHED)									/*!< Cast physical address to cached virtual address, e.g. 0x0xxxxxxx -> 0x8xxxxxxx */
#define MEM_PHYSICAL_TO_K1(x)			(void*)((u32)(x) + SYS_BASE_UNCACHED)								/*!< Cast physical address to uncached virtual address, e.g. 0x0xxxxxxx -> 0xCxxxxxxx */
#define MEM_K0_TO_PHYSICAL(x)			(void*)((u32)(x) - SYS_BASE_CACHED)									/*!< Cast physical address to cached virtual address, e.g. 0x0xxxxxxx -> 0x8xxxxxxx */
#define MEM_K1_TO_PHYSICAL(x)			(void*)((u32)(x) - SYS_BASE_UNCACHED)								/*!< Cast physical address to uncached virtual address, e.g. 0x0xxxxxxx -> 0xCxxxxxxx */
#define MEM_K0_TO_K1(x)					(void*)((u32)(x) + (SYS_BASE_UNCACHED - SYS_BASE_CACHED))			/*!< Cast cached virtual address to uncached virtual address, e.g. 0x8xxxxxxx -> 0xCxxxxxxx */
#define MEM_K1_TO_K0(x)					(void*)((u32)(x) - (SYS_BASE_UNCACHED - SYS_BASE_CACHED))			/*!< Cast uncached virtual address to cached virtual address, e.g. 0xCxxxxxxx -> 0x8xxxxxxx */


#define NET_HEAP_SIZE				8192

#define IOS_O_NONBLOCK				(O_NONBLOCK >> 16)

#define IOCTL_NWC24_STARTUP			0x06

#define IOCTL_NCD_SETIFCONFIG3		0x03
#define IOCTL_NCD_SETIFCONFIG4		0x04
#define IOCTL_NCD_GETLINKSTATUS		0x07

#define NET_UNKNOWN_ERROR_OFFSET	-10000

enum {
	IOCTL_SO_ACCEPT	= 1,
	IOCTL_SO_BIND,   
	IOCTL_SO_CLOSE,	
	IOCTL_SO_CONNECT, 
	IOCTL_SO_FCNTL,
	IOCTL_SO_GETPEERNAME, // todo
	IOCTL_SO_GETSOCKNAME, // todo
	IOCTL_SO_GETSOCKOPT,  // todo    8
	IOCTL_SO_SETSOCKOPT,  
	IOCTL_SO_LISTEN,
	IOCTL_SO_POLL,        // todo    b
	IOCTLV_SO_RECVFROM,
	IOCTLV_SO_SENDTO,
	IOCTL_SO_SHUTDOWN,    // todo    e
	IOCTL_SO_SOCKET,
	IOCTL_SO_GETHOSTID,
	IOCTL_SO_GETHOSTBYNAME,
	IOCTL_SO_GETHOSTBYADDR,// todo
	IOCTLV_SO_GETNAMEINFO, // todo   13
	IOCTL_SO_UNK14,        // todo
	IOCTL_SO_INETATON,     // todo
	IOCTL_SO_INETPTON,     // todo
	IOCTL_SO_INETNTOP,     // todo
	IOCTLV_SO_GETADDRINFO, // todo
	IOCTL_SO_SOCKATMARK,   // todo
	IOCTLV_SO_UNK1A,       // todo
	IOCTLV_SO_UNK1B,       // todo
	IOCTLV_SO_GETINTERFACEOPT, // todo
	IOCTLV_SO_SETINTERFACEOPT, // todo
	IOCTL_SO_SETINTERFACE,     // todo
	IOCTL_SO_STARTUP,           // 0x1f
	IOCTL_SO_ICMPSOCKET =	0x30, // todo
	IOCTLV_SO_ICMPPING,         // todo
	IOCTL_SO_ICMPCANCEL,        // todo
	IOCTL_SO_ICMPCLOSE          // todo
};

struct bind_params {
	u32 socket;
	u32 has_name;
	u8 name[28];
};

struct connect_params {
	u32 socket;
	u32 has_addr;
	u8 addr[28];
};

struct sendto_params {
	u32 socket;
	u32 flags;
	u32 has_destaddr;
	u8 destaddr[28];
}; 

struct setsockopt_params {
	u32 socket;
	u32 level;
	u32 optname;
	u32 optlen;
	u8 optval[20];
};

// 0 means we don't know what this error code means
// I sense a pattern here...
static u8 _net_error_code_map[] = {
	0, // 0
	0, 
	0, 
	0,
	0, 
	0, // 5
	EAGAIN, 
	EALREADY,
	EINVAL,
	0,
	0, // 10
	0,
	0,
	0,
	0,
	0, // 15
	0,
	0,
	0,
	0,
	0, // 20
	0,
	0,
	0,
	0,
	0, // 25
	EINPROGRESS,
	0,
	0,
	0,
	EISCONN, // 30
	0,
	0,
	0,
	0,
	0, // 35
	0,
	0,
	0,
	ENETDOWN, //?
	0, // 40
	0,
	0,
	0,
	0,
	0, // 45
	0,
	0,
	0,
	0,
	0, // 50
	0,
	0,
	0,
	0,
	0, // 55
	0,
	0,
	0,
	0,
	0, // 60
};

int tolower(int c) {
	if (c >= 'A' && c <= 'Z') {
		return c + ('a' - 'A');
	} else {
		return c;
	}
}

s32 net_ip_top_fd = -1;
static s32 __net_hid = -1;
static char __attribute__((aligned(32))) __manage_fs[] = "/dev/net/ncd/manage";
static __attribute__((aligned(32))) char __iptop_fs[] = "/dev/net/ip/top";
static __attribute__((aligned(32))) char __kd_fs[] = "/dev/net/kd/request";

static s32 _net_convert_error(s32 ios_retval)
{
//	return ios_retval;
	if (ios_retval >= 0) return ios_retval;
	if (ios_retval < -sizeof(_net_error_code_map)
		|| !_net_error_code_map[-ios_retval])
			return NET_UNKNOWN_ERROR_OFFSET + ios_retval;
	return -_net_error_code_map[-ios_retval];
}

void usleep(u32 seconds) {
	while(seconds > 0) {
		seconds--;
	}
}

static s32 _open_manage_fd(void)
{
	s32 ncd_fd;

	do {
		ncd_fd = _net_convert_error(IOS_Open(__manage_fs, 0));
		if (ncd_fd < 0) usleep(100000);
	} while(ncd_fd == IPC_ENOENT);

	return ncd_fd;
}

s32 NCDGetLinkStatus(void) 
{
	s32 ret, ncd_fd;
	STACK_ALIGN(u8, linkinfo, 0x20, 32);
	STACK_ALIGN(ioctlv, parms, 1, 32);
  
	ncd_fd = _open_manage_fd();
	if (ncd_fd < 0) return ncd_fd;
	
	parms[0].data = linkinfo;
	parms[0].len = 0x20;

	ret = _net_convert_error(IOS_Ioctlv(ncd_fd, IOCTL_NCD_GETLINKSTATUS, 0, 1, parms));
	IOS_Close(ncd_fd);

  	if (ret < 0) debug_printf("NCDGetLinkStatus returned error %d\n", ret);

	return ret;
}

static s32 NWC24iStartupSocket(void)
{
	s32 kd_fd, ret;
	STACK_ALIGN(u8, kd_buf, 0x20, 32);
	
	kd_fd = _net_convert_error(IOS_Open(__kd_fs, 0));
	if (kd_fd < 0) {
		debug_printf("IOS_Open(%s) failed with code %d\n", __kd_fs, kd_fd);
		return kd_fd;
	}
  
	ret = _net_convert_error(IOS_Ioctl(kd_fd, IOCTL_NWC24_STARTUP, NULL, 0, kd_buf, 0x20));
	if (ret < 0) debug_printf("IOS_Ioctl(6)=%d\n", ret);
  	IOS_Close(kd_fd);
  	return ret;
}

u32 net_gethostip(void)
{
	u32 ip_addr=0;
	int retries;

	if (net_ip_top_fd < 0) return 0;
	for (retries=0, ip_addr=0; !ip_addr && retries < MAX_IP_RETRIES; retries++) {
		ip_addr = IOS_Ioctl(net_ip_top_fd, IOCTL_SO_GETHOSTID, 0, 0, 0, 0);
		debug_printf("."); //fflush(stdout);
		if (!ip_addr) usleep(100000);
	}

	return ip_addr;
}

s32 net_init(void)
{
	s32 ret;
	u32 ip_addr = 0;
	u8 *octets = (u8 *) &ip_addr;

	if (net_ip_top_fd >= 0) return 0;
		
	ret = NCDGetLinkStatus();  // this must be called as part of initialization
	if (ret < 0) {
		debug_printf("NCDGetLinkStatus returned %d\n", ret);
		return ret;
	}
	
	net_ip_top_fd = _net_convert_error(IOS_Open(__iptop_fs, 0));
	if (net_ip_top_fd < 0) {
		debug_printf("IOS_Open(/dev/net/ip/top)=%d\n", net_ip_top_fd);
		return net_ip_top_fd;
	}

	ret = NWC24iStartupSocket(); // this must also be called during init
	if (ret < 0) {
		debug_printf("NWC24iStartupSocket returned %d\n", ret);
		goto error;
	}

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_STARTUP, 0, 0, 0, 0));
	if (ret < 0) {
		debug_printf("IOCTL_SO_STARTUP returned %d\n", ret);
		goto error;
	}


	ip_addr=net_gethostip();

	if (!ip_addr) {
		debug_printf("Unable to obtain IP address\n");
		ret = -ETIMEDOUT;
		goto error;
	}

	debug_printf(" %d.%d.%d.%d\n", octets[0], octets[1], octets[2], octets[3]);

	return 0;

error:
	IOS_Close(net_ip_top_fd);
	net_ip_top_fd = -1;
	return ret;	
}


/* Returned value is a static buffer -- this function is not threadsafe! */
struct hostent * net_gethostbyname(char *addrString)
{
	s32 ret, len, i;
	//u8 *params;
	struct hostent *ipData;
	u32 addrOffset;
	static u8 ipBuffer[0x460] ATTRIBUTE_ALIGN(32);

	memset(ipBuffer, 0, 0x460);

	if (net_ip_top_fd < 0) {
		errno = -ENXIO;
		return NULL;
	}

	len = strlen(addrString) + 1;
	u8* params_ = (u8*)AllocFromGameHeap1(len+32);
	u8* params = (u8*)((u32)params_ + (4 - (u32)params_ % 4));

	memcpy(params, addrString, len);

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_GETHOSTBYNAME, params, len, ipBuffer, 0x460));
	FreeFromGameHeap1((void*)params_);

	if (ret < 0) {
		errno = ret;
		return NULL;
	}

	ipData = ((struct hostent*)ipBuffer);
	addrOffset = (u32)MEM_PHYSICAL_TO_K0(ipData->h_name) - ((u32)ipBuffer + 0x10);

	ipData->h_name = (char*)((u32)MEM_PHYSICAL_TO_K0(ipData->h_name) - addrOffset);
	ipData->h_aliases = (char**)((u32)MEM_PHYSICAL_TO_K0(ipData->h_aliases) - addrOffset);

	for (i=0; (i < 0x40) && (ipData->h_aliases[i] != 0); i++) {
		ipData->h_aliases[i] = (char*)((u32)MEM_PHYSICAL_TO_K0(ipData->h_aliases[i]) - addrOffset);
	}

	ipData->h_addr_list = (char**)((u32)MEM_PHYSICAL_TO_K0(ipData->h_addr_list) - addrOffset);

	for (i=0; (i < 0x40) && (ipData->h_addr_list[i] != 0); i++) {
		ipData->h_addr_list[i] = (char*)((u32)MEM_PHYSICAL_TO_K0(ipData->h_addr_list[i]) - addrOffset);
	}


	errno = 0;
	return ipData;
}

s32 net_socket(u32 domain, u32 type, u32 protocol)
{
	s32 ret;
	STACK_ALIGN(u32, params, 3, 32);

	if (net_ip_top_fd < 0) return -ENXIO;
 
	params[0] = domain;
	params[1] = type;
	params[2] = protocol;

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_SOCKET, params, 12, NULL, 0));
	debug_printf("net_socket(%d, %d, %d)=%d\n", domain, type, protocol, ret);
	return ret;		
}

s32 net_shutdown(s32 s, u32 how)
{
	s32 ret;
	STACK_ALIGN(u32, params, 2, 32);

	if (net_ip_top_fd < 0) return -ENXIO;

	params[0] = s;
	params[1] = how;
	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_SHUTDOWN, params, 8, NULL, 0));

	debug_printf("net_shutdown(%d, %d)=%d\n", s, how, ret);
	return ret;
}

s32 net_bind(s32 s, struct sockaddr *name, socklen_t namelen)
{
	s32 ret;
	STACK_ALIGN(struct bind_params,params,1,32);

	if (net_ip_top_fd < 0) return -ENXIO;
	if (name->sa_family != AF_INET) return -EAFNOSUPPORT;

	name->sa_len = 8;

	memset(params, 0, sizeof(struct bind_params));
	params->socket = s;
	params->has_name = 1;
	memcpy(params->name, name, 8);

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_BIND, params, sizeof (struct bind_params), NULL, 0));
	debug_printf("net_bind(%d, %p)=%d\n", s, name, ret);

	return ret;
}

s32 net_listen(s32 s, u32 backlog)
{
	s32 ret;
	STACK_ALIGN(u32, params, 2, 32);

	if (net_ip_top_fd < 0) return -ENXIO;

	params[0] = s;
	params[1] = backlog;

	debug_printf("calling ios_ioctl(%d, %d, %p, %d)\n", net_ip_top_fd, IOCTL_SO_SOCKET, params, 8);

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_LISTEN, params, 8, NULL, 0));
  	debug_printf("net_listen(%d, %d)=%d\n", s, backlog, ret);
	return ret;	
}

s32 net_accept(s32 s, struct sockaddr *addr, socklen_t *addrlen)
{
	s32 ret;
	STACK_ALIGN(u32, _socket, 1, 32);

	debug_printf("net_accept()\n");

	if (net_ip_top_fd < 0) return -ENXIO;

	if (!addr) return -EINVAL;
	addr->sa_len = 8;
	addr->sa_family = AF_INET;

	if (!addrlen) return -EINVAL;

	if (*addrlen < 8) return -ENOMEM;

	*addrlen = 8;

	*_socket = s;
	debug_printf("calling ios_ioctl(%d, %d, %p, %d)\n", net_ip_top_fd, IOCTL_SO_ACCEPT, _socket, 4);
	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_ACCEPT, _socket, 4, addr, *addrlen));

	debug_printf("net_accept(%d, %p)=%d\n", s, addr, ret);
	return ret;
}

s32 net_connect(s32 s, struct sockaddr *addr, socklen_t addrlen)
{
	s32 ret;
	STACK_ALIGN(struct connect_params,params,1,32);
	
	if (net_ip_top_fd < 0) return -ENXIO;
	if (addr->sa_family != AF_INET) return -EAFNOSUPPORT;
	if (addrlen < 8) return -EINVAL;

	addr->sa_len = 8;

	memset(params, 0, sizeof(struct connect_params));
	params->socket = s;
	params->has_addr = 1;
	memcpy(&params->addr, addr, addrlen);

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_CONNECT, params, sizeof(struct connect_params), NULL, 0));
	if (ret < 0) {
    	debug_printf("SOConnect(%d, %p)=%d\n", s, addr, ret);
	}

  	return ret;
}

s32 net_write(s32 s, const void *data, s32 size)
{
    return net_send(s, data, size, 0);
}

s32 net_send(s32 s, const void *data, s32 size, u32 flags)
{
	return net_sendto(s, data, size, flags, NULL, 0);
}

s32 net_sendto(s32 s, const void *data, s32 len, u32 flags, struct sockaddr *to, socklen_t tolen)
{
	s32 ret;
	//u8 * message_buf = NULL;
	STACK_ALIGN(struct sendto_params,params,1,32);
	STACK_ALIGN(ioctlv, parms, 2, 32);

	if (net_ip_top_fd < 0) return -ENXIO;
	if (tolen > 28) return -EOVERFLOW;

	u8* message_buf_ = (u8*)AllocFromGameHeap1(len+32);
	u8* message_buf = (u8*)((u32)message_buf_ + (4 - (u32)message_buf_ % 4));

	debug_printf("net_sendto(%d, %p, %d, %d, %p, %d)\n", s, data, len, flags, to, tolen);

	if (to && to->sa_len != tolen) {
		debug_printf("warning: to->sa_len was %d, setting to %d\n",	to->sa_len, tolen);
		to->sa_len = tolen;
	}
	
	memset(params, 0, sizeof(struct sendto_params));
	memcpy(message_buf, data, len);   // ensure message buf is aligned

	params->socket = s;  
	params->flags = flags;
	if (to) {
		params->has_destaddr = 1;
		memcpy(params->destaddr, to, to->sa_len);		
	} else {
		params->has_destaddr = 0;
	}

	parms[0].data = message_buf;
	parms[0].len = len;
	parms[1].data = params;
	parms[1].len = sizeof(struct sendto_params);

	ret = _net_convert_error(IOS_Ioctlv(net_ip_top_fd, IOCTLV_SO_SENDTO, 2, 0, parms));
	debug_printf("net_send retuned %d\n", ret);

	FreeFromGameHeap1((void*)message_buf_);

	return ret;
}

s32 net_recv(s32 s, void *mem, s32 len, u32 flags)
{
    return net_recvfrom(s, mem, len, flags, NULL, NULL);	
}

s32 net_recvfrom(s32 s, void *mem, s32 len, u32 flags, struct sockaddr *from, socklen_t *fromlen)
{
	s32 ret;
	//u8* message_buf = NULL;
	STACK_ALIGN(u32, params, 2, 32);
	STACK_ALIGN(ioctlv, parms, 3, 32);

	if (net_ip_top_fd < 0) return -ENXIO;
	if (len<=0) return -EINVAL;

	if (fromlen && from->sa_len != *fromlen) {
		debug_printf("warning: from->sa_len was %d, setting to %d\n",from->sa_len, *fromlen);
		from->sa_len = *fromlen;
	}
	
	u8* message_buf_ = (u8*)AllocFromGameHeap1(len+32);
	u8* message_buf = (u8*)((u32)message_buf_ + (4 - (u32)message_buf_ % 4));

	debug_printf("net_recvfrom(%d, '%s', %d, %d, %p, %d)\n", s, (char *)mem, len, flags, from, fromlen?*fromlen:0);

	memset(message_buf, 0, len);
	params[0] = s;
	params[1] = flags;

	parms[0].data = params;
	parms[0].len = 8;
	parms[1].data = message_buf;
	parms[1].len = len;
	parms[2].data = from;
	parms[2].len = (fromlen?*fromlen:0);

	ret = _net_convert_error(IOS_Ioctlv(net_ip_top_fd, IOCTLV_SO_RECVFROM,	1, 2, parms));
	debug_printf("net_recvfrom returned %d\n", ret);

	if (ret > 0) {
		if (ret > len) {
			ret = -EOVERFLOW;
			goto done;
		}

		memcpy(mem, message_buf, ret);
	}

	if (fromlen && from) *fromlen = from->sa_len;
	
done:
	FreeFromGameHeap1((void*)message_buf_);
	return ret;
}

s32 net_read(s32 s, void *mem, s32 len)
{
	return net_recvfrom(s, mem, len, 0, NULL, NULL);
}

s32 net_close(s32 s)
{
	s32 ret;
	STACK_ALIGN(u32, _socket, 1, 32);

	if (net_ip_top_fd < 0) return -ENXIO;

	*_socket = s;
	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_CLOSE, _socket, 4, NULL, 0));

	if (ret < 0) debug_printf("net_close(%d)=%d\n", s, ret);

	return ret;
}

s32 net_select(s32 maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset, struct timeval *timeout)
{
	// not yet implemented
	return -EINVAL;
}

s32 net_setsockopt(s32 s, u32 level, u32 optname, const void *optval, socklen_t optlen)
{
	s32 ret;
	STACK_ALIGN(struct setsockopt_params,params,1,32);

	if (net_ip_top_fd < 0) return -ENXIO;
	if (optlen < 0 || optlen > 20) return -EINVAL;

	memset(params, 0, sizeof(struct setsockopt_params));
	params->socket = s;
	params->level = level;
	params->optname = optname;
	params->optlen = optlen;
	if (optval && optlen) memcpy (params->optval, optval, optlen);

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_SETSOCKOPT, params, sizeof(struct setsockopt_params), NULL, 0));

	debug_printf("net_setsockopt(%d, %u, %u, %p, %d)=%d\n",	s, level, optname, optval, optlen, ret);
	return ret;
}

s32 net_ioctl(s32 s, u32 cmd, void *argp) 
{
	u32 flags;
	u32 *intp = (u32 *)argp;

	if (net_ip_top_fd < 0) return -ENXIO;
	if (!intp) return -EINVAL;

	switch (cmd) {
		case FIONBIO: 
			flags = net_fcntl(s, F_GETFL, 0);
			flags &= ~IOS_O_NONBLOCK;
			if (*intp) flags |= IOS_O_NONBLOCK;
			return net_fcntl(s, F_SETFL, flags);
		default:
			return -EINVAL;
	}
}

s32 net_fcntl(s32 s, u32 cmd, u32 flags)
{
	s32 ret;
	STACK_ALIGN(u32, params, 3, 32);

	if (net_ip_top_fd < 0) return -ENXIO;
	if (cmd != F_GETFL && cmd != F_SETFL) return -EINVAL;
	

	params[0] = s;
	params[1] = cmd;
	params[2] = flags;

	ret = _net_convert_error(IOS_Ioctl(net_ip_top_fd, IOCTL_SO_FCNTL, params, 12, NULL, 0));

	debug_printf("net_fcntl(%d, %d, %x)=%d\n", params[0], params[1], params[2], ret);

	return ret;
}


char *inet_ntoa(struct in_addr addr)
{
  static char str[16];
  u32 s_addr = addr.s_addr;
  char inv[3];
  char *rp;
  u8 *ap;
  u8 rem;
  u8 n;
  u8 i;

  rp = str;
  ap = (u8 *)&s_addr;
  for(n = 0; n < 4; n++) {
    i = 0;
    do {
      rem = *ap % (u8)10;
      *ap /= (u8)10;
      inv[i++] = '0' + rem;
    } while(*ap);
    while(i--)
      *rp++ = inv[i];
    *rp++ = '.';
    ap++;
  }
  *--rp = 0;
  return str;
}

s32 if_config(char *local_ip, char *netmask, char *gateway,int use_dhcp)
{
	s32 i,ret;
	struct in_addr hostip;

	if ( use_dhcp != true ) return -EINVAL;
	
	for(i=0;i<MAX_INIT_RETRIES && (ret=net_init())==-EAGAIN;i++);
	if(ret<0) return ret;

	hostip.s_addr = net_gethostip();
	if ( local_ip!=NULL && hostip.s_addr ) {
		strcpy(local_ip, inet_ntoa(hostip));
	}
	
	return 0;
	
			
}





















//char *defaulturl = "example.com/index.html";
char *defaulturl = "info.cern.ch/hypertext/WWW/TheProject.html";

struct httpresponse{
	float version;
	int response_code;
	char *text;
	char *date;
	char *modified;
	char *server;
	size_t content_length;
	char *content_type;
	char *charset;
};



void printResponse(struct httpresponse response){
	if(response.version && response.response_code && response.text) {
		OSReport("HTTP/%1.1f %d %s\n", response.version, response.response_code, response.text);
	}
	if(response.content_length) {
		OSReport("Length: %d bytes long\n", response.content_length);
	}
	if(response.modified) {
		OSReport("Modified: %s\n",  response.modified);
	}
	if(response.content_type) {
		OSReport("Content Type: %s\n", response.content_type);
	}
	if(response.charset) {
		OSReport("Charset: %s\n", response.charset);
	}
}



/*
int displayInetFile(const char *url){
	struct httpresponse response;
	memset(&response, 0, sizeof(httpresponse));
	char *filepath = strchr(url, '/');
	char *hostname = strndup(url, filepath - url);
	OSReport("hostname is %s and filepath is %s\n", hostname, filepath);
	struct hostent *host = net_gethostbyname(hostname);//gets the host information by domain name
	struct sockaddr_in server;
	s32 socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);//creates a socket
	if(host == NULL){
		OSReport("Oh crap, can't find %s\n", hostname);
		return -1;
	}
	memset(&server, 0, sizeof(server));//clears out the sockaddr_in structure, just saw this in an example and not sure if it's needed
	server.sin_family = AF_INET;//sets the socket type family thing to IPv4
	server.sin_port = htons(80);//uses port 80 for normal HTTP
	memcpy(&server.sin_addr, host->h_addr_list[0], host->h_length);//copies the host address into the sockaddr_in structure
	if(net_connect(socket, (struct sockaddr *)&server, sizeof(server))){
		OSReport("Darn, failed to connect\n");
		return -1;
	}
	else
		OSReport("Successfully connected!\n");

	char *getstring = (char *)AllocFromGameHeap1(strlen("GET  HTTP/1.0\r\nHost: \r\nConnection: close\r\n\r\n")+strlen(filepath) + strlen(hostname));
	sprintf(getstring,"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", filepath, hostname);
	int len = strlen(getstring);
	int sent = net_write(socket, getstring, len);//writes the request to the socket
	OSReport("sent %d of %d bytes\n", sent, len);
	int bufferlen = 1025;//creates a buffer for receiving
	char *buf = (char *)AllocFromGameHeap1(bufferlen);//creates a buffer for receiving
	unsigned int received = 0;
	int read = 0;
	response.text = (char *)AllocFromGameHeap1(sizeof(char)*32);
	
	
	char *line = (char *)AllocFromGameHeap1(bufferlen);
	char *linebegin, *lineend;
	bool dataStarted = false;
	int headerlength = 0;
	while((read = net_read(socket,buf, bufferlen-1))>0){//while we have more data, read it into the buffer and print it out
		buf[read]='\0';//null terminate the amount read, not sure if necessary but better safe than sorry
		linebegin = buf;
		while((lineend = strchr(linebegin, '\n'))!=NULL){
			memset(line, '\0', bufferlen);
			strncpy(line, linebegin, lineend-linebegin);
			if(!dataStarted){
				if(!strncmp(line, "HTTP/", 5)){
					//well whatever
					//sscanf(line, "HTTP/%f %d %s\n", &(response.version), &(response.response_code), response.text);
				}else if(!strncmp(line, "Content-Length", 14)){
					//sscanf(line, "Content-Length: %d", &response.content_length);
					response.content_length = atoi(&line[16]);
				}else if(!strncmp(line, "Content-Type", 12)){
					char *space = strchr(line, ' ');
					if(space) {
						char *sc = strchr(space, ';');
						if(sc) {
							response.content_type = strndup((space+1), sc-space-1);
							char *eq = strchr(sc, '=');
							if(eq) {
								response.charset = strndup((eq + 1), lineend - eq-1);
							}
						}
					}
				}else if(!strncmp(line, "Last-Modified", 13)){
					char *space = strchr(line, ' ');
					response.modified = strndup(space,lineend - space);
				}else if(!strcmp(line, "\r")){
					OSReport("end of http header\n");
					dataStarted = true;
					headerlength = lineend - buf + 1;
				}
			}
			else{
				OSReport("%s\n", line);
			}
			linebegin = lineend + 1;
		}
		received+=read;
	}
	received-=headerlength;
	printResponse(response);
	FreeFromGameHeap1((void*)line);
	if(response.text)
		FreeFromGameHeap1((void*)response.text);
	if(response.content_type)
		FreeFromGameHeap1((void*)response.content_type);
	if(response.charset)
		FreeFromGameHeap1((void*)response.charset);
	if(response.modified)
		FreeFromGameHeap1((void*)response.modified);
	FreeFromGameHeap1((void*)buf);
	FreeFromGameHeap1((void*)getstring);
	FreeFromGameHeap1((void*)hostname);
	
	if(read==0)
		OSReport("Reached EOF\n");
	if(read==-1)
		OSReport("Read error\n");
	net_close(socket);
	if(received == response.content_length){
		OSReport("Received %d bytes, everything seems to be in order.\n\n", received);
	}else{
		OSReport("Received %d of %d bytes, something went wrong.\n\n", received, response.content_length);
		return -1;
	}
	return 0;
}















// create 
u8 cert[] ATTRIBUTE_ALIGN(32) = {0x30, 0x82, 0x03, 0x8E, 0x30, 0x82, 0x02, 0x76, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x03, 0x3A, 0xF1, 0xE6, 0xA7, 0x11, 0xA9, 0xA0, 0xBB, 0x28, 0x64, 0xB1, 0x1D, 0x09, 0xFA, 0xE5, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x61, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x47, 0x32, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x33, 0x30, 0x38, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x38, 0x30, 0x31, 0x31, 0x35, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x61, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x47, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xBB, 0x37, 0xCD, 0x34, 0xDC, 0x7B, 0x6B, 0xC9, 0xB2, 0x68, 0x90, 0xAD, 0x4A, 0x75, 0xFF, 0x46, 0xBA, 0x21, 0x0A, 0x08, 0x8D, 0xF5, 0x19, 0x54, 0xC9, 0xFB, 0x88, 0xDB, 0xF3, 0xAE, 0xF2, 0x3A, 0x89, 0x91, 0x3C, 0x7A, 0xE6, 0xAB, 0x06, 0x1A, 0x6B, 0xCF, 0xAC, 0x2D, 0xE8, 0x5E, 0x09, 0x24, 0x44, 0xBA, 0x62, 0x9A, 0x7E, 0xD6, 0xA3, 0xA8, 0x7E, 0xE0, 0x54, 0x75, 0x20, 0x05, 0xAC, 0x50, 0xB7, 0x9C, 0x63, 0x1A, 0x6C, 0x30, 0xDC, 0xDA, 0x1F, 0x19, 0xB1, 0xD7, 0x1E, 0xDE, 0xFD, 0xD7, 0xE0, 0xCB, 0x94, 0x83, 0x37, 0xAE, 0xEC, 0x1F, 0x43, 0x4E, 0xDD, 0x7B, 0x2C, 0xD2, 0xBD, 0x2E, 0xA5, 0x2F, 0xE4, 0xA9, 0xB8, 0xAD, 0x3A, 0xD4, 0x99, 0xA4, 0xB6, 0x25, 0xE9, 0x9B, 0x6B, 0x00, 0x60, 0x92, 0x60, 0xFF, 0x4F, 0x21, 0x49, 0x18, 0xF7, 0x67, 0x90, 0xAB, 0x61, 0x06, 0x9C, 0x8F, 0xF2, 0xBA, 0xE9, 0xB4, 0xE9, 0x92, 0x32, 0x6B, 0xB5, 0xF3, 0x57, 0xE8, 0x5D, 0x1B, 0xCD, 0x8C, 0x1D, 0xAB, 0x95, 0x04, 0x95, 0x49, 0xF3, 0x35, 0x2D, 0x96, 0xE3, 0x49, 0x6D, 0xDD, 0x77, 0xE3, 0xFB, 0x49, 0x4B, 0xB4, 0xAC, 0x55, 0x07, 0xA9, 0x8F, 0x95, 0xB3, 0xB4, 0x23, 0xBB, 0x4C, 0x6D, 0x45, 0xF0, 0xF6, 0xA9, 0xB2, 0x95, 0x30, 0xB4, 0xFD, 0x4C, 0x55, 0x8C, 0x27, 0x4A, 0x57, 0x14, 0x7C, 0x82, 0x9D, 0xCD, 0x73, 0x92, 0xD3, 0x16, 0x4A, 0x06, 0x0C, 0x8C, 0x50, 0xD1, 0x8F, 0x1E, 0x09, 0xBE, 0x17, 0xA1, 0xE6, 0x21, 0xCA, 0xFD, 0x83, 0xE5, 0x10, 0xBC, 0x83, 0xA5, 0x0A, 0xC4, 0x67, 0x28, 0xF6, 0x73, 0x14, 0x14, 0x3D, 0x46, 0x76, 0xC3, 0x87, 0x14, 0x89, 0x21, 0x34, 0x4D, 0xAF, 0x0F, 0x45, 0x0C, 0xA6, 0x49, 0xA1, 0xBA, 0xBB, 0x9C, 0xC5, 0xB1, 0x33, 0x83, 0x29, 0x85, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x42, 0x30, 0x40, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x4E, 0x22, 0x54, 0x20, 0x18, 0x95, 0xE6, 0xE3, 0x6E, 0xE6, 0x0F, 0xFA, 0xFA, 0xB9, 0x12, 0xED, 0x06, 0x17, 0x8F, 0x39, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x60, 0x67, 0x28, 0x94, 0x6F, 0x0E, 0x48, 0x63, 0xEB, 0x31, 0xDD, 0xEA, 0x67, 0x18, 0xD5, 0x89, 0x7D, 0x3C, 0xC5, 0x8B, 0x4A, 0x7F, 0xE9, 0xBE, 0xDB, 0x2B, 0x17, 0xDF, 0xB0, 0x5F, 0x73, 0x77, 0x2A, 0x32, 0x13, 0x39, 0x81, 0x67, 0x42, 0x84, 0x23, 0xF2, 0x45, 0x67, 0x35, 0xEC, 0x88, 0xBF, 0xF8, 0x8F, 0xB0, 0x61, 0x0C, 0x34, 0xA4, 0xAE, 0x20, 0x4C, 0x84, 0xC6, 0xDB, 0xF8, 0x35, 0xE1, 0x76, 0xD9, 0xDF, 0xA6, 0x42, 0xBB, 0xC7, 0x44, 0x08, 0x86, 0x7F, 0x36, 0x74, 0x24, 0x5A, 0xDA, 0x6C, 0x0D, 0x14, 0x59, 0x35, 0xBD, 0xF2, 0x49, 0xDD, 0xB6, 0x1F, 0xC9, 0xB3, 0x0D, 0x47, 0x2A, 0x3D, 0x99, 0x2F, 0xBB, 0x5C, 0xBB, 0xB5, 0xD4, 0x20, 0xE1, 0x99, 0x5F, 0x53, 0x46, 0x15, 0xDB, 0x68, 0x9B, 0xF0, 0xF3, 0x30, 0xD5, 0x3E, 0x31, 0xE2, 0x8D, 0x84, 0x9E, 0xE3, 0x8A, 0xDA, 0xDA, 0x96, 0x3E, 0x35, 0x13, 0xA5, 0x5F, 0xF0, 0xF9, 0x70, 0x50, 0x70, 0x47, 0x41, 0x11, 0x57, 0x19, 0x4E, 0xC0, 0x8F, 0xAE, 0x06, 0xC4, 0x95, 0x13, 0x17, 0x2F, 0x1B, 0x25, 0x9F, 0x75, 0xF2, 0xB1, 0x8E, 0x99, 0xA1, 0x6F, 0x13, 0xB1, 0x41, 0x71, 0xFE, 0x88, 0x2A, 0xC8, 0x4F, 0x10, 0x20, 0x55, 0xD7, 0xF3, 0x14, 0x45, 0xE5, 0xE0, 0x44, 0xF4, 0xEA, 0x87, 0x95, 0x32, 0x93, 0x0E, 0xFE, 0x53, 0x46, 0xFA, 0x2C, 0x9D, 0xFF, 0x8B, 0x22, 0xB9, 0x4B, 0xD9, 0x09, 0x45, 0xA4, 0xDE, 0xA4, 0xB8, 0x9A, 0x58, 0xDD, 0x1B, 0x7D, 0x52, 0x9F, 0x8E, 0x59, 0x43, 0x88, 0x81, 0xA4, 0x9E, 0x26, 0xD5, 0x6F, 0xAD, 0xDD, 0x0D, 0xC6, 0x37, 0x7D, 0xED, 0x03, 0x92, 0x1B, 0xE5, 0x77, 0x5F, 0x76, 0xEE, 0x3C, 0x8D, 0xC4, 0x5D, 0x56, 0x5B, 0xA2, 0xD9, 0x66, 0x6E, 0xB3, 0x35, 0x37, 0xE5, 0x32, 0xB6};








static s32 ssl_context = -1;


int displaySSLInetFile(const char *url){
	struct httpresponse response;
	memset(&response, 0, sizeof(httpresponse));
	char *filepath = strchr(url, '/');
	char *hostname = strndup(url, filepath - url);
	OSReport("hostname is %s and filepath is %s\n", hostname, filepath);
	struct hostent *host = net_gethostbyname(hostname);//gets the host information by domain name
	struct sockaddr_in server;
	s32 socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);//creates a socket
	if(host == NULL){
		OSReport("Oh crap, can't find %s\n", hostname);
		return -1;
	}
	memset(&server, 0, sizeof(server));//clears out the sockaddr_in structure, just saw this in an example and not sure if it's needed
	server.sin_family = AF_INET;//sets the socket type family thing to IPv4
	server.sin_port = htons(443);//uses port 443 for normal HTTPS
	memcpy(&server.sin_addr, host->h_addr_list[0], host->h_length);//copies the host address into the sockaddr_in structure
	if(net_connect(socket, (struct sockaddr *)&server, sizeof(server))){
		OSReport("Darn, failed to connect\n");
		return -1;
	}
	else
		OSReport("Successfully connected!\n");

	ssl_context = ssl_new((u8*)hostname, 0);
	if (ssl_context < 0)
	{
		OSReport("Error initializing new SSL context (ssl_context = %d).\r\n", ssl_context);
		return ssl_context;
	}

	s32 ret;
	ret = ssl_setbuiltinclientcert(ssl_context, 0);
	if (ret < 0)
	{
		OSReport("Error setting built-in SSL client cert (ret = %d).\r\n", ret);
		ssl_shutdown(ssl_context);
		return ret;
	}

	ret = ssl_setrootca(ssl_context, cert, sizeof(cert));
	if (ret < 0)
	{
		OSReport("Error setting root CA cert (ret = %d).\r\n", ret);
		ssl_shutdown(ssl_context);
		return ret;
	}

	ret = ssl_connect(ssl_context, socket);
	if (ret < 0)
	{
		OSReport("Error connecting to the hostname through SSL (ret = %d).\r\n", ret);
		ssl_shutdown(ssl_context);
		return ret;
	}
	
	ret = ssl_handshake(ssl_context);
	if (ret < 0)
	{
		OSReport("Error doing a handshake to the hostname through SSL (ret = %d).\r\n", ret);
		ssl_shutdown(ssl_context);
		return ret;
	}

	char *getstring = (char *)AllocFromGameHeap1(strlen("GET  HTTP/1.0\r\nHost: \r\nConnection: close\r\n\r\n")+strlen(filepath) + strlen(hostname));
	sprintf(getstring,"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", filepath, hostname);
	int len = strlen(getstring);
	//int sent = net_write(socket, getstring, len);//writes the request to the socket

	ret = ssl_write(ssl_context, getstring, len);
	if (ret < 0)
	{
		OSReport("Error sending HTTPS request (ret = %d).\r\n", ret);
		return ret;
	}

	int bufferlen = 1025;//creates a buffer for receiving
	char *buf = (char *)AllocFromGameHeap1(bufferlen);//creates a buffer for receiving
	unsigned int received = 0;
	int read = 0;
	response.text = (char *)AllocFromGameHeap1(sizeof(char)*32);
	
	
	char *line = (char *)AllocFromGameHeap1(bufferlen);
	char *linebegin, *lineend;
	bool dataStarted = false;
	int headerlength = 0;
	while((read = ssl_read(ssl_context,buf, bufferlen-1))>0){//while we have more data, read it into the buffer and print it out
		buf[read]='\0';//null terminate the amount read, not sure if necessary but better safe than sorry
		linebegin = buf;
		while((lineend = strchr(linebegin, '\n'))!=NULL){
			memset(line, '\0', bufferlen);
			strncpy(line, linebegin, lineend-linebegin);
			if(!dataStarted){
				if(!strncmp(line, "HTTP/", 5)){
					//well whatever
					//sscanf(line, "HTTP/%f %d %s\n", &(response.version), &(response.response_code), response.text);
				}else if(!strncmp(line, "Content-Length", 14)){
					//sscanf(line, "Content-Length: %d", &response.content_length);
					response.content_length = atoi(&line[16]);
				}else if(!strncmp(line, "Content-Type", 12)){
					char *space = strchr(line, ' ');
					if(space) {
						char *sc = strchr(space, ';');
						if(sc) {
							response.content_type = strndup((space+1), sc-space-1);
							char *eq = strchr(sc, '=');
							if(eq) {
								response.charset = strndup((eq + 1), lineend - eq-1);
							}
						}
					}
				}else if(!strncmp(line, "Last-Modified", 13)){
					char *space = strchr(line, ' ');
					response.modified = strndup(space,lineend - space);
				}else if(!strcmp(line, "\r")){
					OSReport("end of http header\n");
					dataStarted = true;
					headerlength = lineend - buf + 1;
				}
			}
			else{
				OSReport("%s\n", line);
			}
			linebegin = lineend + 1;
		}
		received+=read;
	}
	received-=headerlength;
	printResponse(response);
	FreeFromGameHeap1((void*)line);
	if(response.text)
		FreeFromGameHeap1((void*)response.text);
	if(response.content_type)
		FreeFromGameHeap1((void*)response.content_type);
	if(response.charset)
		FreeFromGameHeap1((void*)response.charset);
	if(response.modified)
		FreeFromGameHeap1((void*)response.modified);
	FreeFromGameHeap1((void*)buf);
	FreeFromGameHeap1((void*)getstring);
	FreeFromGameHeap1((void*)hostname);
	
	if(read==0)
		OSReport("Reached EOF\n");
	if(read==-1)
		OSReport("Read error\n");

	ssl_shutdown(ssl_context);
	net_close(socket);
	if(received == response.content_length){
		OSReport("Received %d bytes, everything seems to be in order.\n\n", received);
	}else{
		OSReport("Received %d of %d bytes, something went wrong.\n\n", received, response.content_length);
		return -1;
	}
	return 0;
}*/











// the retuned pointer must at some point be freed using FreeFromGameHeap1(ptr); to prevent memory leaks!
void* downloadFile(const char *url){
	struct httpresponse response;
	memset(&response, 0, sizeof(httpresponse));
	char *filepath = strchr(url, '/');
	char *hostname = strndup(url, filepath - url);
	OSReport("hostname is %s and filepath is %s\n", hostname, filepath);
	struct hostent *host = net_gethostbyname(hostname);/*gets the host information by domain name*/
	struct sockaddr_in server;
	s32 socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);/*creates a socket*/
	if(host == NULL){
		OSReport("Oh crap, can't find %s\n", hostname);
		return NULL;
	}
	memset(&server, 0, sizeof(server));/*clears out the sockaddr_in structure, just saw this in an example and not sure if it's needed*/
	server.sin_family = AF_INET;/*sets the socket type family thing to IPv4*/
	server.sin_port = htons(80);/*uses port 80 for normal HTTP*/
	memcpy(&server.sin_addr, host->h_addr_list[0], host->h_length);/*copies the host address into the sockaddr_in structure*/
	if(net_connect(socket, (struct sockaddr *)&server, sizeof(server))){
		OSReport("Darn, failed to connect\n");
		return NULL;
	}
	else
		OSReport("Successfully connected!\n");

	char *getstring = (char *)AllocFromGameHeap1(strlen("GET  HTTP/1.0\r\nHost: \r\nConnection: close\r\n\r\n")+strlen(filepath) + strlen(hostname));
	sprintf(getstring,"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", filepath, hostname);
	int len = strlen(getstring);
	int sent = net_write(socket, getstring, len);/*writes the request to the socket*/
	OSReport("sent %d of %d bytes\n", sent, len);
	int bufferlen = 1025;/*creates a buffer for receiving*/
	char *buf = (char *)AllocFromGameHeap1(bufferlen);/*creates a buffer for receiving*/
	unsigned int received = 0;
	int read = 0;
	response.text = NULL;

	u32 fileSize = 0;

	char *line = (char *)AllocFromGameHeap1(bufferlen);
	char *linebegin, *lineend;
	bool dataStarted = false;
	int headerlength = 0;
	while((read = net_read(socket, buf, bufferlen-1))>0){/*while we have more data, read it into the buffer and print it out*/
		buf[read]='\0';/*null terminate the amount read, not sure if necessary but better safe than sorry*/
		if(!dataStarted){
			linebegin = buf;
			while((lineend = strchr(linebegin, '\n'))!=NULL){
				memset(line, '\0', bufferlen);
				strncpy(line, linebegin, lineend-linebegin);
				if(!strncmp(line, "HTTP/", 5)){
					//well whatever
					//sscanf(line, "HTTP/%f %d %s\n", &(response.version), &(response.response_code), response.text);
				}else if(!strncmp(line, "Content-Length", 14)){
					//sscanf(line, "Content-Length: %d", &response.content_length);
					response.content_length = atoi(&line[16]);
					response.text = (char *)AllocFromGameHeap1(response.content_length);
					OSReport("Content-Length: %d, text: %p\n", response.content_length, response.text);
				}else if(!strncmp(line, "Content-Type", 12)){
					char *space = strchr(line, ' ');
					if(space) {
						char *sc = strchr(space, ';');
						if(sc) {
							response.content_type = strndup((space+1), sc-space-1);
							char *eq = strchr(sc, '=');
							if(eq) {
								response.charset = strndup((eq + 1), lineend - eq-1);
							}
						}
					}
				}else if(!strncmp(line, "Last-Modified", 13)){
					char *space = strchr(line, ' ');
					response.modified = strndup(space,lineend - space);
				}else if(!strcmp(line, "\r")){
					OSReport("end of http header\n");
					dataStarted = true;
					headerlength = lineend - buf + 1;
				}
				linebegin = lineend + 1;
			}
			if(response.text) {
				memcpy(response.text, linebegin, bufferlen-(linebegin-buf));
				fileSize += bufferlen-(linebegin-buf)-1; // -1 because lines have an appended 0 byte
				//OSReport("%s\n", line);
			}

		} else {
			if(response.text) {
				memcpy(&response.text[fileSize], buf, read);
				fileSize += read;
				//OSReport("%s\n", line);
			}
		}
		received+=read;
	}
	received-=headerlength;
	printResponse(response);
	FreeFromGameHeap1((void*)line);
	if(response.content_type)
		FreeFromGameHeap1((void*)response.content_type);
	if(response.charset)
		FreeFromGameHeap1((void*)response.charset);
	if(response.modified)
		FreeFromGameHeap1((void*)response.modified);
	FreeFromGameHeap1((void*)buf);
	FreeFromGameHeap1((void*)getstring);
	FreeFromGameHeap1((void*)hostname);
	
	if(read==0)
		OSReport("Reached EOF\n");
	if(read==-1)
		OSReport("Read error\n");
	net_close(socket);
	if(received == response.content_length){
		OSReport("Received %d bytes, everything seems to be in order.\n\n", received);
	}else{
		OSReport("Received %d of %d bytes, something went wrong.\n\n", received, response.content_length);
		return NULL;
	}

	return response.text;
}



bool init(){
	OSReport("Wii HTTP Test\n\nAttempting to initialize network\n");
	//tries to initialize network
	char myip[16];
	if(if_config(myip, NULL, NULL, true)){
		OSReport("Failed to initialize network. Goodbye.\n");
		return false;
	}
	OSReport("Network initialized. Wii's IP is %s.\n", myip);
	return true;
}

void testNetwork() {
	if(init()) {
		void* ptr = downloadFile("nin0.me/New-Super-Mario-Lost-Worlds/Models/supergem.arc");
		OSReport("\n\n\n\n\n\nDownloaded supergem.arc to: %p\n\n\n\n\n\n", ptr);
		FreeFromGameHeap1(ptr);
	}
}