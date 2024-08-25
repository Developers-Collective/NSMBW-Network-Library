#ifndef __NETWORK_H__
#define __NETWORK_H__

/*#include <gctypes.h>
#include <sys/time.h>
#include <sys/types.h>*/

#define HW_IPC_PPCBASE		  0xCD000000
#define HW_IPC_PPCMSG		  (*(vu32*)HW_IPC_PPCBASE)
#define HW_IPC_PPCCTRL		  (*(vu32*)(HW_IPC_PPCBASE + 4))
#define HW_IPC_PPC_SEND		  1
#define HW_IPC_PPC_MSG_ACK	  2
#define HW_IPC_PPC_CTRL_ACK	  4
#define HW_IPC_PPC_CTRL_REGS (HW_IPC_PPC_MSG_ACK|HW_IPC_PPC_CTRL_ACK)
#define IPC_HEAP			 -1

#define IPC_OPEN_NONE		  0
#define IPC_OPEN_READ		  1
#define IPC_OPEN_WRITE		  2
#define IPC_OPEN_RW			  (IPC_OPEN_READ|IPC_OPEN_WRITE)

#define IPC_MAXPATH_LEN		 64

#define IPC_OK				  0
#define IPC_EINVAL			 -4
#define IPC_ENOHEAP			 -5
#define IPC_ENOENT			 -6
#define IPC_EQUEUEFULL		 -8
#define IPC_ENOMEM			-22

#define IOS_MAXFMT_PARAMS		32

static s32 _ipc_hid = -1;
static s32 _ipc_mailboxack = 1;
static u32 _ipc_relnchFl = 0;
static u32 _ipc_initialized = 0;
static u32 _ipc_clntinitialized = 0;
static u64 _ipc_spuriousresponsecnt = 0;
static struct _ipcreq *_ipc_relnchRpc = NULL;

struct _ioctlvfmt_bufent
{
	void *ipc_buf;
	void *io_buf;
	s32 copy_len;
};

struct _ioctlvfmt_cbdata
{
	ipccallback user_cb;
	void *user_data;
	s32 num_bufs;
	u32 hId;
	struct _ioctlvfmt_bufent *bufs;
};


#define	EPERM 1		/* Not owner */
#define	ENOENT 2	/* No such file or directory */
#define	ESRCH 3		/* No such process */
#define	EINTR 4		/* Interrupted system call */
#define	EIO 5		/* I/O error */
#define	ENXIO 6		/* No such device or address */
#define	E2BIG 7		/* Arg list too long */
#define	ENOEXEC 8	/* Exec format error */
#define	EBADF 9		/* Bad file number */
#define	ECHILD 10	/* No children */
#define	EAGAIN 11	/* No more processes */
#define	ENOMEM 12	/* Not enough space */
#define	EACCES 13	/* Permission denied */
#define	EFAULT 14	/* Bad address */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define	ENOTBLK 15	/* Block device required */
#endif
#define	EBUSY 16	/* Device or resource busy */
#define	EEXIST 17	/* File exists */
#define	EXDEV 18	/* Cross-device link */
#define	ENODEV 19	/* No such device */
#define	ENOTDIR 20	/* Not a directory */
#define	EISDIR 21	/* Is a directory */
#define	EINVAL 22	/* Invalid argument */
#define	ENFILE 23	/* Too many open files in system */
#define	EMFILE 24	/* File descriptor value too large */
#define	ENOTTY 25	/* Not a character device */
#define	ETXTBSY 26	/* Text file busy */
#define	EFBIG 27	/* File too large */
#define	ENOSPC 28	/* No space left on device */
#define	ESPIPE 29	/* Illegal seek */
#define	EROFS 30	/* Read-only file system */
#define	EMLINK 31	/* Too many links */
#define	EPIPE 32	/* Broken pipe */
#define	EDOM 33		/* Mathematics argument out of domain of function */
#define	ERANGE 34	/* Result too large */
#define	ENOMSG 35	/* No message of desired type */
#define	EIDRM 36	/* Identifier removed */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define	ECHRNG 37	/* Channel number out of range */
#define	EL2NSYNC 38	/* Level 2 not synchronized */
#define	EL3HLT 39	/* Level 3 halted */
#define	EL3RST 40	/* Level 3 reset */
#define	ELNRNG 41	/* Link number out of range */
#define	EUNATCH 42	/* Protocol driver not attached */
#define	ENOCSI 43	/* No CSI structure available */
#define	EL2HLT 44	/* Level 2 halted */
#endif
#define	EDEADLK 45	/* Deadlock */
#define	ENOLCK 46	/* No lock */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define EBADE 50	/* Invalid exchange */
#define EBADR 51	/* Invalid request descriptor */
#define EXFULL 52	/* Exchange full */
#define ENOANO 53	/* No anode */
#define EBADRQC 54	/* Invalid request code */
#define EBADSLT 55	/* Invalid slot */
#define EDEADLOCK 56	/* File locking deadlock error */
#define EBFONT 57	/* Bad font file fmt */
#endif
#define ENOSTR 60	/* Not a stream */
#define ENODATA 61	/* No data (for no delay io) */
#define ETIME 62	/* Stream ioctl timeout */
#define ENOSR 63	/* No stream resources */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define ENONET 64	/* Machine is not on the network */
#define ENOPKG 65	/* Package not installed */
#define EREMOTE 66	/* The object is remote */
#endif
#define ENOLINK 67	/* Virtual circuit is gone */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define EADV 68		/* Advertise error */
#define ESRMNT 69	/* Srmount error */
#define	ECOMM 70	/* Communication error on send */
#endif
#define EPROTO 71	/* Protocol error */
#define	EMULTIHOP 74	/* Multihop attempted */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define	ELBIN 75	/* Inode is remote (not really error) */
#define	EDOTDOT 76	/* Cross mount point (not really error) */
#endif
#define EBADMSG 77	/* Bad message */
#define EFTYPE 79	/* Inappropriate file type or format */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define ENOTUNIQ 80	/* Given log. name not unique */
#define EBADFD 81	/* f.d. invalid for this operation */
#define EREMCHG 82	/* Remote address changed */
#define ELIBACC 83	/* Can't access a needed shared lib */
#define ELIBBAD 84	/* Accessing a corrupted shared lib */
#define ELIBSCN 85	/* .lib section in a.out corrupted */
#define ELIBMAX 86	/* Attempting to link in too many libs */
#define ELIBEXEC 87	/* Attempting to exec a shared library */
#endif
#define ENOSYS 88	/* Function not implemented */
#ifdef __CYGWIN__
#define ENMFILE 89      /* No more files */
#endif
#define ENOTEMPTY 90	/* Directory not empty */
#define ENAMETOOLONG 91	/* File or path name too long */
#define ELOOP 92	/* Too many symbolic links */
#define EOPNOTSUPP 95	/* Operation not supported on socket */
#define EPFNOSUPPORT 96 /* Protocol family not supported */
#define ECONNRESET 104  /* Connection reset by peer */
#define ENOBUFS 105	/* No buffer space available */
#define EAFNOSUPPORT 106 /* Address family not supported by protocol family */
#define EPROTOTYPE 107	/* Protocol wrong type for socket */
#define ENOTSOCK 108	/* Socket operation on non-socket */
#define ENOPROTOOPT 109	/* Protocol not available */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define ESHUTDOWN 110	/* Can't send after socket shutdown */
#endif
#define ECONNREFUSED 111	/* Connection refused */
#define EADDRINUSE 112		/* Address already in use */
#define ECONNABORTED 113	/* Software caused connection abort */
#define ENETUNREACH 114		/* Network is unreachable */
#define ENETDOWN 115		/* Network interface is not configured */
#define ETIMEDOUT 116		/* Connection timed out */
#define EHOSTDOWN 117		/* Host is down */
#define EHOSTUNREACH 118	/* Host is unreachable */
#define EINPROGRESS 119		/* Connection already in progress */
#define EALREADY 120		/* Socket already connected */
#define EDESTADDRREQ 121	/* Destination address required */
#define EMSGSIZE 122		/* Message too long */
#define EPROTONOSUPPORT 123	/* Unknown protocol */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define ESOCKTNOSUPPORT 124	/* Socket type not supported */
#endif
#define EADDRNOTAVAIL 125	/* Address not available */
#define ENETRESET 126		/* Connection aborted by network */
#define EISCONN 127		/* Socket is already connected */
#define ENOTCONN 128		/* Socket is not connected */
#define ETOOMANYREFS 129
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define EPROCLIM 130
#define EUSERS 131
#endif
#define EDQUOT 132
#define ESTALE 133
#define ENOTSUP 134		/* Not supported */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define ENOMEDIUM 135   /* No medium (in tape drive) */
#endif
#ifdef __CYGWIN__
#define ENOSHARE 136    /* No such host or network path */
#define ECASECLASH 137  /* Filename exists with different case */
#endif
#define EILSEQ 138		/* Illegal byte sequence */
#define EOVERFLOW 139	/* Value too large for defined data type */
#define ECANCELED 140	/* Operation canceled */
#define ENOTRECOVERABLE 141	/* State not recoverable */
#define EOWNERDEAD 142	/* Previous owner died */
#ifdef __LINUX_ERRNO_EXTENSIONS__
#define ESTRPIPE 143	/* Streams pipe error */
#endif
#define EWOULDBLOCK EAGAIN	/* Operation would block */

#define __ELASTERROR 2000	/* Users can add values starting here */

















#define INVALID_SOCKET	(~0)
#define SOCKET_ERROR	(-1)

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

/*
 * Option flags per-socket.
 */
#define  SO_DEBUG			0x0001    /* turn on debugging info recording */
#define  SO_ACCEPTCONN		0x0002    /* socket has had listen() */
#define  SO_REUSEADDR		0x0004    /* allow local address reuse */
#define  SO_KEEPALIVE		0x0008    /* keep connections alive */
#define  SO_DONTROUTE		0x0010    /* just use interface addresses */
#define  SO_BROADCAST		0x0020    /* permit sending of broadcast msgs */
#define  SO_USELOOPBACK		0x0040    /* bypass hardware when possible */
#define  SO_LINGER			0x0080    /* linger on close if data present */
#define  SO_OOBINLINE		0x0100    /* leave received OOB data in line */
#define	 SO_REUSEPORT		0x0200		/* allow local address & port reuse */

#define SO_DONTLINGER		(int)(~SO_LINGER)

/*
 * Additional options, not kept in so_options.
 */
#define SO_SNDBUF			0x1001    /* send buffer size */
#define SO_RCVBUF			0x1002    /* receive buffer size */
#define SO_SNDLOWAT			0x1003    /* send low-water mark */
#define SO_RCVLOWAT			0x1004    /* receive low-water mark */
#define SO_SNDTIMEO			0x1005    /* send timeout */
#define SO_RCVTIMEO			0x1006    /* receive timeout */
#define  SO_ERROR			0x1007    /* get error status and clear */
#define  SO_TYPE			0x1008    /* get socket type */

#define ATTRIBUTE_ALIGN(x) __attribute__((aligned(x)))
// courtesy of Marcan
#define STACK_ALIGN(type, name, cnt, alignment)		u8 _al__##name[((sizeof(type)*(cnt)) + (alignment) + (((sizeof(type)*(cnt))%(alignment)) > 0 ? ((alignment) - ((sizeof(type)*(cnt))%(alignment))) : 0))]; \
													type *name = (type*)(((u32)(_al__##name)) + ((alignment) - (((u32)(_al__##name))&((alignment)-1))))

//s32 net_ip_top_fd;

/*
 * Structure used for manipulating linger option.
 */
struct linger {
       int l_onoff;                /* option on/off */
       int l_linger;               /* linger time */
};

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define  SOL_SOCKET			0xfff    /* options for socket level */

#define AF_UNSPEC			0
#define AF_INET				2
#define PF_INET				AF_INET
#define PF_UNSPEC			AF_UNSPEC

#define IPPROTO_IP			0
#define IPPROTO_TCP			6
#define IPPROTO_UDP			17

#define INADDR_ANY			0
#define INADDR_BROADCAST	0xffffffff

/* Flags we can use with send and recv. */
#define MSG_DONTWAIT		0x40            /* Nonblocking i/o for this operation only */

/*
 * Options for level IPPROTO_IP
 */
#define IP_TOS				1
#define IP_TTL				2


#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos) & IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02
#define IPTOS_MINCOST       IPTOS_LOWCOST

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#define IPTOS_PREC_MASK                 0xe0
#define IPTOS_PREC(tos)                 ((tos) & IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00


/*
 * Commands for ioctlsocket(),  taken from the BSD file fcntl.h.
 *
 *
 * Ioctl's have the command encoded in the lower word,
 * and the size of any in or out parameters in the upper
 * word.  The high 2 bits of the upper word are used
 * to encode the in/out status of the parameter; for now
 * we restrict parameters to at most 128 bytes.
 */
#if !defined(FIONREAD) || !defined(FIONBIO)
#define IOCPARM_MASK    0x7f            /* parameters must be < 128 bytes */
#define IOC_VOID        0x20000000      /* no parameters */
#define IOC_OUT         0x40000000      /* copy out parameters */
#define IOC_IN          0x80000000      /* copy in parameters */
#define IOC_INOUT       (IOC_IN|IOC_OUT)
                                        /* 0x20000000 distinguishes new &
                                           old ioctl's */
#define _IO(x,y)        (IOC_VOID|((x)<<8)|(y))

#define _IOR(x,y,t)     (IOC_OUT|(((long)sizeof(t)&IOCPARM_MASK)<<16)|((x)<<8)|(y))

#define _IOW(x,y,t)     (IOC_IN|(((long)sizeof(t)&IOCPARM_MASK)<<16)|((x)<<8)|(y))
#endif

#ifndef FIONREAD
#define FIONREAD    _IOR('f', 127, unsigned long) /* get # bytes to read */
#endif
#ifndef FIONBIO
#define FIONBIO     _IOW('f', 126, unsigned long) /* set/clear non-blocking i/o */
#endif

/* Socket I/O Controls */
#ifndef SIOCSHIWAT
#define SIOCSHIWAT  _IOW('s',  0, unsigned long)  /* set high watermark */
#define SIOCGHIWAT  _IOR('s',  1, unsigned long)  /* get high watermark */
#define SIOCSLOWAT  _IOW('s',  2, unsigned long)  /* set low watermark */
#define SIOCGLOWAT  _IOR('s',  3, unsigned long)  /* get low watermark */
#define SIOCATMARK  _IOR('s',  7, unsigned long)  /* at oob mark? */
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK			04000U
#endif

#ifndef FD_SET
  #undef  FD_SETSIZE
  #define FD_SETSIZE		16
  #define FD_SET(n, p)		((p)->fd_bits[(n)/8] |=  (1 << ((n) & 7)))
  #define FD_CLR(n, p)		((p)->fd_bits[(n)/8] &= ~(1 << ((n) & 7)))
  #define FD_ISSET(n,p)		((p)->fd_bits[(n)/8] &   (1 << ((n) & 7)))
  #define FD_ZERO(p)		memset((void*)(p),0,sizeof(*(p)))

  typedef struct fd_set {
	u8 fd_bits [(FD_SETSIZE+7)/8];
  } fd_set;

  struct timeval {
    s32    tv_sec;         /* seconds */
    s32    tv_usec;        /* and microseconds */
  };

#endif

#ifndef TCP_NODELAY
#define	TCP_NODELAY	   0x01	   /* don't delay send to coalesce packets */
#endif
#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE  0x02    /* send KEEPALIVE probes when idle for pcb->keepalive miliseconds */
#endif

#ifndef socklen_t
#define socklen_t u32
#endif

#ifndef htons
#define htons(x) (x)
#endif
#ifndef ntohs
#define ntohs(x) (x)
#endif
#ifndef htonl
#define htonl(x) (x)
#endif
#ifndef ntohl
#define ntohl(x) (x)
#endif

#ifndef IP4_ADDR
#define IP4_ADDR(ipaddr, a,b,c,d) (ipaddr)->s_addr = htonl(((u32)(a&0xff)<<24)|((u32)(b&0xff)<<16)|((u32)(c&0xff)<<8)|(u32)(d&0xff))
#define ip4_addr1(ipaddr) ((u32)(ntohl((ipaddr)->s_addr) >> 24) & 0xff)
#define ip4_addr2(ipaddr) ((u32)(ntohl((ipaddr)->s_addr) >> 16) & 0xff)
#define ip4_addr3(ipaddr) ((u32)(ntohl((ipaddr)->s_addr) >> 8) & 0xff)
#define ip4_addr4(ipaddr) ((u32)(ntohl((ipaddr)->s_addr)) & 0xff)
#endif


#define _FREAD      0x0001  /* read enabled */
#define _FWRITE     0x0002  /* write enabled */
#define _FAPPEND    0x0008  /* append (writes guaranteed at the end) */
#define _FCREAT     0x0200  /* open with file create */
#define _FTRUNC     0x0400  /* open with truncation */
#define _FEXCL      0x0800  /* error on open if file exists */
#define _FSYNC      0x2000  /* do all writes synchronously */

#define O_RDONLY    0
#define O_WRONLY    1
#define O_RDWR      2
#define O_APPEND    _FAPPEND
#define O_CREAT     _FCREAT
#define O_TRUNC     _FTRUNC
#define O_EXCL      _FEXCL
#define O_SYNC      _FSYNC

//#define O_NONBLOCK  0x0800 /* non blocking (sockets only) */

#define F_GETFL     3   /* Get file flags */
#define F_SETFL     4   /* Set file flags */

extern "C" int atoi(const char* str);

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_IN_ADDR
#define HAVE_IN_ADDR
struct in_addr {
  u32 s_addr;
};
#endif

struct sockaddr_in {
  u8 sin_len;
  u8 sin_family;
  u16 sin_port;
  struct in_addr sin_addr;
  s8 sin_zero[8];
};

struct sockaddr {
  u8 sa_len;
  u8 sa_family;
  s8 sa_data[14];
};

struct hostent {
  char    *h_name;        /* official name of host */
  char    **h_aliases;    /* alias list */
  u16     h_addrtype;     /* host address type */
  u16     h_length;       /* length of address */
  char    **h_addr_list;  /* list of addresses from name server */
};

u32 inet_addr(const char *cp);
s8 inet_aton(const char *cp, struct in_addr *addr);
char *inet_ntoa(struct in_addr addr); /* returns ptr to static buffer; not reentrant! */

s32 if_config( char *local_ip, char *netmask, char *gateway,int use_dhcp);
s32 if_configex(struct in_addr *local_ip,struct in_addr *netmask,struct in_addr *gateway,int use_dhcp);

u32 net_gethostip();
s32 net_init();
s32 net_socket(u32 domain,u32 type,u32 protocol);
s32 net_bind(s32 s,struct sockaddr *name,socklen_t namelen);
s32 net_listen(s32 s,u32 backlog);
s32 net_accept(s32 s,struct sockaddr *addr,socklen_t *addrlen);
s32 net_connect(s32 s,struct sockaddr *,socklen_t);
s32 net_write(s32 s,const void *data,s32 size);
s32 net_send(s32 s,const void *data,s32 size,u32 flags);
s32 net_sendto(s32 s,const void *data,s32 len,u32 flags,struct sockaddr *to,socklen_t tolen);
s32 net_recv(s32 s,void *mem,s32 len,u32 flags);
s32 net_recvfrom(s32 s,void *mem,s32 len,u32 flags,struct sockaddr *from,socklen_t *fromlen);
s32 net_read(s32 s,void *mem,s32 len);
s32 net_close(s32 s);
s32 net_select(s32 maxfdp1,fd_set *readset,fd_set *writeset,fd_set *exceptset,struct timeval *timeout);
s32 net_setsockopt(s32 s,u32 level,u32 optname,const void *optval,socklen_t optlen);
s32 net_ioctl(s32 s, u32 cmd, void *argp);
s32 net_fcntl(s32 s, u32 cmd, u32 flags);
s32 net_shutdown(s32 s, u32 how);

struct hostent * net_gethostbyname(char *addrString);

#ifdef __cplusplus
	}
#endif

#endif
