#include "network/ssl.h"

#define ISALIGNED(x) ((((u32)x)&0x1F)==0)

static char __ssl_fs[] ATTRIBUTE_ALIGN(32) = "/dev/net/ssl";

static s32 __ssl_fd = -1;
static s32 __ssl_hid = -1;

u32 ssl_init(void) {
    /*if(__ssl_hid < 0 ) {
        __ssl_hid = iosCreateHeap(SSL_HEAP_SIZE);
        if(__ssl_hid < 0){
            return __ssl_hid;
        }
    }*/
    return 0;
}

u32 ssl_open(void) {
    s32 ret;
    if (__ssl_fd < 0) {
        ret = IOS_Open(__ssl_fs,0);
        if(ret<0){
            return ret;
        }
        __ssl_fd = ret;
    }
    return 0;
}

u32 ssl_close(void) {
    s32 ret;
    if(__ssl_fd < 0){
        return 0;
    }
    ret = IOS_Close(__ssl_fd);
    __ssl_fd = -1;
    if(ret<0){
        return ret;
    }
    return 0;
}

s32 ssl_new(u8 * CN, u32 ssl_verify_options) {
    s32 ret;
    s32 aContext[8] ATTRIBUTE_ALIGN(32);
    u32 aVerify_options[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[3];

    ret = ssl_open();
    if(ret){
        return ret;
    }

    aVerify_options[0] = ssl_verify_options;

    if(ISALIGNED(CN)){ 
        parms[0].data = aContext;
        parms[0].len = 0x20;
        parms[1].data = aVerify_options;
        parms[1].len = 0x20;
        parms[2].data = CN;
        parms[2].len = 0x100;

        ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_NEW, 2, 1, parms);
    } else {
        u8 *aCN = (u8*)AllocFromGameHeap1(0x100);
        if (!aCN) {
            return IPC_ENOMEM;
        }
        memcpy(aCN, CN, 0x100);

        parms[0].data = aContext;
        parms[0].len = 0x20;
        parms[1].data = aVerify_options;
        parms[1].len = 0x20;
        parms[2].data = aCN;
        parms[2].len = 0x100;

        ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_NEW, 1, 2, parms);

        FreeFromGameHeap1((void*)aCN);
    }

    ssl_close();
    return (ret ? ret : aContext[0]);
}

s32 ssl_setbuiltinclientcert(s32 ssl_context, s32 index) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aIndex[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[3] ATTRIBUTE_ALIGN(32);
	memset(&aSsl_context, 0, sizeof(aSsl_context));
	memset(&aIndex, 0, sizeof(aIndex));
	memset(&aResponse, 0, sizeof(aResponse));
	memset(&parms, 0, sizeof(parms));
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    aSsl_context[0] = ssl_context;
    aIndex[0] = index;

    parms[0].data = aResponse;
    parms[0].len = 0x20;
    parms[1].data = aSsl_context;
    parms[1].len = 0x20;
    parms[2].data = aIndex;
    parms[2].len = 0x20;

    ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_SETBUILTINCLIENTCERT, 1, 2, parms);
    ssl_close();
    return (ret ? ret : aResponse[0]);
}

s32 ssl_setrootca(s32 ssl_context, const void *root, u32 length) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[3];
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    aSsl_context[0] = ssl_context;

    if(ISALIGNED(root)){ 
        parms[0].data = aResponse;
        parms[0].len = 0x20;
        parms[1].data = aSsl_context;
        parms[1].len = 0x20;
        parms[2].data = (void*)root;
        parms[2].len = length;

        ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_SETROOTCA, 1, 2, parms);
    } else {
        u8 *aRoot = (u8*)AllocFromGameHeap1(length);
        if (!aRoot) {
            return IPC_ENOMEM;
        }
        memcpy(aRoot, root, length);

        parms[0].data = aResponse;
        parms[0].len = 0x20;
        parms[1].data = aSsl_context;
        parms[1].len = 0x20;
        parms[2].data = aRoot;
        parms[2].len = length;

        ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_SETROOTCA, 2, 1, parms);

        FreeFromGameHeap1((void*)aRoot);
    }

    ssl_close();
    return (ret ? ret : aResponse[0]);
}

s32 ssl_connect(s32 ssl_context, s32 socket) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aSocket[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[3];
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    aSsl_context[0] = ssl_context;
    aSocket[0] = socket;

    parms[0].data = aResponse;
    parms[0].len = 0x20;
    parms[1].data = aSsl_context;
    parms[1].len = 0x20;
    parms[2].data = aSocket;
    parms[2].len = 0x20;

    ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_CONNECT, 1, 2, parms);
    ssl_close();
    return (ret ? ret : aResponse[0]);
}

s32 ssl_handshake(s32 ssl_context) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[2];
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    aSsl_context[0] = ssl_context;

    parms[0].data = aResponse;
    parms[0].len = 0x20;
    parms[1].data = aSsl_context;
    parms[1].len = 0x20;

    ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_HANDSHAKE, 1, 1, parms);
    ssl_close();
    return (ret ? ret : aResponse[0]);
}

s32 ssl_read(s32 ssl_context, void* buffer, u32 length) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[3];
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    if(!buffer){
        return IPC_EINVAL;
    }

    u8 *aBuffer = (u8*)AllocFromGameHeap1(length);
    if (!aBuffer) {
        return IPC_ENOMEM;
    }

    aSsl_context[0] = ssl_context;

    parms[0].data = aResponse;
    parms[0].len = 0x20;
    parms[1].data = aBuffer;
    parms[1].len = length;
    parms[2].data = aSsl_context;
    parms[2].len = 0x20;

    ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_READ, 2, 1, parms);
    ssl_close();

    if(ret == IPC_OK){
        memcpy(buffer, aBuffer, aResponse[0]);
    }

    FreeFromGameHeap1((void*)aBuffer);
    return (ret ? ret : aResponse[0]);
}

s32 ssl_write(s32 ssl_context, const void *buffer, u32 length) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[3];
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    if(!buffer){
        return IPC_EINVAL;
    }

    aSsl_context[0] = ssl_context;

    if(ISALIGNED(buffer)){ 
        parms[0].data = aResponse;
        parms[0].len = 0x20;
        parms[1].data = aSsl_context;
        parms[1].len = 0x20;
        parms[2].data = (void*)buffer;
        parms[2].len = length;

        ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_WRITE, 1, 2, parms);
    } else {
        u8 *aBuffer = (u8*)AllocFromGameHeap1(length);
        if (!aBuffer) {
            return IPC_ENOMEM;
        }
        memcpy(aBuffer, buffer, length);

        parms[0].data = aResponse;
        parms[0].len = 0x20;
        parms[1].data = aSsl_context;
        parms[1].len = 0x20;
        parms[2].data = aBuffer;
        parms[2].len = length;

        ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_WRITE, 1, 2, parms);

        FreeFromGameHeap1((void*)aBuffer);
    }

    ssl_close();
    return (ret ? ret : aResponse[0]);
}

s32 ssl_shutdown(s32 ssl_context) {
    s32 aSsl_context[8] ATTRIBUTE_ALIGN(32);
    s32 aResponse[8] ATTRIBUTE_ALIGN(32);
    ioctlv parms[2];
    s32 ret;

    ret = ssl_open();
    if(ret){
        return ret;
    }

    aSsl_context[0] = ssl_context;

    parms[0].data = aResponse;
    parms[0].len = 0x20;
    parms[1].data = aSsl_context;
    parms[1].len = 0x20;

    ret = IOS_Ioctlv(__ssl_fd, IOCTLV_SSL_SHUTDOWN, 1, 1, parms);
    ssl_close();
    return (ret ? ret : aResponse[0]);
}
