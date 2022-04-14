/* udp_proxy.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of udp_proxy.
 *
 * udp_proxy is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * udp_proxy is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* udp_proxy.c
 *   $ gcc -Wall udp_proxy.c -o udp_proxy -levent
 *   $ ./udp_proxy -p 12345 -s 127.0.0.1:11111
 * For use with wolfSSL example server with client talking to proxy
 * on port 12345:
 *   $ ./examples/server/server -u
 *   $ ./examples/client/client -u -p 12345
*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <math.h>
#include <locale.h>
#ifndef _WIN32
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <sysexits.h>
    #define SOCKET_T int
    #define SOCKLEN_T socklen_t
    #define MY_EX_USAGE EX_USAGE
    #define MY_EX_IOERR EX_IOERR
    #define StartUDP()
    #define INVALID_SOCKET (-1)
#else
    #include <winsock2.h>
    #include <process.h>
    #define SOCKET_T SOCKET
    #define SOCKLEN_T int
    #define MY_EX_USAGE 2
    #define MY_EX_IOERR 3
    #define StartUDP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }
#endif

#include <event2/event.h>


/* datagram msg size */
#define MSG_SIZE 2000

#define SET_YELLOW printf("\033[0;33m")
#define SET_BLUE printf("\033[0;34m")
#define RESET_COLOR printf("\033[0m");

struct event_base* base;               /* main base */
struct sockaddr_in proxy, server;      /* proxy address and server address */
int serverLen = sizeof(server);        /* server address len */
int dropPacket    = 0;                 /* dropping packet interval */
int delayPacket   = 0;                 /* delay packet interval */
int dropNth = 0;
int dropPacketNo = 0;
int dropSpecific  = 0;                 /* specific seq to drop in epoch */
int dropSpecificSeq  = 0;              /* specific seq to drop */
int dropSpecificEpoch = 0;             /* specific epoch to drop in */
int delayByOne    = 0;                 /* delay packet by 1 */
int dupePackets   = 0;                 /* duplicate all packets */
int retxPacket = 0;                    /* specific seq to retransmit */
int injectAlert = 0;                   /* inject an alert at end of epoch 0 */
int isDtls13 = 0;
const char* selectedSide = NULL;       /* Forced side to use */
const char* seqOrder = "";             /* how to reorder 0th epoch packets */
const char* delayOrder = "";           /* how to reorder 0th epoch packets */

#define LOG(...)                            \
        do {                                \
            if (fp != NULL) {               \
                fprintf(fp, __VA_ARGS__);   \
                fflush(fp);                 \
            }                               \
            else                            \
                printf(__VA_ARGS__);        \
        } while(0)
FILE *fp = NULL;
const char* logFile = NULL;

typedef struct proxy_ctx {
    SOCKET_T  clientFd;       /* from client to proxy, downstream */
    SOCKET_T  serverFd;       /* form server to proxy, upstream   */
} proxy_ctx;


typedef struct delay_packet {
    char           msg[MSG_SIZE];   /* msg to delay */
    int            msgLen;          /* msg size */
    int            sendCount;       /* msg count for when to stop the delay */
    SOCKET_T       peerFd;          /* fd to later send on */
    proxy_ctx*     ctx;             /* associated context */
} delay_packet;

delay_packet  tmpDelay;            /* our tmp holder */
delay_packet* currDelay = NULL;    /* current packet to delay */

typedef struct time_delay_packet {
    SOCKET_T       fd;              /* file descriptor to send to */
    char           msg[MSG_SIZE];   /* msg to delay */
    int            msgLen;          /* msg size */
    struct event*  ev;              /* event that needs to be cleaned up after
                                     * the timeout expires */
    char*          side;
    int            pktIdx;
} time_delay_packet;

typedef struct event_list {
    struct event* ev;
    struct event_list* next;
} event_list;

static char* serverSide = "server";
static char* clientSide = "client";

event_list evCleanupList = { NULL, NULL };

char bogusAlert[] =
{
    0x15, 254, 253, 0, 0, 0, 0, 0, 0, 0, 69, 0, 2, 1, 10
};


int   myoptind;
char* myoptarg;


static int GetOpt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}

static char* GetRecordType(const char* msg)
{
    if (msg[0] == 0x16) {
        if (msg[13] == 0x01)
            return "Client Hello";
        else if (msg[13] == 0x00)
            return "Hello Request";
        else if (msg[13] == 0x03)
            return "Hello Verify Request";
        else if (msg[13] == 0x04)
            return "Session Ticket";
        else if (msg[13] == 0x0b)
            return "Certificate";
        else if (msg[13] == 0x0d)
            return "Certificate Request";
        else if (msg[13] == 0x0f)
            return "Certificate Verify";
        else if (msg[13] == 0x02)
            return "Server Hello";
        else if (msg[13] == 0x0e)
            return "Server Hello Done";
        else if (msg[13] == 0x10)
            return "Client Key Exchange";
        else if (msg[13] == 0x0c)
            return "Server Key Exchange";
        else
            return "Encrypted Handshake Message";
    }
    else if (msg[0] == 0x14)
        return "Change Cipher Spec";
    else if (msg[0] == 0x17)
        return "Application Data";
    else if (msg[0] == 0x15)
        return "Alert";

    return "Unknown";
}


static int GetRecordSeq(const char* msg)
{
    /* Only use the least significant 32-bits of the sequence number. */
    return (int)( msg[7]  << 24 |
                  msg[8] << 16 |
                  msg[9] << 8 |
                  msg[10]);
}


static int GetRecordEpoch(const char* msg)
{
    return (int)(msg[3] << 8 | msg[4]);
}


static void IncrementRecordSeq(char* msg)
{
    if (msg[3] == 0 && (msg[4] == 0 || msg[4] == 1)) {
        unsigned long seq = (int)( msg[7] << 24 | msg[8] << 16 |
                                   msg[9] << 8 | msg[10] );

        LOG(" old seq: %lu\n", seq);
        seq++;
        LOG(" new seq: %lu\n", seq);

        msg[7] = (char)(seq >> 24);
        msg[8] = (char)(seq >> 16);
        msg[9] = (char)(seq >> 8);
        msg[10] = (char)seq;
    }
}

static void logMsg(char* side, char* msg, int msgSz, int pktIdx)
{
    if (!isDtls13)
        LOG("%s: E: %d Seq: %2d handshake: %2d got %s read %d bytes\n", side,
                GetRecordEpoch(msg), GetRecordSeq(msg), msg[18],
                GetRecordType(msg), msgSz);
    else
        LOG("%d: %s: read %d bytes\n", pktIdx, side, msgSz);
}

typedef struct pkt {
    char bin[MSG_SIZE];
    int binSz;
    int pktIdx;
    struct pkt* next;
} pkt;
static pkt* pktStore = NULL;

static void pushPkt(char* msg, int msgSz, int peerIdx)
{
    if (msg && msgSz > 0) {
        pkt* tmp;
        pkt* new = (pkt*)malloc(sizeof(pkt));
        if (new == NULL)
            return;
        if (!isDtls13)
            LOG("Storing pkt with seq %d\n", GetRecordSeq(msg));
        else
            LOG("Storing pkt %d\n", peerIdx);
        memset(new, 0, sizeof(pkt));
        new->pktIdx = peerIdx;
        if (msgSz > MSG_SIZE) {
            LOG("Truncating saved packet");
            msgSz = MSG_SIZE;
        }
        memcpy(new->bin, msg, msgSz);
        new->binSz = msgSz;
        if (pktStore == NULL) {
            pktStore = new;
        }
        else {
            tmp = pktStore;
            while (tmp->next != NULL)
                tmp = tmp->next;
            tmp->next = new;
        }
    }
}

static void pktStoreDrain(char* side, SOCKET_T peerFd) {
    pkt* tmp = pktStore;
    pkt* prev = NULL;
    pktStore = NULL;
    while (tmp != NULL) {
        logMsg(side, tmp->bin, tmp->binSz, tmp->pktIdx);
        send(peerFd, tmp->bin, tmp->binSz, 0);
        prev = tmp;
        tmp = tmp->next;
        free(prev);
    }
}

static void pktStoreSend(char* side, SOCKET_T peerFd) {
    while (*seqOrder != '\0') {
        pkt* tmp = pktStore;
        pkt* prev = NULL;
        int seq = *seqOrder - '0';
        while (tmp != NULL) {
            if ((isDtls13 && tmp->pktIdx == seq) ||
               (!isDtls13 && GetRecordSeq(tmp->bin) == seq)) {
                logMsg(side, tmp->bin, tmp->binSz, tmp->pktIdx);
                send(peerFd, tmp->bin, tmp->binSz, 0);
                seqOrder++;
                if (prev != NULL)
                    prev->next = tmp->next;
                else if (tmp->next != NULL)
                    pktStore = tmp->next;
                else
                    pktStore = NULL;
                free(tmp);
                break;
            }
            prev = tmp;
            tmp = tmp->next;
        }
        if (tmp == NULL)
            return;
    }
}

static void clearEventList(void)
{
    event_list* list;
    for (list = &evCleanupList; list != NULL; list = list->next) {
        if (list->ev != NULL)
            event_free(list->ev);
    }
    list = evCleanupList.next;
    evCleanupList.ev = NULL;
    evCleanupList.next = NULL;
    for (; list != NULL; list = list->next)
        free(list);
}

static void addEventToCleanupList(struct event* ev)
{
    if (evCleanupList.ev == NULL)
        evCleanupList.ev = ev;
    else {
        event_list* list = &evCleanupList;
        while (list->next != NULL)
            list = list->next;
        list->next = (event_list*)malloc(sizeof(event_list));
        if (list->next == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }
        list->next->ev = ev;
        list->next->next = NULL;
    }
}

static void sendTimeDelayedPkt(evutil_socket_t fd, short flags, void* arg)
{
    time_delay_packet* tctx = (time_delay_packet*)arg;

    clearEventList();

    if (tctx->side == serverSide)
        SET_BLUE;
    else
        SET_YELLOW;
    logMsg(tctx->side, tctx->msg, tctx->msgLen, tctx->pktIdx);
    RESET_COLOR;
    send(tctx->fd, tctx->msg, tctx->msgLen, 0);

    /* Add event to cleanup queue */
    addEventToCleanupList(tctx->ev);
}

/* msg callback, send along to peer or do manipulation */
static void Msg(evutil_socket_t fd, short which, void* arg)
{
    static int msgCount = 0;
    static int peerIdx[2] = {-1, -1}; /* Number of packets seen from peer.
                                       * [0] client [1] server */

    char       msg[MSG_SIZE];
    proxy_ctx* ctx = (proxy_ctx*)arg;
    int        ret = recv(fd, msg, MSG_SIZE, 0);

    clearEventList();

    if (ret == 0)
        LOG("read 0\n");
    else if (ret < 0)
        LOG("read < 0\n");
    else {
        SOCKET_T peerFd;
        char* side;   /* from message side */
        int sideIdx;

        if (ctx->serverFd == fd) {
            peerFd = ctx->clientFd;
            side   = serverSide;
            sideIdx = 1;
        }
        else {
            peerFd = ctx->serverFd;
            side   = clientSide;
            sideIdx = 0;
        }

        peerIdx[sideIdx]++;

        if (!isDtls13) {
            if (side == selectedSide && GetRecordEpoch(msg) == 0
                    && *seqOrder != '\0') {
                int seq = *seqOrder - '0';
                if (GetRecordSeq(msg) != seq) {
                    pushPkt(msg, ret, -1);
                    return;
                }
                else {
                    seqOrder++;
                }
            }
        }
        else {
            /* No way of knowing what the sequence number is so just blindly
             * re-order the encrypted packets */
            if (side == selectedSide && *seqOrder != '\0') {
                int seq = *seqOrder - '0';
                if (peerIdx[sideIdx] != seq) {
                    pushPkt(msg, ret, peerIdx[sideIdx]);
                    return;
                }
                else {
                    seqOrder++;
                }
            }
        }

        if (*delayOrder != '\0') {
            /* We need to delay this packet */
            struct event* ev;
            double t = strtod(delayOrder, (char**)&delayOrder);
            time_delay_packet* tctx =
                    (time_delay_packet*)malloc(sizeof(time_delay_packet));
            struct timeval timeout = { 0 };

            if (tctx == NULL) {
                perror("malloc failed");
                exit(EXIT_FAILURE);
            }

            if (*delayOrder == ',')
                delayOrder++;

            memcpy(tctx->msg, msg, ret);
            tctx->msgLen = ret;
            tctx->fd = peerFd;
            tctx->side = side;
            tctx->pktIdx = peerIdx[sideIdx];

            LOG("*** delaying packet %d by %f seconds\n", peerIdx[sideIdx], t);
            timeout.tv_usec = (int)(modf(t, &t) * 1000000.0);
            timeout.tv_sec = (int)t;

            ev = evtimer_new(base, sendTimeDelayedPkt, tctx);
            if (ev == NULL) {
                perror("evtimer_new failed");
                exit(EXIT_FAILURE);
            }
            tctx->ev = ev;
            if (evtimer_add(ev, &timeout) != 0) {
                perror("evtimer_add failed");
                exit(EXIT_FAILURE);
            }
            return;
        }

        if (side == serverSide)
            SET_BLUE;
        else
            SET_YELLOW;
        logMsg(side, msg, ret, peerIdx[sideIdx]);
        RESET_COLOR;

        msgCount++;

        if (delayByOne &&
            GetRecordEpoch(msg) == 0 &&
            GetRecordSeq(msg) == delayByOne &&
            side == selectedSide) {

            LOG("*** delaying server packet %d\n", delayByOne);
            if (currDelay == NULL)
               currDelay = &tmpDelay;
            else {
               LOG("*** oops, still have a packet in delay\n");
               assert(0);
            }
            memcpy(currDelay->msg, msg, ret);
            currDelay->msgLen = ret;
            currDelay->sendCount = msgCount + delayPacket;
            currDelay->peerFd = peerFd;
            currDelay->ctx = ctx;
            return;
        }

        /* is it now time to send along delayed packet */
        if (delayPacket && currDelay && currDelay->sendCount == msgCount) {
            LOG("*** sending on delayed packet\n");
            send(currDelay->peerFd, currDelay->msg, currDelay->msgLen, 0);
            currDelay = NULL;
        }

        /* should we specifically drop the current packet from epoch 0 */
        if (dropSpecific && side == selectedSide &&
            GetRecordEpoch(msg) == dropSpecificEpoch &&
            GetRecordSeq(msg) == dropSpecificSeq) {
            LOG("*** but dropping this packet specifically\n");
            return;
        }

        if (dropNth && dropPacketNo == msgCount) {
            LOG("*** but dropping the %d packet\n", msgCount);
            return;
        }

        /* should we delay the current packet */
        if (delayPacket && (msgCount % delayPacket) == 0) {
            LOG("*** but delaying this packet\n");
            if (currDelay == NULL)
               currDelay = &tmpDelay;
            else {
               LOG("*** oops, still have a packet in delay\n");
               assert(0);
            }
            memcpy(currDelay->msg, msg, ret);
            currDelay->msgLen = ret;
            currDelay->sendCount = msgCount + delayPacket;
            currDelay->peerFd = peerFd;
            currDelay->ctx = ctx;
            return;
        }

        /* should we drop current packet altogether */
        if (dropPacket && (msgCount % dropPacket) == 0 
             && msg[0] != 0x17 /* But don't drop application data */) {
            LOG("*** but dropping this packet\n");
            return;
        }

        /* forward along */
        send(peerFd, msg, ret, 0);
        
        if (side == selectedSide) {
            if (side == serverSide)
                SET_BLUE;
            else
                SET_YELLOW;
            if ((isDtls13 || GetRecordEpoch(msg) == 0) && *seqOrder != '\0')
                pktStoreSend(side, peerFd);
            else
                pktStoreDrain(side, peerFd);
            RESET_COLOR;
        }

        if (injectAlert) {
            if (injectAlert == 1 && side == clientSide && msg[0] == 0x14) {
                bogusAlert[10] = (char)(GetRecordSeq(msg) + 1);
                injectAlert = 2;
            }
            if (injectAlert == 2 && side == serverSide && msg[0] == 0x14) {
                LOG("*** injecting a bogus alert from client after "
                       "change cipher spec\n");
                ret = send(ctx->serverFd, bogusAlert, sizeof(bogusAlert), 0);
                if (ret < 0) {
                    perror("send failed");
                    exit(EXIT_FAILURE);
                }
                injectAlert = 0;
            }
        }

        if (dupePackets)
            send(peerFd, msg, ret, 0);

        if (retxPacket && GetRecordEpoch(msg) == 0
            && GetRecordSeq(msg) == retxPacket && side == selectedSide) {

            IncrementRecordSeq(msg);
            IncrementRecordSeq(msg+14);
            send(peerFd, msg, ret, 0);
        }


        if (delayByOne &&
            GetRecordEpoch(msg) == 0 &&
            GetRecordSeq(msg) > delayByOne &&
            side == selectedSide &&
            currDelay) {

            LOG("*** sending on delayed packet\n");
            send(currDelay->peerFd, currDelay->msg, currDelay->msgLen, 0);
            currDelay = NULL;
        }
    }
}


/* new client callback */
static void newClient(evutil_socket_t fd, short which, void* arg)
{
    int ret, on = 1;
    struct sockaddr_in client;
    SOCKLEN_T len = sizeof(client);
    char msg[MSG_SIZE];
    int  msgLen;
    struct event* cliEvent;
    struct event* srvEvent;

    proxy_ctx* ctx = (proxy_ctx*)malloc(sizeof(proxy_ctx));
    if (ctx == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    /* let's 'connect' to client so main loop doesn't hear about this
       'connection' again, also allows pairing with upStream 'connect' */
    msgLen = recvfrom(fd, msg, MSG_SIZE, 0, (struct sockaddr*)&client, &len);
    SET_YELLOW;
    LOG("%s: got %s, first msg\n", clientSide, GetRecordType(msg));
    RESET_COLOR;
    ctx->clientFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->clientFd == INVALID_SOCKET) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(ctx->clientFd, SOL_SOCKET, SO_REUSEADDR,
               (char*)&on, (SOCKLEN_T)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(ctx->clientFd, SOL_SOCKET, SO_REUSEPORT,
               (char*)&on, (SOCKLEN_T)sizeof(on));
#endif

    ret = bind(ctx->clientFd, (struct sockaddr*)&proxy, sizeof(proxy));
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    ret = connect(ctx->clientFd, (struct sockaddr*)&client, len);
    if (ret < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    /* need to set up server socket too */
    ctx->serverFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->serverFd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    ret = connect(ctx->serverFd, (struct sockaddr*)&server, sizeof(server));
    if (ret < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    /* client and server both use same Msg relay callback */
    cliEvent = event_new(base, ctx->clientFd, EV_READ|EV_PERSIST, Msg, ctx); 
    if (cliEvent == NULL) {
        perror("event_new failed for cliEvent");
        exit(EXIT_FAILURE);
    }
    event_add(cliEvent, NULL);

    srvEvent = event_new(base, ctx->serverFd, EV_READ|EV_PERSIST, Msg, ctx); 
    if (srvEvent == NULL) {
        perror("event_new failed for srvEvent");
        exit(EXIT_FAILURE);
    }
    event_add(srvEvent, NULL);

    if (dropNth && dropPacketNo == 0) {
        LOG("*** but dropping this packet\n");
        return;
    }

    /* send along initial client message */
    ret = send(ctx->serverFd, msg, msgLen, 0);
    if (ret < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }
}


static void Usage(void)
{
    printf("udp_proxy \n");

    printf("-?                  Help, print this usage\n");
    printf("-p <num>            Proxy port to 'listen' on\n");
    printf("-s <server:port>    Server address in dotted decimal:port\n");
    printf("-d <num>            Drop every <num> packet, default 0\n");
    printf("-f <num>            Drop the <num> packet, default none\n");
    printf("-x <epoch>:<num>    "
           "Drop specifically packet with sequence <num> from <epoch>\n");
    printf("-y <num>            Delay every <num> packet, default 0\n");
    printf("-b <num>            "
           "Delay specific packet with sequence <num> by 1\n");
    printf("-D                  Duplicate all packets\n");
    printf("-R <num>            Retransmit packet sequence <num>\n");
    printf("-a                  Inject clear alert from client after CCS\n");
    printf("-r <pkt seq>        Re-order packets from zeroth epoch in this order\n"
           "                    ex: 146523\n");
    printf("-S <client|server>  Force side (default: server)\n");
    printf("-u                  Interpret traffic as DTLS 1.3\n");
    printf("-l <log file>       Use the provided argument as the log file\n");
    printf("-t <delays>         Comma seperated list of delays for each \n"
           "                    subsequent packet in seconds.\n");
}


int main(int argc, char** argv)
{
    SOCKET_T sockfd;
    int ret, ch, on = 1;
    struct event* mainEvent;
    short port = -1;
    char* serverString = NULL;

    setlocale(LC_ALL, ""); /* Make portable */

    while ( (ch = GetOpt(argc, argv, "?Dap:s:d:y:x:b:R:S:r:f:ul:t:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);
                break;

            case 'p' :
                port = atoi(myoptarg);
                break;

            case 'd' :
                dropPacket = atoi(myoptarg);
                break;

            case 'y' :
                delayPacket = atoi(myoptarg);
                break;

            case 'x':
                dropSpecific = 1;
                dropSpecificEpoch = atoi(myoptarg);
                dropSpecificSeq = atoi(strchr(myoptarg, ':') + 1);
                break;

            case 's' :
                serverString = myoptarg;
                break;

            case 'b':
                delayByOne = atoi(myoptarg);
                break;

            case 'D' :
                dupePackets = 1;
                break;

            case 'R' :
                retxPacket = atoi(myoptarg);
                break;

            case 'r' :
                {
                    const char* c = seqOrder = myoptarg;
                    for (; *c != '\0'; c++) {
                        if (*c > '9' || *c < '0') {
                            Usage();
                            exit(MY_EX_USAGE);
                        }
                    }
                }
                break;

            case 't' :
                {
                    const char* c = delayOrder = myoptarg;
                    while (*c != '\0') {
                        double d = strtod(c, (char**)&c);
                        if (d == 0.0) {
                            Usage();
                            exit(MY_EX_USAGE);
                        }
                        if (*c == ',')
                            c++;
                    }
                    if (*c != '\0') {
                        Usage();
                        exit(MY_EX_USAGE);
                    }
                }
                break;

            case 'a':
                injectAlert = 1;
                break;

            case 'S':
                if (strcmp(myoptarg, clientSide) == 0)
                    selectedSide = clientSide;
                else if (strcmp(myoptarg, serverSide) == 0)
                    selectedSide = serverSide;
                else {
                    Usage();
                    exit(MY_EX_USAGE);
                }
                break;

            case 'f':
                dropNth = 1;
                dropPacketNo = atoi(myoptarg);
                break;

            case 'u':
                isDtls13 = 1;
                break;

            case 'l':
                logFile = myoptarg;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
                break;
        }
    }

    if (logFile != NULL) {
        fp  = fopen(logFile, "w");
        if (fp == NULL) {
            LOG("Can't open log file\n");
            exit(MY_EX_IOERR);
        }
    }

    if (port == -1) {
        LOG("need to set 'listen port'\n");
        Usage();
        exit(MY_EX_USAGE);
    }

    if (serverString == NULL) {
        LOG("need to set server address string\n");
        Usage();
        exit(MY_EX_USAGE);
    }

    if (selectedSide == NULL)
        selectedSide = serverSide;

    StartUDP();

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    memset(&proxy, 0, sizeof(proxy));
    proxy.sin_family = AF_INET;
    proxy.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy.sin_port = htons(port);

    memset(&server, 0, sizeof(server));
    ret = evutil_parse_sockaddr_port(serverString, (struct sockaddr*)&server,
                                     &serverLen);
    if (ret < 0) {
        perror("parse_sockaddr_port failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               (char*)&on, (SOCKLEN_T)sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
               (char*)&on, (SOCKLEN_T)sizeof(on));
#endif

    ret = bind(sockfd, (struct sockaddr*)&proxy, sizeof(proxy));
    if (ret < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    base = event_base_new();
    if (base == NULL) {
        perror("event_base_new failed");
        exit(EXIT_FAILURE);
    }

    mainEvent = event_new(base, sockfd, EV_READ|EV_PERSIST, newClient, NULL);
    if (mainEvent == NULL) {
        perror("event_new failed for mainEvent");
        exit(EXIT_FAILURE);
    }
    event_add(mainEvent, NULL);

    event_base_dispatch(base);

    LOG("done with dispatching\n");

    return 0;
}
