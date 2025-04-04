// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/mem.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "./internal.h"
#include "../internal.h"

typedef union bio_addr_st {
  struct sockaddr sa;
# ifdef AF_INET6
  struct sockaddr_in6 s_in6;
# endif
  struct sockaddr_in s_in;
} BIO_ADDR;

typedef struct bio_dgram_data_st {
  BIO_ADDR peer;
  unsigned int connected;
  unsigned int _errno;
  unsigned int mtu;
  struct timeval next_timeout;
  struct timeval socket_timeout;
  unsigned int peekmode;
} bio_dgram_data;

static int dgram_clear(BIO *a)
{
  if (a == NULL)
    return 0;
  if (a->shutdown) {
    if (a->init) {
      close(a->num);
    }
    a->init = 0;
    a->flags = 0;
  }
  return 1;
}

static int BIO_dgram_non_fatal_error(int err)
{
  switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif

        return 1;
    default:
      break;
  }
  return 0;
}

static int BIO_dgram_should_retry(int i)
{
  int err;

  if ((i == 0) || (i == -1)) {
    err = errno;

# if defined(OPENSSL_SYS_WINDOWS)
    /*
     * If the socket return value (i) is -1 and err is unexpectedly 0 at
     * this point, the error code was overwritten by another system call
     * before this error handling is called.
     */
# endif

    return BIO_dgram_non_fatal_error(err);
  }
  return 0;
}

static void dgram_reset_rcv_timeout(BIO *b)
{
# if defined(SO_RCVTIMEO)
  bio_dgram_data *data = (bio_dgram_data *)b->ptr;

  /* Is a timer active? */
  if (data->next_timeout.tv_sec > 0 || data->next_timeout.tv_usec > 0) {
#  ifdef OPENSSL_SYS_WINDOWS
    int timeout = data->socket_timeout.tv_sec * 1000 +
        data->socket_timeout.tv_usec / 1000;
    if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                   (void *)&timeout, sizeof(timeout)) < 0) {
      perror("setsockopt");
                   }
#  else
    if (setsockopt
        (b->num, SOL_SOCKET, SO_RCVTIMEO, &(data->socket_timeout),
         sizeof(struct timeval)) < 0) {
      perror("setsockopt");
         }
#  endif
  }
# endif
}

/*
 * BIO_ADDR_sockaddr_size - non-public function that returns the size
 * of the struct sockaddr the BIO_ADDR is using.  If the protocol family
 * isn't set or is something other than AF_INET, AF_INET6 or AF_UNIX,
 * the size of the BIO_ADDR type is returned.
 */
static socklen_t BIO_ADDR_sockaddr_size(const BIO_ADDR *ap)
{
  if (ap->sa.sa_family == AF_INET)
    return sizeof(ap->s_in);
#ifdef AF_INET6
  if (ap->sa.sa_family == AF_INET6)
    return sizeof(ap->s_in6);
#endif
  return sizeof(*ap);
}

static const struct sockaddr *BIO_ADDR_sockaddr(const BIO_ADDR *ap)
{
  return &(ap->sa);
}

static int dgram_write(BIO *b, const char *in, int inl)
{
  int ret;
  bio_dgram_data *data = (bio_dgram_data *)b->ptr;
  errno = 0;

  if (data->connected)
    ret = write(b->num, in, inl);
  else {
    int peerlen = BIO_ADDR_sockaddr_size(&data->peer);

    ret = sendto(b->num, in, inl, 0,
                 BIO_ADDR_sockaddr(&data->peer), peerlen);
  }

  BIO_clear_retry_flags(b);
  if (ret <= 0) {
    if (BIO_dgram_should_retry(ret)) {
      BIO_set_retry_write(b);
      data->_errno = errno;
    }
  }
  return ret;
}

static void get_current_time(struct timeval *t)
{
# if defined(_WIN32)
  SYSTEMTIME st;
  union {
    unsigned __int64 ul;
    FILETIME ft;
  } now;

  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &now.ft);
#  ifdef  __MINGW32__
  now.ul -= 116444736000000000ULL;
#  else
  now.ul -= 116444736000000000UI64; /* re-bias to 1/1/1970 */
#  endif
  t->tv_sec = (long)(now.ul / 10000000);
  t->tv_usec = ((int)(now.ul % 10000000)) / 10;
# else
  gettimeofday(t, NULL);
# endif
}

static void dgram_adjust_rcv_timeout(BIO *b)
{
# if defined(SO_RCVTIMEO)
    bio_dgram_data *data = (bio_dgram_data *)b->ptr;
    union {
        size_t s;
        int i;
    } sz = {
        0
    };

    /* Is a timer active? */
    if (data->next_timeout.tv_sec > 0 || data->next_timeout.tv_usec > 0) {
        struct timeval timenow, timeleft;

        /* Read current socket timeout */
#  ifdef OPENSSL_SYS_WINDOWS
        int timeout;

        sz.i = sizeof(timeout);
        if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                       (void *)&timeout, &sz.i) < 0) {
            perror("getsockopt");
        } else {
            data->socket_timeout.tv_sec = timeout / 1000;
            data->socket_timeout.tv_usec = (timeout % 1000) * 1000;
        }
#  else
        sz.i = sizeof(data->socket_timeout);
        if (getsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                       &(data->socket_timeout), (void *)&sz) < 0) {
            perror("getsockopt");
        } else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0)
            assert(sz.s <= sizeof(data->socket_timeout));
#  endif

        /* Get current time */
        get_current_time(&timenow);

        /* Calculate time left until timer expires */
        OPENSSL_memcpy(&timeleft, &(data->next_timeout), sizeof(struct timeval));
        if (timeleft.tv_usec < timenow.tv_usec) {
            timeleft.tv_usec = 1000000 - timenow.tv_usec + timeleft.tv_usec;
            timeleft.tv_sec--;
        } else {
            timeleft.tv_usec -= timenow.tv_usec;
        }
        if (timeleft.tv_sec < timenow.tv_sec) {
            timeleft.tv_sec = 0;
            timeleft.tv_usec = 1;
        } else {
            timeleft.tv_sec -= timenow.tv_sec;
        }

        /*
         * Adjust socket timeout if next handshake message timer will expire
         * earlier.
         */
        if ((data->socket_timeout.tv_sec == 0
             && data->socket_timeout.tv_usec == 0)
            || (data->socket_timeout.tv_sec > timeleft.tv_sec)
            || (data->socket_timeout.tv_sec == timeleft.tv_sec
                && data->socket_timeout.tv_usec >= timeleft.tv_usec)) {
#  ifdef OPENSSL_SYS_WINDOWS
            timeout = timeleft.tv_sec * 1000 + timeleft.tv_usec / 1000;
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, sizeof(timeout)) < 0) {
                perror("setsockopt");
            }
#  else
            if (setsockopt(b->num, SOL_SOCKET, SO_RCVTIMEO, &timeleft,
                           sizeof(struct timeval)) < 0) {
                perror("setsockopt");
            }
#  endif
        }
    }
# endif
}

static struct sockaddr *BIO_ADDR_sockaddr_noconst(BIO_ADDR *ap)
{
  return &(ap->sa);
}

static int dgram_read(BIO *b, char *out, int outl)
{
  int ret = 0;
  bio_dgram_data *data = (bio_dgram_data *)b->ptr;
  int flags = 0;

  BIO_ADDR peer;
  socklen_t len = sizeof(peer);

  if (out != NULL) {
    errno = 0;;
    OPENSSL_cleanse(&peer, sizeof(peer));
    dgram_adjust_rcv_timeout(b);
    if (data->peekmode)
      flags = MSG_PEEK;
    ret = recvfrom(b->num, out, outl, flags,
                   BIO_ADDR_sockaddr_noconst(&peer), &len);

    if (!data->connected && ret >= 0)
      BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, &peer);

    BIO_clear_retry_flags(b);
    if (ret < 0) {
      if (BIO_dgram_should_retry(ret)) {
        BIO_set_retry_read(b);
        data->_errno = errno;
      }
    }

    dgram_reset_rcv_timeout(b);
  }
  return ret;
}

static int dgram_puts(BIO *bp, const char *str)
{
  int n, ret;

  n = strlen(str);
  ret = dgram_write(bp, str, n);
  return ret;
}

static long dgram_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
# if defined(OPENSSL_SYS_LINUX) && (defined(IP_MTU_DISCOVER) || defined(IP_MTU))
    socklen_t sockopt_len;      /* assume that system supporting IP_MTU is
                                 * modern enough to define socklen_t */
    socklen_t addr_len;
    BIO_ADDR addr;
# endif

    switch (cmd) {
    case BIO_C_SET_FD:
        dgram_clear(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int dgram_new(BIO *bi)
{
  bio_dgram_data *data = OPENSSL_zalloc(sizeof(*data));

  if (data == NULL)
    return 0;
  bi->ptr = data;
  return 1;
}

static int dgram_free(BIO *a)
{
  bio_dgram_data *data;

  if (a == NULL)
    return 0;
  if (!dgram_clear(a))
    return 0;

  data = (bio_dgram_data *)a->ptr;
  OPENSSL_free(data);

  return 1;
}

static const BIO_METHOD methods_dgramp = {
  BIO_TYPE_DGRAM,
  "datagram socket",
  dgram_write,
  dgram_read,
  dgram_puts,
  NULL,                       /* dgram_gets,         */
  dgram_ctrl,
  dgram_new,
  dgram_free,
  NULL,                       /* dgram_callback_ctrl */
};

const BIO_METHOD *BIO_s_datagram(void) {
  return &methods_dgramp;
}


