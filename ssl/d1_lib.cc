/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/ssl.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "../crypto/internal.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

// DTLS1_MTU_TIMEOUTS is the maximum number of timeouts to expire
// before starting to decrease the MTU.
#define DTLS1_MTU_TIMEOUTS                     2

// DTLS1_MAX_TIMEOUTS is the maximum number of timeouts to expire
// before failing the DTLS handshake.
#define DTLS1_MAX_TIMEOUTS                     12

DTLS1_STATE::DTLS1_STATE()
    : has_change_cipher_spec(false),
      outgoing_messages_complete(false),
      flight_has_reply(false) {}

DTLS1_STATE::~DTLS1_STATE() {}

bool dtls1_new(SSL *ssl) {
  if (!tls_new(ssl)) {
    return false;
  }
  UniquePtr<DTLS1_STATE> d1 = MakeUnique<DTLS1_STATE>();
  if (!d1) {
    tls_free(ssl);
    return false;
  }

  ssl->d1 = d1.release();

  // Set the version to the highest supported version.
  //
  // TODO(davidben): Move this field into |s3|, have it store the normalized
  // protocol version, and implement this pre-negotiation quirk in |SSL_version|
  // at the API boundary rather than in internal state.
  ssl->version = DTLS1_2_VERSION;
  return true;
}

void dtls1_free(SSL *ssl) {
  tls_free(ssl);

  if (ssl == NULL) {
    return;
  }

  Delete(ssl->d1);
  ssl->d1 = NULL;
}

void dtls1_start_timer(SSL *ssl) {
  // If timer is not set, initialize duration (by default, 1 second)
  if (ssl->d1->next_timeout.tv_sec == 0 && ssl->d1->next_timeout.tv_usec == 0) {
    ssl->d1->timeout_duration_ms = ssl->initial_timeout_duration_ms;
  }

  // Set timeout to current time
  ssl_get_current_time(ssl, &ssl->d1->next_timeout);

  // Add duration to current time
  ssl->d1->next_timeout.tv_sec += ssl->d1->timeout_duration_ms / 1000;
  ssl->d1->next_timeout.tv_usec += (ssl->d1->timeout_duration_ms % 1000) * 1000;
  if (ssl->d1->next_timeout.tv_usec >= 1000000) {
    ssl->d1->next_timeout.tv_sec++;
    ssl->d1->next_timeout.tv_usec -= 1000000;
  }
}

bool dtls1_is_timer_expired(SSL *ssl) {
  struct timeval timeleft;

  // Get time left until timeout, return false if no timer running
  if (!DTLSv1_get_timeout(ssl, &timeleft)) {
    return false;
  }

  // Return false if timer is not expired yet
  if (timeleft.tv_sec > 0 || timeleft.tv_usec > 0) {
    return false;
  }

  // Timer expired, so return true
  return true;
}

static void dtls1_double_timeout(SSL *ssl) {
  ssl->d1->timeout_duration_ms *= 2;
  if (ssl->d1->timeout_duration_ms > 60000) {
    ssl->d1->timeout_duration_ms = 60000;
  }
}

void dtls1_stop_timer(SSL *ssl) {
  ssl->d1->num_timeouts = 0;
  OPENSSL_memset(&ssl->d1->next_timeout, 0, sizeof(ssl->d1->next_timeout));
  ssl->d1->timeout_duration_ms = ssl->initial_timeout_duration_ms;
}

bool dtls1_check_timeout_num(SSL *ssl) {
  ssl->d1->num_timeouts++;

  // Reduce MTU after 2 unsuccessful retransmissions
  if (ssl->d1->num_timeouts > DTLS1_MTU_TIMEOUTS &&
      !(SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
    long mtu =
        BIO_ctrl(ssl->wbio.get(), BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0, nullptr);
    if (mtu >= 0 && mtu <= (1 << 30) && (unsigned)mtu >= dtls1_min_mtu()) {
      ssl->d1->mtu = (unsigned)mtu;
    }
  }

  if (ssl->d1->num_timeouts > DTLS1_MAX_TIMEOUTS) {
    // fail the connection, enough alerts have been sent
    OPENSSL_PUT_ERROR(SSL, SSL_R_READ_TIMEOUT_EXPIRED);
    return false;
  }

  return true;
}

BSSL_NAMESPACE_END

using namespace bssl;

void DTLSv1_set_initial_timeout_duration(SSL *ssl, unsigned int duration_ms) {
  ssl->initial_timeout_duration_ms = duration_ms;
}

int DTLSv1_get_timeout(const SSL *ssl, struct timeval *out) {
  if (!SSL_is_dtls(ssl)) {
    return 0;
  }

  // If no timeout is set, just return 0.
  if (ssl->d1->next_timeout.tv_sec == 0 && ssl->d1->next_timeout.tv_usec == 0) {
    return 0;
  }

  struct OPENSSL_timeval timenow;
  ssl_get_current_time(ssl, &timenow);

  // If timer already expired, set remaining time to 0.
  if (ssl->d1->next_timeout.tv_sec < timenow.tv_sec ||
      (ssl->d1->next_timeout.tv_sec == timenow.tv_sec &&
       ssl->d1->next_timeout.tv_usec <= timenow.tv_usec)) {
    OPENSSL_memset(out, 0, sizeof(*out));
    return 1;
  }

  // Calculate time left until timer expires.
  struct OPENSSL_timeval ret;
  OPENSSL_memcpy(&ret, &ssl->d1->next_timeout, sizeof(ret));
  ret.tv_sec -= timenow.tv_sec;
  if (ret.tv_usec >= timenow.tv_usec) {
    ret.tv_usec -= timenow.tv_usec;
  } else {
    ret.tv_usec = 1000000 + ret.tv_usec - timenow.tv_usec;
    ret.tv_sec--;
  }

  // If remaining time is less than 15 ms, set it to 0 to prevent issues
  // because of small divergences with socket timeouts.
  if (ret.tv_sec == 0 && ret.tv_usec < 15000) {
    OPENSSL_memset(&ret, 0, sizeof(ret));
  }

  // Clamp the result in case of overflow.
  if (ret.tv_sec > INT_MAX) {
    assert(0);
    out->tv_sec = INT_MAX;
  } else {
    out->tv_sec = ret.tv_sec;
  }

  out->tv_usec = ret.tv_usec;
  return 1;
}

int DTLSv1_handle_timeout(SSL *ssl) {
  ssl_reset_error_state(ssl);

  if (!SSL_is_dtls(ssl)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return -1;
  }

  // If no timer is expired, don't do anything.
  if (!dtls1_is_timer_expired(ssl)) {
    return 0;
  }

  if (!dtls1_check_timeout_num(ssl)) {
    return -1;
  }

  dtls1_double_timeout(ssl);
  dtls1_start_timer(ssl);
  return dtls1_retransmit_outgoing_messages(ssl);
}

int DTLSv1_listen(SSL *s, BIO_ADDR *client)
{
    int next, n, ret = 0;
    unsigned char cookie[DTLS1_COOKIE_LENGTH];
    unsigned char seq[SEQ_NUM_SIZE];
    const unsigned char *data;
    unsigned char *buf, *wbuf;
    size_t fragoff, fraglen, msglen, reclen, align = 0;
    unsigned int rectype, versmajor, msgseq, msgtype, clientvers, cookielen;
    BIO *rbio, *wbio;
    BIO_ADDR *tmpclient = NULL;
    PACKET pkt, msgpkt, msgpayload, session, cookiepkt;

    if (s->handshake_func == NULL) {
        /* Not properly initialized yet */
        SSL_set_accept_state(s);
    }

    /* Ensure there is no state left over from a previous invocation */
    if (!SSL_clear(s))
        return -1;

    ERR_clear_error();

    rbio = SSL_get_rbio(s);
    wbio = SSL_get_wbio(s);

    if (!rbio || !wbio) {
        SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_BIO_NOT_SET);
        return -1;
    }

    /*
     * Note: This check deliberately excludes DTLS1_BAD_VER because that version
     * requires the MAC to be calculated *including* the first ClientHello
     * (without the cookie). Since DTLSv1_listen is stateless that cannot be
     * supported. DTLS1_BAD_VER must use cookies in a stateful manner (e.g. via
     * SSL_accept)
     */
    if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
        SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_UNSUPPORTED_SSL_VERSION);
        return -1;
    }

    if (!ssl3_setup_buffers(s)) {
        /* SSLerr already called */
        return -1;
    }
    buf = RECORD_LAYER_get_rbuf(&s->rlayer)->buf;
    wbuf = RECORD_LAYER_get_wbuf(&s->rlayer)[0].buf;
#if defined(SSL3_ALIGN_PAYLOAD)
# if SSL3_ALIGN_PAYLOAD != 0
    /*
     * Using SSL3_RT_HEADER_LENGTH here instead of DTLS1_RT_HEADER_LENGTH for
     * consistency with ssl3_read_n. In practice it should make no difference
     * for sensible values of SSL3_ALIGN_PAYLOAD because the difference between
     * SSL3_RT_HEADER_LENGTH and DTLS1_RT_HEADER_LENGTH is exactly 8
     */
    align = (size_t)buf + SSL3_RT_HEADER_LENGTH;
    align = SSL3_ALIGN_PAYLOAD - 1 - ((align - 1) % SSL3_ALIGN_PAYLOAD);
# endif
#endif
    buf += align;

    do {
        /* Get a packet */

        clear_sys_error();
        n = BIO_read(rbio, buf, SSL3_RT_MAX_PLAIN_LENGTH
                                + DTLS1_RT_HEADER_LENGTH);
        if (n <= 0) {
            if (BIO_should_retry(rbio)) {
                /* Non-blocking IO */
                goto end;
            }
            return -1;
        }

        if (!PACKET_buf_init(&pkt, buf, n)) {
            SSLerr(SSL_F_DTLSV1_LISTEN, ERR_R_INTERNAL_ERROR);
            return -1;
        }

        /*
         * Parse the received record. If there are any problems with it we just
         * dump it - with no alert. RFC6347 says this "Unlike TLS, DTLS is
         * resilient in the face of invalid records (e.g., invalid formatting,
         * length, MAC, etc.).  In general, invalid records SHOULD be silently
         * discarded, thus preserving the association; however, an error MAY be
         * logged for diagnostic purposes."
         */

        /* this packet contained a partial record, dump it */
        if (n < DTLS1_RT_HEADER_LENGTH) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_RECORD_TOO_SMALL);
            goto end;
        }

        if (s->msg_callback)
            s->msg_callback(0, 0, SSL3_RT_HEADER, buf,
                            DTLS1_RT_HEADER_LENGTH, s, s->msg_callback_arg);

        /* Get the record header */
        if (!PACKET_get_1(&pkt, &rectype)
            || !PACKET_get_1(&pkt, &versmajor)) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        if (rectype != SSL3_RT_HANDSHAKE) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_UNEXPECTED_MESSAGE);
            goto end;
        }

        /*
         * Check record version number. We only check that the major version is
         * the same.
         */
        if (versmajor != DTLS1_VERSION_MAJOR) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_BAD_PROTOCOL_VERSION_NUMBER);
            goto end;
        }

        if (!PACKET_forward(&pkt, 1)
            /* Save the sequence number: 64 bits, with top 2 bytes = epoch */
            || !PACKET_copy_bytes(&pkt, seq, SEQ_NUM_SIZE)
            || !PACKET_get_length_prefixed_2(&pkt, &msgpkt)) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_LENGTH_MISMATCH);
            goto end;
        }
        reclen = PACKET_remaining(&msgpkt);
        /*
         * We allow data remaining at the end of the packet because there could
         * be a second record (but we ignore it)
         */

        /* This is an initial ClientHello so the epoch has to be 0 */
        if (seq[0] != 0 || seq[1] != 0) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_UNEXPECTED_MESSAGE);
            goto end;
        }

        /* Get a pointer to the raw message for the later callback */
        data = PACKET_data(&msgpkt);

        /* Finished processing the record header, now process the message */
        if (!PACKET_get_1(&msgpkt, &msgtype)
            || !PACKET_get_net_3_len(&msgpkt, &msglen)
            || !PACKET_get_net_2(&msgpkt, &msgseq)
            || !PACKET_get_net_3_len(&msgpkt, &fragoff)
            || !PACKET_get_net_3_len(&msgpkt, &fraglen)
            || !PACKET_get_sub_packet(&msgpkt, &msgpayload, fraglen)
            || PACKET_remaining(&msgpkt) != 0) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        if (msgtype != SSL3_MT_CLIENT_HELLO) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_UNEXPECTED_MESSAGE);
            goto end;
        }

        /* Message sequence number can only be 0 or 1 */
        if (msgseq > 2) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_INVALID_SEQUENCE_NUMBER);
            goto end;
        }

        /*
         * We don't support fragment reassembly for ClientHellos whilst
         * listening because that would require server side state (which is
         * against the whole point of the ClientHello/HelloVerifyRequest
         * mechanism). Instead we only look at the first ClientHello fragment
         * and require that the cookie must be contained within it.
         */
        if (fragoff != 0 || fraglen > msglen) {
            /* Non initial ClientHello fragment (or bad fragment) */
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_FRAGMENTED_CLIENT_HELLO);
            goto end;
        }

        if (s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, data,
                            fraglen + DTLS1_HM_HEADER_LENGTH, s,
                            s->msg_callback_arg);

        if (!PACKET_get_net_2(&msgpayload, &clientvers)) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        /*
         * Verify client version is supported
         */
        if (DTLS_VERSION_LT(clientvers, (unsigned int)s->method->version) &&
            s->method->version != DTLS_ANY_VERSION) {
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_WRONG_VERSION_NUMBER);
            goto end;
        }

        if (!PACKET_forward(&msgpayload, SSL3_RANDOM_SIZE)
            || !PACKET_get_length_prefixed_1(&msgpayload, &session)
            || !PACKET_get_length_prefixed_1(&msgpayload, &cookiepkt)) {
            /*
             * Could be malformed or the cookie does not fit within the initial
             * ClientHello fragment. Either way we can't handle it.
             */
            SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_LENGTH_MISMATCH);
            goto end;
        }

        /*
         * Check if we have a cookie or not. If not we need to send a
         * HelloVerifyRequest.
         */
        if (PACKET_remaining(&cookiepkt) == 0) {
            next = LISTEN_SEND_VERIFY_REQUEST;
        } else {
            /*
             * We have a cookie, so lets check it.
             */
            if (s->ctx->app_verify_cookie_cb == NULL) {
                SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_NO_VERIFY_COOKIE_CALLBACK);
                /* This is fatal */
                return -1;
            }
            if (s->ctx->app_verify_cookie_cb(s, PACKET_data(&cookiepkt),
                    (unsigned int)PACKET_remaining(&cookiepkt)) == 0) {
                /*
                 * We treat invalid cookies in the same was as no cookie as
                 * per RFC6347
                 */
                next = LISTEN_SEND_VERIFY_REQUEST;
            } else {
                /* Cookie verification succeeded */
                next = LISTEN_SUCCESS;
            }
        }

        if (next == LISTEN_SEND_VERIFY_REQUEST) {
            WPACKET wpkt;
            unsigned int version;
            size_t wreclen;

            /*
             * There was no cookie in the ClientHello so we need to send a
             * HelloVerifyRequest. If this fails we do not worry about trying
             * to resend, we just drop it.
             */

            /* Generate the cookie */
            if (s->ctx->app_gen_cookie_cb == NULL ||
                s->ctx->app_gen_cookie_cb(s, cookie, &cookielen) == 0 ||
                cookielen > 255) {
                SSLerr(SSL_F_DTLSV1_LISTEN, SSL_R_COOKIE_GEN_CALLBACK_FAILURE);
                /* This is fatal */
                return -1;
            }

            /*
             * Special case: for hello verify request, client version 1.0 and we
             * haven't decided which version to use yet send back using version
             * 1.0 header: otherwise some clients will ignore it.
             */
            version = (s->method->version == DTLS_ANY_VERSION) ? DTLS1_VERSION
                                                               : s->version;

            /* Construct the record and message headers */
            if (!WPACKET_init_static_len(&wpkt,
                                         wbuf,
                                         ssl_get_max_send_fragment(s)
                                         + DTLS1_RT_HEADER_LENGTH,
                                         0)
                    || !WPACKET_put_bytes_u8(&wpkt, SSL3_RT_HANDSHAKE)
                    || !WPACKET_put_bytes_u16(&wpkt, version)
                       /*
                        * Record sequence number is always the same as in the
                        * received ClientHello
                        */
                    || !WPACKET_memcpy(&wpkt, seq, SEQ_NUM_SIZE)
                       /* End of record, start sub packet for message */
                    || !WPACKET_start_sub_packet_u16(&wpkt)
                       /* Message type */
                    || !WPACKET_put_bytes_u8(&wpkt,
                                             DTLS1_MT_HELLO_VERIFY_REQUEST)
                       /*
                        * Message length - doesn't follow normal TLS convention:
                        * the length isn't the last thing in the message header.
                        * We'll need to fill this in later when we know the
                        * length. Set it to zero for now
                        */
                    || !WPACKET_put_bytes_u24(&wpkt, 0)
                       /*
                        * Message sequence number is always 0 for a
                        * HelloVerifyRequest
                        */
                    || !WPACKET_put_bytes_u16(&wpkt, 0)
                       /*
                        * We never fragment a HelloVerifyRequest, so fragment
                        * offset is 0
                        */
                    || !WPACKET_put_bytes_u24(&wpkt, 0)
                       /*
                        * Fragment length is the same as message length, but
                        * this *is* the last thing in the message header so we
                        * can just start a sub-packet. No need to come back
                        * later for this one.
                        */
                    || !WPACKET_start_sub_packet_u24(&wpkt)
                       /* Create the actual HelloVerifyRequest body */
                    || !dtls_raw_hello_verify_request(&wpkt, cookie, cookielen)
                       /* Close message body */
                    || !WPACKET_close(&wpkt)
                       /* Close record body */
                    || !WPACKET_close(&wpkt)
                    || !WPACKET_get_total_written(&wpkt, &wreclen)
                    || !WPACKET_finish(&wpkt)) {
                SSLerr(SSL_F_DTLSV1_LISTEN, ERR_R_INTERNAL_ERROR);
                WPACKET_cleanup(&wpkt);
                /* This is fatal */
                return -1;
            }

            /*
             * Fix up the message len in the message header. Its the same as the
             * fragment len which has been filled in by WPACKET, so just copy
             * that. Destination for the message len is after the record header
             * plus one byte for the message content type. The source is the
             * last 3 bytes of the message header
             */
            memcpy(&wbuf[DTLS1_RT_HEADER_LENGTH + 1],
                   &wbuf[DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH - 3],
                   3);

            if (s->msg_callback)
                s->msg_callback(1, 0, SSL3_RT_HEADER, buf,
                                DTLS1_RT_HEADER_LENGTH, s, s->msg_callback_arg);

            if ((tmpclient = BIO_ADDR_new()) == NULL) {
                SSLerr(SSL_F_DTLSV1_LISTEN, ERR_R_MALLOC_FAILURE);
                goto end;
            }

            /*
             * This is unnecessary if rbio and wbio are one and the same - but
             * maybe they're not. We ignore errors here - some BIOs do not
             * support this.
             */
            if (BIO_dgram_get_peer(rbio, tmpclient) > 0) {
                (void)BIO_dgram_set_peer(wbio, tmpclient);
            }
            BIO_ADDR_free(tmpclient);
            tmpclient = NULL;

            /* TODO(size_t): convert this call */
            if (BIO_write(wbio, wbuf, wreclen) < (int)wreclen) {
                if (BIO_should_retry(wbio)) {
                    /*
                     * Non-blocking IO...but we're stateless, so we're just
                     * going to drop this packet.
                     */
                    goto end;
                }
                return -1;
            }

            if (BIO_flush(wbio) <= 0) {
                if (BIO_should_retry(wbio)) {
                    /*
                     * Non-blocking IO...but we're stateless, so we're just
                     * going to drop this packet.
                     */
                    goto end;
                }
                return -1;
            }
        }
    } while (next != LISTEN_SUCCESS);

    /*
     * Set expected sequence numbers to continue the handshake.
     */
    s->d1->handshake_read_seq = 1;
    s->d1->handshake_write_seq = 1;
    s->d1->next_handshake_write_seq = 1;
    DTLS_RECORD_LAYER_set_write_sequence(&s->rlayer, seq);

    /*
     * We are doing cookie exchange, so make sure we set that option in the
     * SSL object
     */
    SSL_set_options(s, SSL_OP_COOKIE_EXCHANGE);

    /*
     * Tell the state machine that we've done the initial hello verify
     * exchange
     */
    ossl_statem_set_hello_verify_done(s);

    /*
     * Some BIOs may not support this. If we fail we clear the client address
     */
    if (BIO_dgram_get_peer(rbio, client) <= 0)
        BIO_ADDR_clear(client);

    /* Buffer the record in the processed_rcds queue */
    if (!dtls_buffer_listen_record(s, reclen, seq, align))
        return -1;

    ret = 1;
 end:
    BIO_ADDR_free(tmpclient);
    return ret;
}
