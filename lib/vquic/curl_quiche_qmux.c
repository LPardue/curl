/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_QUICHE)
#include <quiche.h>

#include "bufq.h"
#include "uint-hash.h"
#include "urldata.h"
#include "cfilters.h"
#include "cf-dns.h"
#include "cf-socket.h"
#include "curl_trc.h"
#include "rand.h"
#include "multiif.h"
#include "connect.h"
#include "progress.h"
#include "select.h"
#include "http1.h"
#include "vquic/vquic.h"
#include "vquic/vquic_int.h"
#include "vquic/curl_quiche.h"
#include "transfer.h"
#include "url.h"
#include "bufref.h"
#include "vtls/vtls.h"
#include "vtls/vtls_int.h"
#include "curlx/strdup.h"

/* HTTP/3 error values defined in RFC 9114, ch. 8.1 */
#define CURL_H3_NO_ERROR  0x0100

#define QUIC_MAX_STREAMS       100

#define H3_STREAM_WINDOW_SIZE  (1024 * 128)
#define H3_STREAM_CHUNK_SIZE   (1024 * 16)
#define H3_STREAM_RECV_CHUNKS \
  (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)

/* QMux send/recv buffer size */
#define QMUX_BUF_SIZE  65536

struct cf_qmux_ctx {
  curl_socket_t sockfd;
  quiche_conn *qconn;
  quiche_config *cfg;
  quiche_h3_conn *h3c;
  quiche_h3_config *h3config;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  struct curltime started_at;
  struct curltime handshake_at;
  struct curltime first_byte_at;
  struct uint_hash streams;
  struct dynbuf h1hdr;
  struct bufq writebuf;
  curl_off_t data_recvd;
  uint8_t *egress_buf;           /* partial egress data waiting to be sent */
  size_t egress_buf_len;         /* total bytes in egress_buf */
  size_t egress_buf_sent;        /* bytes already sent from egress_buf */
  BIT(initialized);
  BIT(goaway);
  BIT(shutdown_started);
};

#ifdef DEBUG_QUICHE
static int debug_log_init = 0;
static void quiche_debug_log(const char *line, void *argp)
{
  (void)argp;
  curl_mfprintf(stderr, "%s\n", line);
}
#endif

static void h3_stream_hash_free(unsigned int id, void *stream);

static void cf_qmux_ctx_init(struct cf_qmux_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
#ifdef DEBUG_QUICHE
  if(!debug_log_init) {
    quiche_enable_debug_logging(quiche_debug_log, NULL);
    debug_log_init = 1;
  }
#endif
  curlx_dyn_init(&ctx->h1hdr, CURL_MAX_HTTP_HEADER);
  Curl_uint32_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  Curl_bufq_init2(&ctx->writebuf, H3_STREAM_CHUNK_SIZE, H3_STREAM_RECV_CHUNKS,
                  BUFQ_OPT_SOFT_LIMIT);
  ctx->data_recvd = 0;
  ctx->sockfd = CURL_SOCKET_BAD;
  ctx->initialized = TRUE;
}

static void cf_qmux_ctx_free(struct cf_qmux_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_uint32_hash_destroy(&ctx->streams);
    curlx_dyn_free(&ctx->h1hdr);
    Curl_bufq_free(&ctx->writebuf);
    curlx_free(ctx->egress_buf);
    ctx->egress_buf = NULL;
  }
  curlx_free(ctx);
}

static void cf_qmux_ctx_close(struct cf_qmux_ctx *ctx)
{
  if(ctx->h3c) {
    quiche_h3_conn_free(ctx->h3c);
    ctx->h3c = NULL;
  }
  if(ctx->h3config) {
    quiche_h3_config_free(ctx->h3config);
    ctx->h3config = NULL;
  }
  if(ctx->qconn) {
    quiche_conn_free(ctx->qconn);
    ctx->qconn = NULL;
  }
  if(ctx->cfg) {
    quiche_config_free(ctx->cfg);
    ctx->cfg = NULL;
  }
}

static CURLcode cf_flush_egress(struct Curl_cfilter *cf,
                                struct Curl_easy *data);

/*
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  uint64_t id;             /* HTTP/3 protocol stream identifier */
  struct h1_req_parser h1; /* h1 request parsing */
  uint64_t error3;         /* HTTP/3 stream error code */
  int status_code;         /* HTTP status code */
  CURLcode xfer_result;    /* result from write_hd/body */
  BIT(opened);
  BIT(closed);
  BIT(reset);
  BIT(send_closed);
  BIT(resp_hds_complete);
  BIT(resp_got_header);
  BIT(quic_flow_blocked);
};

static void h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
  Curl_h1_req_parse_free(&stream->h1);
  curlx_free(stream);
}

static void h3_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct h3_stream_ctx *)stream);
}

typedef bool cf_qmux_svisit(struct Curl_cfilter *cf,
                             struct Curl_easy *sdata,
                             struct h3_stream_ctx *stream,
                             void *user_data);

struct cf_qmux_visit_ctx {
  struct Curl_cfilter *cf;
  struct Curl_multi *multi;
  cf_qmux_svisit *cb;
  void *user_data;
};

static bool cf_qmux_stream_do(uint32_t mid, void *val, void *user_data)
{
  struct cf_qmux_visit_ctx *vctx = user_data;
  struct h3_stream_ctx *stream = val;
  struct Curl_easy *sdata = Curl_multi_get_easy(vctx->multi, mid);
  if(sdata)
    return vctx->cb(vctx->cf, sdata, stream, vctx->user_data);
  return TRUE;
}

static void cf_qmux_for_all_streams(struct Curl_cfilter *cf,
                                     struct Curl_multi *multi,
                                     cf_qmux_svisit *do_cb,
                                     void *user_data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct cf_qmux_visit_ctx vctx;
  vctx.cf = cf;
  vctx.multi = multi;
  vctx.cb = do_cb;
  vctx.user_data = user_data;
  Curl_uint32_hash_visit(&ctx->streams, cf_qmux_stream_do, &vctx);
}

static bool cf_qmux_do_resume(struct Curl_cfilter *cf,
                               struct Curl_easy *sdata,
                               struct h3_stream_ctx *stream,
                               void *user_data)
{
  (void)user_data;
  if(stream->quic_flow_blocked) {
    stream->quic_flow_blocked = FALSE;
    Curl_multi_mark_dirty(sdata);
    CURL_TRC_CF(sdata, cf, "[%" PRIu64 "] unblock", stream->id);
  }
  return TRUE;
}

static bool cf_qmux_do_expire(struct Curl_cfilter *cf,
                               struct Curl_easy *sdata,
                               struct h3_stream_ctx *stream,
                               void *user_data)
{
  (void)stream;
  (void)user_data;
  CURL_TRC_CF(sdata, cf, "conn closed, mark as dirty");
  stream->xfer_result = CURLE_SEND_ERROR;
  Curl_multi_mark_dirty(sdata);
  return TRUE;
}

static CURLcode h3_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(stream)
    return CURLE_OK;

  stream = curlx_calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_uint32_hash_set(&ctx->streams, data->mid, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void cf_qmux_stream_close(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  CURLcode result;

  if(ctx->qconn && !stream->closed) {
    quiche_conn_stream_shutdown(ctx->qconn, stream->id,
                                QUICHE_SHUTDOWN_READ, CURL_H3_NO_ERROR);
    if(!stream->send_closed) {
      quiche_conn_stream_shutdown(ctx->qconn, stream->id,
                                  QUICHE_SHUTDOWN_WRITE, CURL_H3_NO_ERROR);
      stream->send_closed = TRUE;
    }
    stream->closed = TRUE;
    result = cf_flush_egress(cf, data);
    if(result)
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] stream close, flush egress -> %d",
                  stream->id, result);
  }
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(stream) {
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] easy handle is done", stream->id);
    cf_qmux_stream_close(cf, data, stream);
    Curl_uint32_hash_remove(&ctx->streams, data->mid);
  }
}

static void cf_qmux_expire_conn_closed(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  DEBUGASSERT(data->multi);
  CURL_TRC_CF(data, cf, "conn closed, expire all transfers");
  cf_qmux_for_all_streams(cf, data->multi, cf_qmux_do_expire, NULL);
}

static void cf_qmux_write_hd(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct h3_stream_ctx *stream,
                              const char *buf, size_t blen, bool eos)
{
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp_hd(data, buf, blen, eos);
    if(stream->xfer_result)
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] error %d writing %zu "
                  "bytes of headers", stream->id, stream->xfer_result, blen);
  }
}

struct cb_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct h3_stream_ctx *stream;
};

static bool is_valid_h3_header(const uint8_t *hdr, size_t hlen)
{
  while(hlen--) {
    switch(*hdr++) {
    case '\n':
    case '\r':
    case '\0':
      return FALSE;
    }
  }
  return TRUE;
}

static int cb_each_header(uint8_t *name, size_t name_len,
                          uint8_t *value, size_t value_len,
                          void *argp)
{
  struct cb_ctx *x = argp;
  struct Curl_cfilter *cf = x->cf;
  struct Curl_easy *data = x->data;
  struct h3_stream_ctx *stream = x->stream;
  struct cf_qmux_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(!stream || stream->xfer_result)
    return 1; /* abort iteration */

  if((name_len == 7) && !strncmp(HTTP_PSEUDO_STATUS, (char *)name, 7) &&
     is_valid_h3_header(value, value_len)) {
    curlx_dyn_reset(&ctx->h1hdr);
    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)value, value_len);
    if(!result)
      result = curlx_dyn_addn(&ctx->h1hdr, STRCONST("HTTP/3 "));
    if(!result)
      result = curlx_dyn_addn(&ctx->h1hdr, (const char *)value, value_len);
    if(!result)
      result = curlx_dyn_addn(&ctx->h1hdr, STRCONST(" \r\n"));
    if(!result)
      cf_qmux_write_hd(cf, data, stream, curlx_dyn_ptr(&ctx->h1hdr),
                        curlx_dyn_len(&ctx->h1hdr), FALSE);
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] status: %s",
                stream->id, curlx_dyn_ptr(&ctx->h1hdr));
  }
  else {
    if(is_valid_h3_header(value, value_len) &&
       is_valid_h3_header(name, name_len)) {
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] header: %.*s: %.*s",
                  stream->id, (int)name_len, name,
                  (int)value_len, value);
      curlx_dyn_reset(&ctx->h1hdr);
      result = curlx_dyn_addn(&ctx->h1hdr, (const char *)name, name_len);
      if(!result)
        result = curlx_dyn_addn(&ctx->h1hdr, STRCONST(": "));
      if(!result)
        result = curlx_dyn_addn(&ctx->h1hdr, (const char *)value, value_len);
      if(!result)
        result = curlx_dyn_addn(&ctx->h1hdr, STRCONST("\r\n"));
      if(!result)
        cf_qmux_write_hd(cf, data, stream, curlx_dyn_ptr(&ctx->h1hdr),
                          curlx_dyn_len(&ctx->h1hdr), FALSE);
    }
    else
      CURL_TRC_CF(x->data, x->cf, "[%" PRIu64 "] ignore %zu bytes bad header",
                  stream->id, value_len + name_len);
  }

  if(result) {
    CURL_TRC_CF(x->data, x->cf, "[%" PRIu64 "] on header error %d",
                stream->id, result);
    if(!stream->xfer_result)
      stream->xfer_result = result;
  }
  return stream->xfer_result ? 1 : 0;
}

static CURLcode stream_resp_read(void *reader_ctx,
                                 unsigned char *buf, size_t len,
                                 size_t *pnread)
{
  struct cb_ctx *x = reader_ctx;
  struct cf_qmux_ctx *ctx = x->cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
  ssize_t nread;

  *pnread = 0;
  if(!stream)
    return CURLE_RECV_ERROR;

  nread = quiche_h3_recv_body(ctx->h3c, ctx->qconn, stream->id, buf, len);
  if(!curlx_sztouz(nread, pnread))
    return CURLE_AGAIN;
  return CURLE_OK;
}

static void cf_qmux_flush_body(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct h3_stream_ctx *stream)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  const uint8_t *buf;
  size_t blen;

  while(stream && !stream->xfer_result) {
    if(Curl_bufq_peek(&ctx->writebuf, &buf, &blen)) {
      stream->xfer_result = Curl_xfer_write_resp(
        data, (const char *)buf, blen, FALSE);
      Curl_bufq_skip(&ctx->writebuf, blen);
      if(stream->xfer_result) {
        CURL_TRC_CF(data, cf, "[%" PRIu64 "] error %d writing %zu bytes"
                    " of data", stream->id, stream->xfer_result, blen);
      }
    }
    else
      break;
  }
  Curl_bufq_reset(&ctx->writebuf);
}

static void cf_qmux_recv_body(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h3_stream_ctx *stream)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  size_t nread;
  struct cb_ctx cb_ctx;
  CURLcode result = CURLE_OK;

  if(!stream)
    return;

  cb_ctx.cf = cf;
  cb_ctx.data = data;
  cb_ctx.stream = stream;
  Curl_bufq_reset(&ctx->writebuf);
  while(!result) {
    result = Curl_bufq_slurp(&ctx->writebuf,
                             stream_resp_read, &cb_ctx, &nread);
    if(!result)
      cf_qmux_flush_body(cf, data, stream);
    else if(result == CURLE_AGAIN)
      break;
    else if(result) {
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] recv_body error %d",
                  stream->id, result);
      failf(data, "[%" PRIu64 "] Error %d in HTTP/3 response body for stream",
            stream->id, result);
      stream->closed = TRUE;
      stream->reset = TRUE;
      stream->send_closed = TRUE;
      if(!stream->xfer_result)
        stream->xfer_result = result;
    }
  }
  cf_qmux_flush_body(cf, data, stream);
}

static void cf_qmux_process_ev(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct h3_stream_ctx *stream,
                                quiche_h3_event *ev)
{
  if(!stream)
    return;

  switch(quiche_h3_event_type(ev)) {
  case QUICHE_H3_EVENT_HEADERS: {
    struct cb_ctx cb_ctx;
    stream->resp_got_header = TRUE;
    cb_ctx.cf = cf;
    cb_ctx.data = data;
    cb_ctx.stream = stream;
    quiche_h3_event_for_each_header(ev, cb_each_header, &cb_ctx);
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] <- [HEADERS]", stream->id);
    Curl_multi_mark_dirty(data);
    break;
  }
  case QUICHE_H3_EVENT_DATA:
    if(!stream->resp_hds_complete) {
      stream->resp_hds_complete = TRUE;
      cf_qmux_write_hd(cf, data, stream, "\r\n", 2, FALSE);
    }
    cf_qmux_recv_body(cf, data, stream);
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] <- [DATA]", stream->id);
    Curl_multi_mark_dirty(data);
    break;

  case QUICHE_H3_EVENT_RESET:
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] RESET", stream->id);
    stream->closed = TRUE;
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    /* TODO: quiche does not currently expose the stream error code
     * from RESET events. stream->error3 remains 0. */
    Curl_multi_mark_dirty(data);
    break;

  case QUICHE_H3_EVENT_FINISHED:
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] CLOSED", stream->id);
    if(!stream->resp_hds_complete) {
      stream->resp_hds_complete = TRUE;
      cf_qmux_write_hd(cf, data, stream, "\r\n", 2, TRUE);
    }
    stream->closed = TRUE;
    Curl_multi_mark_dirty(data);
    break;

  case QUICHE_H3_EVENT_GOAWAY: {
    struct cf_qmux_ctx *qmux_ctx = cf->ctx;
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] <- [GOAWAY]", stream->id);
    qmux_ctx->goaway = TRUE;
    break;
  }

  default:
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] recv, unhandled event %d",
                stream->id, quiche_h3_event_type(ev));
    break;
  }
}

struct cf_qmux_disp_ctx {
  uint64_t stream_id;
  struct Curl_cfilter *cf;
  struct Curl_multi *multi;
  quiche_h3_event *ev;
};

static bool cf_qmux_disp_event(uint32_t mid, void *val, void *user_data)
{
  struct cf_qmux_disp_ctx *dctx = user_data;
  struct h3_stream_ctx *stream = val;

  if(stream->id == dctx->stream_id) {
    struct Curl_easy *sdata = Curl_multi_get_easy(dctx->multi, mid);
    if(sdata)
      cf_qmux_process_ev(dctx->cf, sdata, stream, dctx->ev);
    return FALSE; /* stop iterating */
  }
  return TRUE;
}

static CURLcode cf_qmux_poll_events(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
  quiche_h3_event *ev;

  while(ctx->h3c) {
    int64_t rv = quiche_h3_conn_poll(ctx->h3c, ctx->qconn, &ev);
    if(rv == QUICHE_H3_ERR_DONE) {
      break;
    }
    else if(rv < 0) {
      CURL_TRC_CF(data, cf, "error poll: %" PRId64, rv);
      return CURLE_HTTP3;
    }
    else {
      stream = H3_STREAM_CTX(ctx, data);
      if(stream && stream->id == (uint64_t)rv) {
        cf_qmux_process_ev(cf, data, stream, ev);
        quiche_h3_event_free(ev);
        if(stream->xfer_result)
          return stream->xfer_result;
      }
      else {
        struct cf_qmux_disp_ctx dctx;
        dctx.stream_id = (uint64_t)rv;
        dctx.cf = cf;
        dctx.multi = data->multi;
        dctx.ev = ev;
        Curl_uint32_hash_visit(&ctx->streams, cf_qmux_disp_event, &dctx);
        quiche_h3_event_free(ev);
      }
    }
  }
  return CURLE_OK;
}

/*
 * cf_process_ingress: read data from TLS (SSL_read) and feed into quiche.
 * Uses dummy RecvInfo since QMux ignores addressing internally.
 */
static CURLcode cf_process_ingress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  uint8_t buf[QMUX_BUF_SIZE];
  int pkts = 0;

  /* Dummy address for RecvInfo — QMux ignores these */
  struct sockaddr_in dummy_addr;
  quiche_recv_info recv_info;

  DEBUGASSERT(ctx->qconn);

  memset(&dummy_addr, 0, sizeof(dummy_addr));
  dummy_addr.sin_family = AF_INET;
  recv_info.from = (struct sockaddr *)&dummy_addr;
  recv_info.from_len = sizeof(dummy_addr);
  recv_info.to = (struct sockaddr *)&dummy_addr;
  recv_info.to_len = sizeof(dummy_addr);

  while(1) {
    size_t nread = 0;
    ssize_t rv;
    CURLcode r;

    /* Read from the SSL filter below */
    r = Curl_conn_cf_recv(cf->next, data, (char *)buf, sizeof(buf), &nread);
    if(r == CURLE_AGAIN || nread == 0) {
      break; /* no more data available right now */
    }
    if(r) {
      CURL_TRC_CF(data, cf, "ingress, recv from SSL error: %d", r);
      return r;
    }

    if(!ctx->first_byte_at.tv_sec && !ctx->first_byte_at.tv_usec)
      ctx->first_byte_at = *Curl_pgrs_now(data);

    rv = quiche_conn_recv(ctx->qconn, buf, nread, &recv_info);
    if(rv < 0) {
      if(rv == QUICHE_ERR_DONE) {
        if(quiche_conn_is_draining(ctx->qconn)) {
          CURL_TRC_CF(data, cf, "ingress, connection is draining");
          return CURLE_RECV_ERROR;
        }
        if(quiche_conn_is_closed(ctx->qconn)) {
          CURL_TRC_CF(data, cf, "ingress, connection is closed");
          return CURLE_RECV_ERROR;
        }
        CURL_TRC_CF(data, cf, "ingress, quiche is DONE");
        break;
      }
      else {
        failf(data, "quiche_conn_recv returned %zd", rv);
        return CURLE_RECV_ERROR;
      }
    }
    ++pkts;
  }

  if(pkts > 0) {
    /* quiche digested ingress data. It might have opened flow control
     * windows again. */
    DEBUGASSERT(data->multi);
    cf_qmux_for_all_streams(cf, data->multi, cf_qmux_do_resume, NULL);
  }
  return cf_qmux_poll_events(cf, data);
}

/*
 * cf_flush_egress: drain quiche_conn_send() and write to TLS (SSL_write).
 * No GSO, no packet bursting — just loop until QUICHE_ERR_DONE.
 */
static CURLcode cf_flush_egress(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  uint8_t out[QMUX_BUF_SIZE];
  int64_t expiry_ns;
  int64_t timeout_ns;

  expiry_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if(!expiry_ns) {
    quiche_conn_on_timeout(ctx->qconn);
    if(quiche_conn_is_closed(ctx->qconn)) {
      if(quiche_conn_is_timed_out(ctx->qconn))
        failf(data, "connection closed by idle timeout");
      else
        failf(data, "connection closed by server");
      cf_qmux_expire_conn_closed(cf, data);
      return CURLE_SEND_ERROR;
    }
  }

  /* First, flush any partially-sent egress data from previous call */
  while(ctx->egress_buf && ctx->egress_buf_sent < ctx->egress_buf_len) {
    size_t nsent = 0;
    CURLcode r = Curl_conn_cf_send(cf->next, data,
                   (const char *)ctx->egress_buf + ctx->egress_buf_sent,
                   ctx->egress_buf_len - ctx->egress_buf_sent,
                   FALSE, &nsent);
    if(r == CURLE_AGAIN) {
      Curl_expire(data, 1, EXPIRE_QUIC);
      goto out;
    }
    if(r) {
      failf(data, "QMux egress send failed: %d", r);
      return CURLE_SEND_ERROR;
    }
    ctx->egress_buf_sent += nsent;
  }
  /* Previous buffer fully sent, free it */
  if(ctx->egress_buf) {
    curlx_free(ctx->egress_buf);
    ctx->egress_buf = NULL;
    ctx->egress_buf_len = 0;
    ctx->egress_buf_sent = 0;
  }

  /* Now generate new egress data from quiche */
  while(1) {
    quiche_send_info send_info;
    ssize_t written = quiche_conn_send(ctx->qconn, out, sizeof(out),
                                       &send_info);
    if(written == QUICHE_ERR_DONE)
      break;

    if(written < 0) {
      failf(data, "quiche_conn_send returned %zd", written);
      return CURLE_SEND_ERROR;
    }

    /* Write the QMux record(s) to the SSL filter below */
    {
      const uint8_t *p = out;
      size_t remaining = (size_t)written;
      while(remaining > 0) {
        size_t nsent = 0;
        CURLcode r = Curl_conn_cf_send(cf->next, data, (const char *)p,
                                       remaining, FALSE, &nsent);
        if(r == CURLE_AGAIN) {
          /* Save unsent portion for next flush call */
          ctx->egress_buf = curlx_memdup((const char *)p, remaining);
          if(!ctx->egress_buf)
            return CURLE_OUT_OF_MEMORY;
          ctx->egress_buf_len = remaining;
          ctx->egress_buf_sent = 0;
          Curl_expire(data, 1, EXPIRE_QUIC);
          goto out;
        }
        if(r) {
          failf(data, "QMux egress send failed: %d", r);
          return CURLE_SEND_ERROR;
        }
        p += nsent;
        remaining -= nsent;
      }
    }
  }

out:
  timeout_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if(timeout_ns % 1000000)
    timeout_ns += 1000000;
  Curl_expire(data, (timeout_ns / 1000000), EXPIRE_QUIC);
  return CURLE_OK;
}

static CURLcode recv_closed_stream(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   size_t *pnread)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;

  DEBUGASSERT(stream);
  *pnread = 0;
  if(stream->reset) {
    if(stream->error3 == CURL_H3_ERR_REQUEST_REJECTED) {
      infof(data, "HTTP/3 stream %" PRIu64 " refused by server, try again "
            "on a new connection", stream->id);
      connclose(cf->conn, "REFUSED_STREAM");
      data->state.refused_stream = TRUE;
      return CURLE_RECV_ERROR;
    }
    else if(stream->resp_hds_complete && data->req.no_body) {
        CURL_TRC_CF(data, cf, "[%" PRIu64 "] error after response headers, "
                    "but we did not want a body anyway, ignore error 0x%"
                    PRIx64 " %s", stream->id, stream->error3,
                    vquic_h3_err_str(stream->error3));
        return CURLE_OK;
    }
    failf(data, "HTTP/3 stream %" PRIu64 " reset by server (error 0x%" PRIx64
          " %s)", stream->id, stream->error3,
          vquic_h3_err_str(stream->error3));
    result = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] cf_recv, was reset -> %d",
                stream->id, result);
  }
  else if(!stream->resp_got_header) {
    failf(data, "HTTP/3 stream %" PRIu64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    result = CURLE_HTTP3;
  }
  return result;
}

static CURLcode cf_qmux_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t blen, size_t *pnread)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;

  *pnread = 0;
  (void)buf;
  (void)blen;

  if(!stream)
    return CURLE_RECV_ERROR;

  result = cf_process_ingress(cf, data);
  if(result) {
    CURL_TRC_CF(data, cf, "cf_recv, error on ingress");
    goto out;
  }

  if(stream->xfer_result) {
    cf_qmux_stream_close(cf, data, stream);
    result = stream->xfer_result;
    goto out;
  }
  else if(stream->closed)
    result = recv_closed_stream(cf, data, pnread);
  else if(quiche_conn_is_draining(ctx->qconn)) {
    failf(data, "QUIC connection is draining");
    result = CURLE_HTTP3;
  }
  else
    result = CURLE_AGAIN;

out:
  result = Curl_1st_fatal(result, cf_flush_egress(cf, data));
  if(*pnread > 0)
    ctx->data_recvd += *pnread;
  CURL_TRC_CF(data, cf, "[%" PRIu64 "] cf_recv(len=%zu) -> %d, %zu, total=%"
              FMT_OFF_T, stream->id, blen, result, *pnread, ctx->data_recvd);
  return result;
}

static CURLcode cf_qmux_send_body(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_stream_ctx *stream,
                                   const uint8_t *buf, size_t len, bool eos,
                                   size_t *pnwritten)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  ssize_t rv;

  *pnwritten = 0;
  rv = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->id,
                           (uint8_t *)CURL_UNCONST(buf), len, eos);
  if(rv == QUICHE_H3_ERR_DONE || (rv == 0 && len > 0)) {
    if(!quiche_conn_stream_writable(ctx->qconn, stream->id, len)) {
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] send_body(len=%zu) "
                  "-> window exhausted", stream->id, len);
      stream->quic_flow_blocked = TRUE;
    }
    return CURLE_AGAIN;
  }
  else if(rv == QUICHE_H3_TRANSPORT_ERR_INVALID_STREAM_STATE) {
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] send_body(len=%zu) "
                "-> invalid stream state", stream->id, len);
    return CURLE_HTTP3;
  }
  else if(rv == QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE) {
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] send_body(len=%zu) -> exceeds size",
                stream->id, len);
    return CURLE_SEND_ERROR;
  }
  else if(!curlx_sztouz(rv, pnwritten)) {
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] send_body(len=%zu) -> quiche err %zd",
                stream->id, len, rv);
    return CURLE_SEND_ERROR;
  }
  else {
    if(eos && (len == *pnwritten))
      stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] send body(len=%zu, eos=%d) -> %zu",
                stream->id, len, stream->send_closed, *pnwritten);
    return CURLE_OK;
  }
}

static CURLcode h3_open_stream(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const uint8_t *buf, size_t blen, bool eos,
                               size_t *pnwritten)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t nheader, i;
  int64_t rv;
  struct dynhds h2_headers;
  quiche_h3_header *nva = NULL;
  CURLcode result = CURLE_OK;

  *pnwritten = 0;
  if(!stream) {
    result = h3_data_setup(cf, data);
    if(result)
      return result;
    stream = H3_STREAM_CTX(ctx, data);
    DEBUGASSERT(stream);
  }

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  DEBUGASSERT(stream);

  result = Curl_h1_req_parse_read(&stream->h1, buf, blen, NULL,
                                  !data->state.http_ignorecustom ?
                                  data->set.str[STRING_CUSTOMREQUEST] : NULL,
                                  0, pnwritten);
  if(result)
    goto out;
  if(!stream->h1.done) {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  result = Curl_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if(result)
    goto out;

  Curl_h1_req_parse_free(&stream->h1);

  nheader = Curl_dynhds_count(&h2_headers);
  nva = curlx_malloc(sizeof(quiche_h3_header) * nheader);
  if(!nva) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < nheader; ++i) {
    struct dynhds_entry *e = Curl_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].name_len = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].value_len = e->valuelen;
  }

  buf += *pnwritten;
  blen -= *pnwritten;

  if(eos && !blen)
    stream->send_closed = TRUE;

  rv = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                              stream->send_closed);
  CURL_TRC_CF(data, cf, "quiche_send_request() -> %" PRId64, rv);
  if(rv < 0) {
    if(QUICHE_H3_ERR_STREAM_BLOCKED == rv) {
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] blocked", stream->id);
      stream->quic_flow_blocked = TRUE;
      result = CURLE_AGAIN;
      goto out;
    }
    else {
      CURL_TRC_CF(data, cf, "send_request(%s) -> %" PRId64,
                  Curl_bufref_ptr(&data->state.url), rv);
    }
    result = CURLE_SEND_ERROR;
    goto out;
  }

  DEBUGASSERT(!stream->opened);
  stream->id = (uint64_t)rv;
  stream->opened = TRUE;
  stream->closed = FALSE;
  stream->reset = FALSE;

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" PRIu64 "] OPENED stream for %s",
          stream->id, Curl_bufref_ptr(&data->state.url));
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" PRIu64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].name_len, nva[i].name,
            (int)nva[i].value_len, nva[i].value);
    }
  }

  if(blen) {
    size_t nwritten;
    CURLcode r2 = CURLE_OK;

    r2 = cf_qmux_send_body(cf, data, stream, buf, blen, eos, &nwritten);
    if(r2 && (r2 != CURLE_AGAIN)) {
      result = r2;
    }
    else if(nwritten > 0) {
      *pnwritten += nwritten;
    }
  }

out:
  curlx_free(nva);
  Curl_dynhds_free(&h2_headers);
  return result;
}

static CURLcode cf_qmux_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const uint8_t *buf, size_t len, bool eos,
                              size_t *pnwritten)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result;

  *pnwritten = 0;

  result = cf_process_ingress(cf, data);
  if(result)
    goto out;

  if(!stream || !stream->opened) {
    result = h3_open_stream(cf, data, buf, len, eos, pnwritten);
    if(result)
      goto out;
    stream = H3_STREAM_CTX(ctx, data);
  }
  else if(stream->xfer_result) {
    cf_qmux_stream_close(cf, data, stream);
    result = stream->xfer_result;
  }
  else if(stream->closed) {
    if(stream->resp_hds_complete) {
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] discarding data "
                  "on closed stream with response", stream->id);
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" PRIu64 "] send_body(len=%zu) "
                "-> stream closed", stream->id, len);
    result = CURLE_HTTP3;
    goto out;
  }
  else {
    result = cf_qmux_send_body(cf, data, stream, buf, len, eos, pnwritten);
  }

out:
  result = Curl_1st_fatal(result, cf_flush_egress(cf, data));

  CURL_TRC_CF(data, cf, "[%" PRIu64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : (uint64_t)~0, len,
              result, *pnwritten);
  return result;
}

static bool stream_is_writable(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  return stream && (quiche_conn_stream_writable(
    ctx->qconn, stream->id, 1) > 0);
}

static CURLcode cf_qmux_adjust_pollset(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  bool want_recv, want_send;
  CURLcode result = CURLE_OK;

  if(!ctx->qconn) {
    /* Not yet in QMux phase — delegate to SSL/TCP below */
    if(cf->next)
      return cf->next->cft->adjust_pollset(cf->next, data, ps);
    return CURLE_OK;
  }

  Curl_pollset_check(data, ps, ctx->sockfd, &want_recv, &want_send);
  if(want_recv || want_send) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    bool c_exhaust, s_exhaust;

    c_exhaust = FALSE;
    s_exhaust = want_send && stream && stream->opened &&
                (stream->quic_flow_blocked || !stream_is_writable(cf, data));
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                (ctx->egress_buf != NULL);

    result = Curl_pollset_set(data, ps, ctx->sockfd, want_recv, want_send);
  }
  return result;
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  (void)cf;
  if(!pause) {
    Curl_multi_mark_dirty(data);
  }
  return CURLE_OK;
}

static CURLcode cf_qmux_cntrl(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               int event, int arg1, void *arg2)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(stream && !stream->send_closed) {
      unsigned char body[1];
      size_t sent;

      stream->send_closed = TRUE;
      body[0] = 'X';
      result = cf_qmux_send(cf, data, body, 0, TRUE, &sent);
      CURL_TRC_CF(data, cf, "[%" PRIu64 "] DONE_SEND -> %d, %zu",
                  stream->id, result, sent);
    }
    break;
  }
  case CF_CTRL_CONN_INFO_UPDATE:
    if(!cf->sockindex && cf->connected) {
      cf->conn->httpversion_seen = 30;
      Curl_conn_set_multiplex(cf->conn);
    }
    break;
  default:
    break;
  }
  return result;
}

/*
 * cf_qmux_connect: connection state machine
 *
 * 1. Wait for SSL → TCP below to connect (curl's SSL filter handles TLS)
 * 2. Create quiche config+connection in QMux mode
 * 3. Exchange QMux transport parameters until established
 * 4. Create H3 connection
 */
static CURLcode cf_qmux_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;

  /* First, wait for the SSL → TCP sub-chain to connect */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
    *done = FALSE;
    CURL_TRC_CF(data, cf, "SSL+TCP sub-chain connected");
  }

  /* SSL is connected. Now do QMux handshake. */
  {
    if(!ctx->qconn) {
      /* Create the quiche config with QMux mode enabled */
      const struct Curl_sockaddr_ex *sockaddr = NULL;
      struct sockaddr_in dummy_local;

      ctx->cfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
      if(!ctx->cfg) {
        failf(data, "cannot create quiche config");
        return CURLE_FAILED_INIT;
      }

      quiche_config_enable_qmux(ctx->cfg, true);
      quiche_config_enable_pacing(ctx->cfg, FALSE);
      quiche_config_set_max_idle_timeout(ctx->cfg, 30000);
      quiche_config_set_initial_max_data(ctx->cfg, (1 * 1024 * 1024));
      quiche_config_set_initial_max_streams_bidi(ctx->cfg, QUIC_MAX_STREAMS);
      quiche_config_set_initial_max_streams_uni(ctx->cfg, QUIC_MAX_STREAMS);
      quiche_config_set_initial_max_stream_data_bidi_local(ctx->cfg,
        H3_STREAM_WINDOW_SIZE);
      quiche_config_set_initial_max_stream_data_bidi_remote(ctx->cfg,
        H3_STREAM_WINDOW_SIZE);
      quiche_config_set_initial_max_stream_data_uni(ctx->cfg,
        H3_STREAM_WINDOW_SIZE);
      quiche_config_set_disable_active_migration(ctx->cfg, TRUE);
      quiche_config_set_max_connection_window(ctx->cfg,
        10 * QUIC_MAX_STREAMS * H3_STREAM_WINDOW_SIZE);
      quiche_config_set_max_stream_window(ctx->cfg,
        10 * H3_STREAM_WINDOW_SIZE);
      quiche_config_set_application_protos(ctx->cfg,
        (uint8_t *)CURL_UNCONST(
          QUICHE_H3_OVER_QMUX_APPLICATION_PROTOCOL),
        sizeof(QUICHE_H3_OVER_QMUX_APPLICATION_PROTOCOL) - 1);

      result = Curl_rand(data, ctx->scid, sizeof(ctx->scid));
      if(result)
        return result;

      /* Walk the filter chain to find the TCP socket filter.
       * We go through SSL → TCP; Curl_cf_socket_peek only works
       * on socket filters directly. */
      {
        struct Curl_cfilter *f;
        CURLcode peek_result = CURLE_FAILED_INIT;
        for(f = cf->next; f; f = f->next) {
          peek_result = Curl_cf_socket_peek(f, data, &ctx->sockfd,
                                            &sockaddr, NULL);
          if(!peek_result)
            break;
        }
        if(peek_result)
          return CURLE_QUIC_CONNECT_ERROR;
      }

      /* Dummy local address — QMux ignores it */
      memset(&dummy_local, 0, sizeof(dummy_local));
      dummy_local.sin_family = AF_INET;

      /* Use quiche_connect() instead of quiche_conn_new_with_tls().
       * QMux does not pass SSL* to quiche — TLS is handled by
       * the SSL filter below us. */
      ctx->qconn = quiche_connect(cf->conn->origin->hostname,
                                  ctx->scid, sizeof(ctx->scid),
                                  (struct sockaddr *)&dummy_local,
                                  sizeof(dummy_local),
                                  &sockaddr->curl_sa_addr,
                                  sockaddr->addrlen,
                                  ctx->cfg);
      if(!ctx->qconn) {
        failf(data, "cannot create quiche QMux connection");
        return CURLE_OUT_OF_MEMORY;
      }

      /* Known to not work on Windows */
#if !defined(_WIN32) && defined(HAVE_QUICHE_CONN_SET_QLOG_FD)
      {
        int qfd;
        (void)Curl_qlogdir(data, ctx->scid, sizeof(ctx->scid), &qfd);
        if(qfd != -1)
          quiche_conn_set_qlog_fd(ctx->qconn, qfd,
                                  "qlog title", "curl qmux qlog");
      }
#endif

      ctx->started_at = *Curl_pgrs_now(data);

      /* Initial flush to send transport parameters */
      result = cf_flush_egress(cf, data);
      if(result)
        return result;
    }

    /* Process incoming data and flush outgoing until established */
    result = cf_process_ingress(cf, data);
    if(result)
      return result;

    result = cf_flush_egress(cf, data);
    if(result)
      return result;

    if(quiche_conn_is_established(ctx->qconn)) {
      const uint8_t *app_proto;
      size_t app_proto_len;

      ctx->handshake_at = *Curl_pgrs_now(data);
      CURL_TRC_CF(data, cf, "QMux handshake complete after %"
                  FMT_TIMEDIFF_T "ms",
                  curlx_ptimediff_ms(&ctx->handshake_at, &ctx->started_at));

      /* Verify that the application protocol matches what we expect */
      quiche_conn_application_proto(ctx->qconn, &app_proto, &app_proto_len);
      CURL_TRC_CF(data, cf, "QMux negotiated app proto: %.*s",
                  (int)app_proto_len, app_proto);

      ctx->h3config = quiche_h3_config_new();
      if(!ctx->h3config) {
        return CURLE_OUT_OF_MEMORY;
      }

      ctx->h3c = quiche_h3_conn_new_with_transport(ctx->qconn,
                                                    ctx->h3config);
      if(!ctx->h3c) {
        return CURLE_OUT_OF_MEMORY;
      }

      cf->connected = TRUE;
      *done = TRUE;
      CURL_TRC_CF(data, cf, "QMux connected, HTTP/3 ready");
    }
    else if(quiche_conn_is_draining(ctx->qconn)) {
      result = CURLE_WEIRD_SERVER_REPLY;
    }
  }

#ifdef CURLVERBOSE
  if(result && result != CURLE_AGAIN) {
    infof(data, "QMux connect failed: %s", curl_easy_strerror(result));
  }
#endif
  return result;
}

static CURLcode cf_qmux_shutdown(struct Curl_cfilter *cf,
                                  struct Curl_easy *data, bool *done)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  if(!ctx->shutdown_started) {
    int err;

    ctx->shutdown_started = TRUE;
    err = quiche_conn_close(ctx->qconn, TRUE, 0, NULL, 0);
    if(err && err != QUICHE_ERR_DONE) {
      CURL_TRC_CF(data, cf, "error %d adding shutdown packet, "
                  "aborting shutdown", err);
      result = CURLE_SEND_ERROR;
      goto out;
    }
  }

  /* Flush pending egress */
  result = cf_flush_egress(cf, data);
  if(result)
    goto out;

  /* Only mark done if all egress data has been fully sent */
  if(ctx->egress_buf && ctx->egress_buf_sent < ctx->egress_buf_len) {
    CURL_TRC_CF(data, cf, "shutdown sending blocked");
    Curl_expire(data, 1, EXPIRE_QUIC);
  }
  else {
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
  }

out:
  return result;
}

static void cf_qmux_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  if(cf->ctx) {
    bool done;
    (void)cf_qmux_shutdown(cf, data, &done);
    cf_qmux_ctx_close(cf->ctx);
    cf->connected = FALSE;
  }
}

static void cf_qmux_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  (void)data;
  if(cf->ctx) {
    cf_qmux_ctx_close(cf->ctx);
    cf_qmux_ctx_free(cf->ctx);
    cf->ctx = NULL;
  }
}

static CURLcode cf_qmux_query(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               int query, int *pres1, void *pres2)
{
  struct cf_qmux_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    uint64_t max_streams = cf->conn->attached_xfers;
    if(!ctx->goaway && ctx->qconn) {
      max_streams += quiche_conn_peer_streams_left_bidi(ctx->qconn);
    }
    *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    CURL_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%u in use)",
                cf->conn->connection_id, *pres1, cf->conn->attached_xfers);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->first_byte_at.tv_sec || ctx->first_byte_at.tv_usec) {
      timediff_t ms = curlx_ptimediff_ms(&ctx->first_byte_at,
                                         &ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->started_at.tv_sec || ctx->started_at.tv_usec)
      *when = ctx->started_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 30;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO:
    /* Delegate to the SSL filter below */
    break;
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = cf->connected ? "h3" : NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_qmux_conn_is_alive(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *input_pending)
{
  struct cf_qmux_ctx *ctx = cf->ctx;
  bool alive = TRUE;

  *input_pending = FALSE;
  if(!ctx->qconn)
    return FALSE;

  if(quiche_conn_is_closed(ctx->qconn)) {
    if(quiche_conn_is_timed_out(ctx->qconn))
      CURL_TRC_CF(data, cf, "connection was closed due to idle timeout");
    else
      CURL_TRC_CF(data, cf, "connection is closed");
    return FALSE;
  }

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    return FALSE;

  if(*input_pending) {
    *input_pending = FALSE;
    if(cf_process_ingress(cf, data))
      alive = FALSE;
    else {
      alive = TRUE;
    }
  }

  return alive;
}

struct Curl_cftype Curl_cft_http3_qmux = {
  "HTTP/3-QMUX",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP,
  0,
  cf_qmux_destroy,
  cf_qmux_connect,
  cf_qmux_close,
  cf_qmux_shutdown,
  cf_qmux_adjust_pollset,
  Curl_cf_def_data_pending,
  cf_qmux_send,
  cf_qmux_recv,
  cf_qmux_cntrl,
  cf_qmux_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_qmux_query,
};

CURLcode Curl_cf_qmux_create(struct Curl_cfilter **pcf,
                              struct Curl_easy *data,
                              struct connectdata *conn,
                              struct Curl_sockaddr_ex *addr,
                              uint8_t transport)
{
  struct cf_qmux_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  (void)transport;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_qmux_ctx_init(ctx);

  result = Curl_cf_create(&cf, &Curl_cft_http3_qmux, ctx);
  if(result)
    goto out;
  cf->conn = conn;

  /* Create TCP filter at the bottom */
  result = Curl_cf_tcp_create(&cf->next, data, conn, addr, TRNSPRT_TCP);
  if(result)
    goto out;
  cf->next->conn = cf->conn;
  cf->next->sockindex = cf->sockindex;

  /* Insert SSL filter between QMux and TCP with h3qx-01 ALPN.
   * Chain becomes: QMux → SSL → TCP */
  {
    static const struct alpn_spec ALPN_SPEC_QMUX = { { "h3qx-01" }, 1 };
    result = Curl_cf_ssl_insert_after_alpn(cf, data, &ALPN_SPEC_QMUX);
    if(result)
      goto out;
  }

out:
  *pcf = (!result) ? cf : NULL;
  if(result) {
    if(cf)
      Curl_conn_cf_discard_chain(&cf, data);
    else if(ctx)
      cf_qmux_ctx_free(ctx);
  }

  return result;
}

#endif /* !CURL_DISABLE_HTTP && USE_QUICHE */
