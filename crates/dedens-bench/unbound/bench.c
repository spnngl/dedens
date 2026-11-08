/*
 * Unbound's codec on the inputs of the Rust benches (D14): the captured
 * responses of testdata/proto/ and the generated zone of
 * `examples/zone.rs`, read from the file given as the only argument. `just
 * bench-unbound` builds it against a pinned Unbound release.
 *
 * - parse:  parse_packet, Unbound's first pass: it checks the structure and
 * notes where each RRset's records lie in the packet, without decoding RDATA
 * (dedens has no such pass: `decode_reusing` also checks every RDATA).
 * - decode: reply_info_parse, what Unbound does with an upstream answer: the
 * first pass, EDNS, then the RRsets copied out of the packet with names
 * decompressed (closest to an owned decode).
 * - encode: reply_info_encode with the OPT record, into a reused buffer, names
 * compressed.
 * - zone:   sldns_fp2wire_rr_buf over the zone, one record at a time, as
 * auth-zone does.
 *
 * Prints the median nanoseconds per operation of 101 samples, each of at least
 * 1 ms.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sldns/rrdef.h"
#include "sldns/sbuffer.h"
#include "sldns/str2wire.h"
#include "util/alloc.h"
#include "util/data/msgencode.h"
#include "util/data/msgparse.h"
#include "util/data/msgreply.h"
#include "util/net_help.h"
#include "util/regional.h"

#define SAMPLES 101

static const char *const cases[] = {"a", "mx", "txt_large"};

typedef void (*bench_fn)(void *arg);

static void die(const char *what) {
  fprintf(stderr, "unbound bench: %s\n", what);
  exit(1);
}

static double now_ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
    die("clock_gettime");
  return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int cmp_double(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}

/* Median nanoseconds per call of f(arg). */
static double measure(bench_fn f, void *arg) {
  double samples[SAMPLES];
  size_t iters = 1;
  double start;
  size_t i, s;
  /* Calibrate: double the iterations until one sample lasts 1 ms. */
  for (;;) {
    start = now_ns();
    for (i = 0; i < iters; i++)
      f(arg);
    if (now_ns() - start >= 1e6)
      break;
    iters *= 2;
  }
  for (s = 0; s < SAMPLES; s++) {
    start = now_ns();
    for (i = 0; i < iters; i++)
      f(arg);
    samples[s] = (now_ns() - start) / (double)iters;
  }
  qsort(samples, SAMPLES, sizeof(samples[0]), cmp_double);
  return samples[SAMPLES / 2];
}

static size_t read_file(const char *path, char **out) {
  FILE *f = fopen(path, "rb");
  long len;
  if (!f || fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 ||
      fseek(f, 0, SEEK_SET) != 0)
    die(path);
  if (!(*out = malloc((size_t)len + 1)) ||
      fread(*out, 1, (size_t)len, f) != (size_t)len)
    die(path);
  (*out)[len] = 0;
  fclose(f);
  return (size_t)len;
}

struct message {
  sldns_buffer *pkt;
  sldns_buffer *out;
  struct regional *region;
  struct alloc_cache *alloc;
  struct query_info qinfo;
  struct reply_info *rep;
  struct edns_data edns;
  uint16_t id, flags;
};

static void bench_parse(void *arg) {
  struct message *m = arg;
  struct msg_parse *msg = regional_alloc(m->region, sizeof(*msg));
  if (!msg)
    die("regional_alloc");
  memset(msg, 0, sizeof(*msg));
  sldns_buffer_set_position(m->pkt, 0);
  if (parse_packet(m->pkt, msg, m->region) != 0)
    die("parse_packet");
  regional_free_all(m->region);
}

static void bench_decode(void *arg) {
  struct message *m = arg;
  struct query_info qinfo;
  struct reply_info *rep;
  struct edns_data edns;
  if (reply_info_parse(m->pkt, m->alloc, &qinfo, &rep, m->region, &edns) != 0)
    die("reply_info_parse");
  query_info_clear(&qinfo);
  reply_info_parsedelete(rep, m->alloc);
  regional_free_all(m->region);
}

static void bench_encode(void *arg) {
  struct message *m = arg;
  if (!reply_info_encode(&m->qinfo, m->rep, m->id, m->flags, m->out, 0,
                         m->region, 65535, (int)(m->edns.bits & EDNS_DO), 0))
    die("reply_info_encode");
  attach_edns_record(m->out, &m->edns);
  regional_free_all(m->region);
}

struct zone {
  char *text;
  size_t len;
  size_t records;
};

static void bench_zone(void *arg) {
  struct zone *z = arg;
  struct sldns_file_parse_state state;
  uint8_t rr[LDNS_RR_BUF_SIZE];
  size_t rr_len, dname_len, records = 0;
  int status;
  FILE *in = fmemopen(z->text, z->len, "r");
  if (!in)
    die("fmemopen");
  memset(&state, 0, sizeof(state));
  state.default_ttl = 3600;
  state.lineno = 1;
  while (!feof(in)) {
    rr_len = sizeof(rr);
    dname_len = 0;
    if ((status = sldns_fp2wire_rr_buf(in, rr, &rr_len, &dname_len, &state)) !=
        0) {
      fprintf(stderr, "unbound bench: zone line %d: %s\n", state.lineno,
              sldns_get_errorstr_parse(status));
      exit(1);
    }
    if (rr_len != 0)
      records++;
  }
  fclose(in);
  z->records = records;
}

int main(int argc, char **argv) {
  struct alloc_cache super_alloc, alloc;
  struct message m;
  struct zone z;
  struct regional *setup;
  size_t i;
  if (argc != 2)
    die("usage: bench ZONE_FILE");

  alloc_init(&super_alloc, NULL, 0);
  alloc_init(&alloc, &super_alloc, 1);
  memset(&m, 0, sizeof(m));
  m.alloc = &alloc;
  if (!(m.pkt = sldns_buffer_new(65535)) ||
      !(m.out = sldns_buffer_new(65535)) || !(m.region = regional_create()))
    die("allocation");

  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char path[4096];
    char *data;
    size_t len;
    int n = snprintf(path, sizeof(path),
                     "%s/../../testdata/proto/%s.bin", BENCH_DIR,
                     cases[i]);
    if (n < 0 || (size_t)n >= sizeof(path))
      die("test data path longer than 4095 bytes: move the checkout");
    len = read_file(path, &data);
    sldns_buffer_clear(m.pkt);
    sldns_buffer_write(m.pkt, data, len);
    sldns_buffer_flip(m.pkt);
    free(data);
    m.id = sldns_buffer_read_u16_at(m.pkt, 0);
    m.flags = sldns_buffer_read_u16_at(m.pkt, 2);

    printf("parse_unbound/%s\t%.0f ns\n", cases[i], measure(bench_parse, &m));
    printf("decode_unbound/%s\t%.0f ns\n", cases[i], measure(bench_decode, &m));

    /* Encode keeps one decoded reply, its EDNS options in a region the encoder
     * does not free. */
    if (!(setup = regional_create()))
      die("allocation");
    if (reply_info_parse(m.pkt, m.alloc, &m.qinfo, &m.rep, setup, &m.edns) != 0)
      die("reply_info_parse");
    printf("encode_unbound/%s\t%.0f ns\n", cases[i], measure(bench_encode, &m));
    query_info_clear(&m.qinfo);
    reply_info_parsedelete(m.rep, m.alloc);
    regional_destroy(setup);
  }

  z.len = read_file(argv[1], &z.text);
  bench_zone(&z);
  printf("zone_unbound (%zu records)\t%.2f ms\n", z.records,
         measure(bench_zone, &z) / 1e6);

  free(z.text);
  regional_destroy(m.region);
  sldns_buffer_free(m.pkt);
  sldns_buffer_free(m.out);
  alloc_clear(&alloc);
  alloc_clear(&super_alloc);
  return 0;
}
