#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include <caml/alloc.h>
#include <caml/bigarray.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/socketaddr.h>
#include <caml/unixsupport.h>

#ifndef Max_young_wosize
#include <caml/config.h>
#endif

/* Faraday.iovec = { buffer : bigstring; off : int; len : int } */
#define IOVEC_BUFFER(v) Field((v), 0)
#define IOVEC_OFF(v) Long_val(Field((v), 1))
#define IOVEC_LEN(v) Long_val(Field((v), 2))

static struct iovec *ocaml_quic_fill_iovecs(value viovecs,
                                            struct iovec *small_iov,
                                            size_t small_cap,
                                            mlsize_t *count_out) {
  struct iovec *iov = small_iov;
  size_t cap = small_cap;
  mlsize_t count = 0;
  value cur = viovecs;

  while (cur != Val_emptylist) {
    if ((size_t)count == cap) {
      size_t new_cap = cap * 2;
      struct iovec *new_iov = caml_stat_alloc_noexc(new_cap * sizeof(struct iovec));
      if (new_iov == NULL) {
        if (iov != small_iov) caml_stat_free(iov);
        caml_raise_out_of_memory();
      }
      memcpy(new_iov, iov, count * sizeof(struct iovec));
      if (iov != small_iov) caml_stat_free(iov);
      iov = new_iov;
      cap = new_cap;
    }

    value viov = Field(cur, 0);
    struct caml_ba_array *ba = Caml_ba_array_val(IOVEC_BUFFER(viov));
    char *base = (char *)ba->data + IOVEC_OFF(viov);
    iov[count].iov_base = base;
    iov[count].iov_len = IOVEC_LEN(viov);
    count++;
    cur = Field(cur, 1);
  }

  *count_out = count;
  return iov;
}

CAMLprim value ocaml_quic_eio_send_msg_iovecs(value vfd, value vaddr,
                                              value viovecs) {
  CAMLparam3(vfd, vaddr, viovecs);
  union sock_addr_union addr;
  socklen_param_type addr_len;
  struct msghdr msg;
  struct iovec small_iov[16];
  struct iovec *iov;
  mlsize_t count = 0;
  int ret;
  iov = ocaml_quic_fill_iovecs(viovecs, small_iov,
                               sizeof(small_iov) / sizeof(small_iov[0]), &count);

  get_sockaddr(vaddr, &addr, &addr_len);
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &addr;
  msg.msg_namelen = addr_len;
  msg.msg_iov = iov;
  msg.msg_iovlen = count;

  caml_enter_blocking_section();
  ret = sendmsg(Int_val(vfd), &msg, 0);
  caml_leave_blocking_section();

  if (iov != small_iov) caml_stat_free(iov);

  if (ret == -1) uerror("sendmsg", Nothing);
  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_quic_eio_send_msg_iovecs_nb(value vfd, value vaddr,
                                                 value viovecs) {
  CAMLparam3(vfd, vaddr, viovecs);
  union sock_addr_union addr;
  socklen_param_type addr_len;
  struct msghdr msg;
  struct iovec small_iov[16];
  struct iovec *iov;
  mlsize_t count = 0;
  int ret;
  iov = ocaml_quic_fill_iovecs(viovecs, small_iov,
                               sizeof(small_iov) / sizeof(small_iov[0]), &count);

  get_sockaddr(vaddr, &addr, &addr_len);
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &addr;
  msg.msg_namelen = addr_len;
  msg.msg_iov = iov;
  msg.msg_iovlen = count;

  ret = sendmsg(Int_val(vfd), &msg, 0);

  if (iov != small_iov) caml_stat_free(iov);

  if (ret == -1) uerror("sendmsg", Nothing);
  CAMLreturn(Val_int(ret));
}

static value ocaml_quic_alloc_encoded_sockaddr(union sock_addr_union *addr,
                                               socklen_param_type addr_len) {
  CAMLparam0();
  CAMLlocal1(result);
  (void)addr_len;

  switch (addr->s_gen.sa_family) {
  case AF_INET: {
    size_t len = 1 + 4 + 2;
    result = caml_alloc_string(len);
    unsigned char *dst = (unsigned char *)Bytes_val(result);
    dst[0] = 4;
    memcpy(dst + 1, &addr->s_inet.sin_addr, 4);
    memcpy(dst + 5, &addr->s_inet.sin_port, 2);
    CAMLreturn(result);
  }
#ifdef HAS_IPV6
  case AF_INET6: {
    size_t len = 1 + 16 + 2;
    result = caml_alloc_string(len);
    unsigned char *dst = (unsigned char *)Bytes_val(result);
    dst[0] = 6;
    memcpy(dst + 1, &addr->s_inet6.sin6_addr, 16);
    memcpy(dst + 17, &addr->s_inet6.sin6_port, 2);
    CAMLreturn(result);
  }
#endif
  case AF_UNIX: {
    size_t path_len = strnlen(addr->s_unix.sun_path, sizeof(addr->s_unix.sun_path));
    result = caml_alloc_string(path_len + 1);
    unsigned char *dst = (unsigned char *)Bytes_val(result);
    dst[0] = 0;
    memcpy(dst + 1, addr->s_unix.sun_path, path_len);
    CAMLreturn(result);
  }
  default:
    caml_failwith("quic_eio_recvfrom_into: unsupported address family");
  }
}

static int ocaml_quic_encoded_sockaddr_matches(value vaddr,
                                               union sock_addr_union *addr,
                                               socklen_param_type addr_len) {
  mlsize_t len = caml_string_length(vaddr);
  const unsigned char *src = (const unsigned char *)String_val(vaddr);
  (void)addr_len;

  switch (addr->s_gen.sa_family) {
  case AF_INET:
    return len == 7 && src[0] == 4 && memcmp(src + 1, &addr->s_inet.sin_addr, 4) == 0 &&
           memcmp(src + 5, &addr->s_inet.sin_port, 2) == 0;
#ifdef HAS_IPV6
  case AF_INET6:
    return len == 19 && src[0] == 6 &&
           memcmp(src + 1, &addr->s_inet6.sin6_addr, 16) == 0 &&
           memcmp(src + 17, &addr->s_inet6.sin6_port, 2) == 0;
#endif
  case AF_UNIX: {
    size_t path_len = strnlen(addr->s_unix.sun_path, sizeof(addr->s_unix.sun_path));
    return len == path_len + 1 && src[0] == 0 &&
           memcmp(src + 1, addr->s_unix.sun_path, path_len) == 0;
  }
  default:
    return 0;
  }
}

CAMLprim value ocaml_quic_eio_recvfrom_into_nb(value vfd, value vbuf, value voff,
                                               value vlen, value vlast_addr_opt) {
  CAMLparam5(vfd, vbuf, voff, vlen, vlast_addr_opt);
  CAMLlocal3(vresult, vaddr, vn);
  struct caml_ba_array *ba = Caml_ba_array_val(vbuf);
  char *dst = (char *)ba->data + Long_val(voff);
  union sock_addr_union addr;
  socklen_param_type addr_len = sizeof(addr);
  int ret;

  ret = recvfrom(Int_val(vfd), dst, Long_val(vlen), 0, &addr.s_gen, &addr_len);

  if (ret == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) CAMLreturn(Val_int(0));
    uerror("recvfrom", Nothing);
  }

  vn = Val_int(ret);
  if (vlast_addr_opt != Val_int(0) &&
      ocaml_quic_encoded_sockaddr_matches(Field(vlast_addr_opt, 0), &addr, addr_len)) {
    vresult = caml_alloc(1, 0);
    Store_field(vresult, 0, vn);
    CAMLreturn(vresult);
  }

  vaddr = ocaml_quic_alloc_encoded_sockaddr(&addr, addr_len);
  vresult = caml_alloc(2, 1);
  Store_field(vresult, 0, vn);
  Store_field(vresult, 1, vaddr);
  CAMLreturn(vresult);
}
