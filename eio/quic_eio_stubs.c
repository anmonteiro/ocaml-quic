#include <string.h>
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

CAMLprim value ocaml_quic_eio_send_msg_iovecs(value vfd, value vaddr,
                                              value viovecs) {
  CAMLparam3(vfd, vaddr, viovecs);
  union sock_addr_union addr;
  socklen_param_type addr_len;
  struct msghdr msg;
  struct iovec small_iov[16];
  struct iovec *iov = small_iov;
  mlsize_t count = 0;
  value cur = viovecs;
  int ret;

  while (cur != Val_emptylist) {
    count++;
    cur = Field(cur, 1);
  }

  if (count > sizeof(small_iov) / sizeof(small_iov[0])) {
    iov = caml_stat_alloc_noexc(count * sizeof(struct iovec));
    if (iov == NULL) caml_raise_out_of_memory();
  }

  cur = viovecs;
  for (mlsize_t i = 0; i < count; i++) {
    value viov = Field(cur, 0);
    struct caml_ba_array *ba = Caml_ba_array_val(IOVEC_BUFFER(viov));
    char *base = (char *)ba->data + IOVEC_OFF(viov);
    iov[i].iov_base = base;
    iov[i].iov_len = IOVEC_LEN(viov);
    cur = Field(cur, 1);
  }

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
  struct iovec *iov = small_iov;
  mlsize_t count = 0;
  value cur = viovecs;
  int ret;

  while (cur != Val_emptylist) {
    count++;
    cur = Field(cur, 1);
  }

  if (count > sizeof(small_iov) / sizeof(small_iov[0])) {
    iov = caml_stat_alloc_noexc(count * sizeof(struct iovec));
    if (iov == NULL) caml_raise_out_of_memory();
  }

  cur = viovecs;
  for (mlsize_t i = 0; i < count; i++) {
    value viov = Field(cur, 0);
    struct caml_ba_array *ba = Caml_ba_array_val(IOVEC_BUFFER(viov));
    char *base = (char *)ba->data + IOVEC_OFF(viov);
    iov[i].iov_base = base;
    iov[i].iov_len = IOVEC_LEN(viov);
    cur = Field(cur, 1);
  }

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

CAMLprim value ocaml_quic_eio_recvfrom_into(value vfd, value vbuf, value voff,
                                            value vlen) {
  CAMLparam4(vfd, vbuf, voff, vlen);
  CAMLlocal3(vpair, vaddr, vn);
  struct caml_ba_array *ba = Caml_ba_array_val(vbuf);
  char *dst = (char *)ba->data + Long_val(voff);
  union sock_addr_union addr;
  socklen_param_type addr_len = sizeof(addr);
  int ret;

  ret = recvfrom(Int_val(vfd), dst, Long_val(vlen), 0, &addr.s_gen, &addr_len);

  if (ret == -1) uerror("recvfrom", Nothing);

  vn = Val_int(ret);
  vaddr = ocaml_quic_alloc_encoded_sockaddr(&addr, addr_len);
  vpair = caml_alloc(2, 0);
  Store_field(vpair, 0, vn);
  Store_field(vpair, 1, vaddr);
  CAMLreturn(vpair);
}
