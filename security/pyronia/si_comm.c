/* Netlink socket family used by a Pyronia-aware language runtime
 * to send callstack information to the Pyronia LSM for access control
 * decisions.
 *
 *@author Marcela S. Melara
 */

#include <net/genetlink.h>
#include <net/sock.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <uapi/linux/pyronia_netlink.h>
#include <uapi/linux/pyronia_mac.h>

#include "include/callgraph.h"
#include "include/context.h"
#include "include/policy.h"
#include "include/si_comm.h"
#include "include/stack_inspector.h"

struct pyr_callstack_request *callstack_req;

static DECLARE_WAIT_QUEUE_HEAD(callstack_req_waitq);

/* family definition */
static struct genl_family si_comm_gnl_family = {
    .id = GENL_ID_GENERATE,         //genetlink should generate an id
    .hdrsize = 0,
    .name = "SI_COMM", // name of this family, used by userspace
    .version = VERSION_NR,                   //version number
    .maxattr = SI_COMM_A_MAX,
};

static int send_to_runtime(u32 port_id, int cmd, int attr, int msg) {
    struct sk_buff *skb;
    void *msg_head;
    int ret = -1;
    char buf[12];

     // allocate the message memory
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL) {
        printk(KERN_ERR "[%s] Could not allocate skb for cmd message %d for port %d\n",
               __func__, cmd, port_id);
        goto out;
    }

    //Create the message headers
    msg_head = genlmsg_put(skb, 0, 0, &si_comm_gnl_family,
                           0, cmd);

    if (msg_head == NULL) {
        ret = -ENOMEM;
        printk("[%s] genlmsg_put() returned error for %d\n", __func__, port_id);
        goto out;
    }

    if (cmd == SI_COMM_C_STACK_REQ && attr == SI_COMM_A_KERN_REQ) {
      // create the message
      ret = nla_put_u8(skb, attr, STACK_REQ_CMD);
      if (ret != 0) {
        printk(KERN_ERR "[%s] Could not create the message for %d\n", __func__, port_id);
        goto out;
      }
    }
    else {
      sprintf(buf, "%d", msg);
      ret = nla_put_string(skb, SI_COMM_A_USR_MSG, buf);
      if (ret != 0)
        goto out;
    }

    // finalize the message
    genlmsg_end(skb, msg_head);

    // send the message
    ret = nlmsg_unicast(init_net.genl_sock, skb, port_id);
    if (ret < 0) {
        printk("[%s] Error %d sending message to %d\n", __func__, ret, port_id);
        goto out;
    }
    ret = 0;

 out:
    if (ret) {
        // TODO: release the kraken here
    }
    return ret;
}

/* STACK_REQ command: send a message requesting the current language
 * runtime's callstack from the given process, and return the callgraph
 * to the caller.
 * Expects the caller to hold the stack_request lock. */
pyr_cg_node_t *pyr_stack_request(u32 pid)
{
    int err;
    pyr_cg_node_t *cg = NULL;

    if (!pid) {
      PYR_ERROR("[%s] Oops, cannot request callstack from pid = 0!!\n", __func__);
      return NULL;
    }

    callstack_req->port_id = pid;

    PYR_DEBUG("[%s] Requesting callstack from runtime at %d\n", __func__, callstack_req->port_id);

    err = send_to_runtime(callstack_req->port_id, SI_COMM_C_STACK_REQ,
                          SI_COMM_A_KERN_REQ, STACK_REQ_CMD);

    if (err) {
      goto out;
    }

    callstack_req->runtime_responded = 0;

    wait_event_interruptible(callstack_req_waitq, callstack_req->runtime_responded == 1);

    if (!callstack_req->cg_buf) {
      goto out;
    }

    // deserialize the callstack we've received from userland
    if (pyr_deserialize_callstack(&cg, callstack_req->cg_buf)) {
        goto out;
    }

 out:
    callstack_req->runtime_responded = 0;
    return cg;
}

/* Return a pointer to the current callstack request.
 * This can be then be used to acquire the lock to do a callstack
 * request. */
struct pyr_callstack_request *pyr_get_current_callstack_request(void) {
  return callstack_req;
}

/* REGISTER_PROC command: receive a message with a process' PID and
 * library-level policy. This handler then stores this PID and policy
 * as part of the process' profile to enable
 * the kernel to request callstack information from the process
 * upon sensitive system calls.
 */
static int pyr_register_proc(struct sk_buff *skb,  struct genl_info *info)
{
    struct nlattr *na;
    char *msg = NULL, *port_str = NULL;
    int err = 0;
    u32 snd_port;
    int valid_pid = 0;
    struct task_struct *tsk;
    struct pyr_profile *profile;

    if (info == NULL)
        goto out;

    /*for each attribute there is an index in info->attrs which points
     * to a nlattr structure in this structure the data is given */
    na = info->attrs[SI_COMM_A_USR_MSG];
    if (na) {
        msg = (char *)nla_data(na);
        if (msg == NULL)
            printk(KERN_ERR "[%s] error while receiving data\n", __func__);
    }
    else
        printk(KERN_CRIT "no info->attrs %i\n", SI_COMM_A_USR_MSG);

    /* Parse the received message here */
    PYR_DEBUG("[%s] Received registration message: %s\n", __func__, msg);
    
    // the first token in our message should contain the
    // SI port for the sender application
    port_str = strsep(&msg, SI_PORT_STR_DELIM);
    if (!port_str) {
        PYR_ERROR("[%s] Malformed registration message: %s\n", __func__, msg);
        err = -1;
        goto out;
    }
    err = kstrtou32(port_str, 10, &snd_port);
    if (err)
      goto out;

    // TODO: Handle port IDs that are different from the PID
    valid_pid = (snd_port == info->snd_portid) ? 1 : 0;

    if (valid_pid) {
      tsk = pid_task(find_vpid(snd_port), PIDTYPE_PID);
      if (!tsk) {
        valid_pid = 0;
	PYR_DEBUG("couldn't find task with sender PID\n");
        goto out;
      }
      profile = pyr_get_task_profile(tsk);
      if (!profile) {
        valid_pid = 0;
	PYR_DEBUG("couldn't find profile for the task\n");
        goto out;
      }
      err = pyr_init_profile_lib_policy(profile, snd_port);
      if (err) {
	valid_pid = 0;
	PYR_DEBUG("couldn't init lib policy db for the task\n");
	goto out;
      }
      // load the library policy with the remaining message
      mutex_lock(&profile->ns->lock);
      err = pyr_deserialize_lib_policy(profile, msg);
      mutex_unlock(&profile->ns->lock);
      if (err) {
	PYR_DEBUG("couldn't deserialize lib policy\n");
	valid_pid = 0;
	goto out;
      }
      pyr_get_profile(profile);
    }

    printk(KERN_INFO "[%s] userspace at port %d registered SI port ID: %d\n", __func__, info->snd_portid, snd_port);

 out:
    /* This serves as an ACK from the kernel */
    err = send_to_runtime(info->snd_portid,
                          SI_COMM_C_REGISTER_PROC, SI_COMM_A_USR_MSG,
                          !valid_pid);
    if (err)
      printk(KERN_ERR "[%s] Error responding to runtime: %d\n", __func__, err);

    return 0;
}

/* STACK_REQ command: receive a response containing the requested
 * runtime callstack. This handler sets the runtime_requested variable
 * to true, so that the callstack request waiting for the response may
 * complete.
 */
static int pyr_get_callstack(struct sk_buff *skb, struct genl_info *info) {
  struct nlattr *na;
  char * mydata = NULL;

  if (info == NULL)
    goto out;

  /* for each attribute there is an index in info->attrs which points
   * to a nlattr structure in this structure the data is given */
  na = info->attrs[SI_COMM_A_USR_MSG];
  if (na) {
    mydata = (char *)nla_data(na);
    if (mydata == NULL)
      printk(KERN_ERR "[%s] error while receiving data\n", __func__);
  }
  else
    printk(KERN_CRIT "[%s] no info->attrs %i\n", __func__, SI_COMM_A_USR_MSG);


  if (info->snd_portid != callstack_req->port_id) {
    // this is going to cause the callstack request to continue blocking
    PYR_DEBUG("[%s] Inconsistent runtime IDs. Got %d, expected %d\n", __func__, callstack_req->port_id, info->snd_portid);
    goto out;
  }

  memcpy(callstack_req->cg_buf, mydata, MAX_RECV_LEN);
  callstack_req->runtime_responded = 1;
  wake_up_interruptible(&callstack_req_waitq);

 out:
  return 0;
}

/* SAVE_CONTEXT command: receive a message with callstack information
 * to store in the specified process' Pyronia ACL. */
static int pyr_save_context(struct sk_buff *skb,  struct genl_info *info)
{
    return 0;
}

/* commands:
 *
 * - REGISTER_PROC: register a language runtime instance with the LSM.
 * - SAVE_CONTEXT: pre-emptively save
 * callstack info as part of a process' access policy.*/
static const struct genl_ops si_comm_gnl_ops[] = {
    {
        .cmd = SI_COMM_C_REGISTER_PROC,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = pyr_register_proc,
    },
    {
        .cmd = SI_COMM_C_SAVE_CONTEXT,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = pyr_save_context,
    },
    {
        .cmd = SI_COMM_C_STACK_REQ,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = pyr_get_callstack,
    },
};

static int __init pyr_kernel_comm_init(void)
{
    int rc;

    /*register new family*/
    rc = genl_register_family_with_ops(&si_comm_gnl_family, si_comm_gnl_ops);
    if (rc != 0){
      printk(KERN_ERR "[%s] register ops: %i\n",__func__, rc);
      goto fail;
    }

    if(pyr_callstack_request_alloc(&callstack_req)) {
      printk(KERN_ERR "[%s] Could not allocate new stack request object\n", __func__);
      goto fail;
    }

    PYR_DEBUG("[%s] Initialized SI communication channel\n", __func__);
    return 0;

fail:
    genl_unregister_family(&si_comm_gnl_family);
    printk(KERN_CRIT "[%s] Error occured while creating SI netlink channel\n", __func__);
    return -1;
}

static void __exit pyr_kernel_comm_exit(void)
{
    int ret;

    /*unregister the family*/
    ret = genl_unregister_family(&si_comm_gnl_family);
    if(ret !=0){
      printk(KERN_ERR "[%s] unregister family %i\n", __func__, ret);
    }

    pyr_callstack_request_free(&callstack_req);

    PYR_DEBUG("[%s] SI channel teardown complete\n", __func__);
}


module_init(pyr_kernel_comm_init);
module_exit(pyr_kernel_comm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcela S. Melara");
MODULE_DESCRIPTION("Main component for stack inspection-related LSM-to-userspace communication.");
