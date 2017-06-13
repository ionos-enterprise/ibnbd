#define pr_fmt(fmt) KBUILD_MODNAME " L" __stringify(__LINE__) ": " fmt

#include <linux/module.h>
#include <linux/wait.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/utsname.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_fmr_pool.h>
#include <rdma/ib.h>
#include <rdma/ibtrs_clt.h>
#include "ibtrs_clt_internal.h"
#include "ibtrs_clt_sysfs.h"
#include <rdma/ibtrs.h>
#include <rdma/ibtrs_log.h>
#include <linux/list.h>

#define CONS_PER_SESSION (nr_cpu_ids + 1)
#define RECONNECT_SEED 8
#define MAX_SEGMENTS 31

MODULE_AUTHOR("ibnbd@profitbricks.com");
MODULE_DESCRIPTION("InfiniBand Transport Client");
MODULE_VERSION(__stringify(IBTRS_VER));
MODULE_LICENSE("GPL");

static bool use_fr;
module_param(use_fr, bool, 0444);
MODULE_PARM_DESC(use_fr, "use FRWR mode for memory registration if possible."
		 " (default: 0)");

static int retry_count = 7;

static int retry_count_set(const char *val, const struct kernel_param *kp)
{
	int err, ival;

	err = kstrtoint(val, 0, &ival);
	if (err)
		return err;

	if (ival < MIN_RTR_CNT || ival > MAX_RTR_CNT)
		return -EINVAL;

	retry_count = ival;

	return 0;
}

static const struct kernel_param_ops retry_count_ops = {
	.set		= retry_count_set,
	.get		= param_get_int,
};
module_param_cb(retry_count, &retry_count_ops, &retry_count, 0644);

MODULE_PARM_DESC(retry_count, "Number of times to send the message if the"
		 " remote side didn't respond with Ack or Nack (default: 3,"
		 " min: " __stringify(MIN_RTR_CNT) ", max: "
		 __stringify(MAX_RTR_CNT) ")");

static int fmr_sg_cnt = 4;
module_param_named(fmr_sg_cnt, fmr_sg_cnt, int, 0644);
MODULE_PARM_DESC(fmr_sg_cnt, "when sg_cnt is bigger than fmr_sg_cnt, enable"
		 " FMR (default: 4)");

static int default_heartbeat_timeout_ms = DEFAULT_HEARTBEAT_TIMEOUT_MS;

static int default_heartbeat_timeout_set(const char *val,
					 const struct kernel_param *kp)
{
	int ret, ival;

	ret = kstrtouint(val, 0, &ival);
	if (ret) {
		pr_err("Failed to convert string '%s' to unsigned int\n", val);
		return ret;
	}

	ret = ibtrs_heartbeat_timeout_validate(ival);
	if (ret)
		return ret;

	default_heartbeat_timeout_ms = ival;

	return 0;
}

static const struct kernel_param_ops heartbeat_timeout_ops = {
	.set		= default_heartbeat_timeout_set,
	.get		= param_get_int,
};

module_param_cb(default_heartbeat_timeout_ms, &heartbeat_timeout_ops,
		&default_heartbeat_timeout_ms, 0644);
MODULE_PARM_DESC(default_heartbeat_timeout_ms, "default heartbeat timeout,"
		 " min: " __stringify(MIN_HEARTBEAT_TIMEOUT_MS)
		 " (default:" __stringify(DEFAULT_HEARTBEAT_TIMEOUT_MS) ")");

static char hostname[MAXHOSTNAMELEN] = "";

static int hostname_set(const char *val, const struct kernel_param *kp)
{
	int ret = 0, len = strlen(val);

	if (len >= sizeof(hostname))
		return -EINVAL;
	strlcpy(hostname, val, sizeof(hostname));
	*strchrnul(hostname, '\n') = '\0';

	pr_info("hostname changed to %s\n", hostname);
	return ret;
}

static struct kparam_string hostname_kparam_str = {
	.maxlen	= sizeof(hostname),
	.string	= hostname
};

static const struct kernel_param_ops hostname_ops = {
	.set	= hostname_set,
	.get	= param_get_string,
};

module_param_cb(hostname, &hostname_ops,
		&hostname_kparam_str, 0644);
MODULE_PARM_DESC(hostname, "Sets hostname of local server, will send to the"
		 " other side if set,  will display togather with addr "
		 "(default: empty)");

#define LOCAL_INV_WR_ID_MASK	1
#define	FAST_REG_WR_ID_MASK	2

static const struct ibtrs_clt_ops *clt_ops;
static struct workqueue_struct *ibtrs_wq;
static LIST_HEAD(sess_list);
static DEFINE_MUTEX(sess_mutex);

static uuid_le uuid;

enum csm_state {
	_CSM_STATE_MIN,
	CSM_STATE_RESOLVING_ADDR,
	CSM_STATE_RESOLVING_ROUTE,
	CSM_STATE_CONNECTING,
	CSM_STATE_CONNECTED,
	CSM_STATE_CLOSING,
	CSM_STATE_FLUSHING,
	CSM_STATE_CLOSED,
	_CSM_STATE_MAX
};

enum csm_ev {
	CSM_EV_ADDR_RESOLVED,
	CSM_EV_ROUTE_RESOLVED,
	CSM_EV_CON_ESTABLISHED,
	CSM_EV_SESS_CLOSING,
	CSM_EV_CON_DISCONNECTED,
	CSM_EV_BEACON_COMPLETED,
	CSM_EV_WC_ERROR,
	CSM_EV_CON_ERROR
};

enum ssm_ev {
	SSM_EV_CON_CONNECTED,
	SSM_EV_RECONNECT,		/* in RECONNECT state only*/
	SSM_EV_RECONNECT_USER,		/* triggered by user via sysfs */
	SSM_EV_RECONNECT_HEARTBEAT,	/* triggered by the heartbeat */
	SSM_EV_SESS_CLOSE,
	SSM_EV_CON_CLOSED,		/* when CSM switched to CLOSED */
	SSM_EV_CON_ERROR,		/* triggered by CSM when smth. wrong */
	SSM_EV_ALL_CON_CLOSED,		/* triggered when all cons closed */
	SSM_EV_GOT_RDMA_INFO
};

static const char *ssm_state_str(enum ssm_state state)
{
	switch (state) {
	case SSM_STATE_IDLE:
		return "SSM_STATE_IDLE";
	case SSM_STATE_IDLE_RECONNECT:
		return "SSM_STATE_IDLE_RECONNECT";
	case SSM_STATE_WF_INFO:
		return "SSM_STATE_WF_INFO";
	case SSM_STATE_WF_INFO_RECONNECT:
		return "SSM_STATE_WF_INFO_RECONNECT";
	case SSM_STATE_OPEN:
		return "SSM_STATE_OPEN";
	case SSM_STATE_OPEN_RECONNECT:
		return "SSM_STATE_OPEN_RECONNECT";
	case SSM_STATE_CONNECTED:
		return "SSM_STATE_CONNECTED";
	case SSM_STATE_RECONNECT:
		return "SSM_STATE_RECONNECT";
	case SSM_STATE_CLOSE_DESTROY:
		return "SSM_STATE_CLOSE_DESTROY";
	case SSM_STATE_CLOSE_RECONNECT:
		return "SSM_STATE_CLOSE_RECONNECT";
	case SSM_STATE_CLOSE_RECONNECT_IMM:
		return "SSM_STATE_CLOSE_RECONNECT_IMM";
	case SSM_STATE_DISCONNECTED:
		return "SSM_STATE_DISCONNECTED";
	case SSM_STATE_DESTROYED:
		return "SSM_STATE_DESTROYED";
	default:
		return "UNKNOWN";
	}
}

static const char *ssm_event_str(enum ssm_ev ev)
{
	switch (ev) {
	case SSM_EV_CON_CONNECTED:
		return "SSM_EV_CON_CONNECTED";
	case SSM_EV_RECONNECT:
		return "SSM_EV_RECONNECT";
	case SSM_EV_RECONNECT_USER:
		return "SSM_EV_RECONNECT_USER";
	case SSM_EV_RECONNECT_HEARTBEAT:
		return "SSM_EV_RECONNECT_HEARTBEAT";
	case SSM_EV_SESS_CLOSE:
		return "SSM_EV_SESS_CLOSE";
	case SSM_EV_CON_CLOSED:
		return "SSM_EV_CON_CLOSED";
	case SSM_EV_CON_ERROR:
		return "SSM_EV_CON_ERROR";
	case SSM_EV_ALL_CON_CLOSED:
		return "SSM_EV_ALL_CON_CLOSED";
	case SSM_EV_GOT_RDMA_INFO:
		return "SSM_EV_GOT_RDMA_INFO";
	default:
		return "UNKNOWN";
	}
}

static const char *csm_state_str(enum csm_state state)
{
	switch (state) {
	case CSM_STATE_RESOLVING_ADDR:
		return "CSM_STATE_RESOLVING_ADDR";
	case CSM_STATE_RESOLVING_ROUTE:
		return "CSM_STATE_RESOLVING_ROUTE";
	case CSM_STATE_CONNECTING:
		return "CSM_STATE_CONNECTING";
	case CSM_STATE_CONNECTED:
		return "CSM_STATE_CONNECTED";
	case CSM_STATE_FLUSHING:
		return "CSM_STATE_FLUSHING";
	case CSM_STATE_CLOSING:
		return "CSM_STATE_CLOSING";
	case CSM_STATE_CLOSED:
		return "CSM_STATE_CLOSED";
	default:
		return "UNKNOWN";
	}
}

static const char *csm_event_str(enum csm_ev ev)
{
	switch (ev) {
	case CSM_EV_ADDR_RESOLVED:
		return "CSM_EV_ADDR_RESOLVED";
	case CSM_EV_ROUTE_RESOLVED:
		return "CSM_EV_ROUTE_RESOLVED";
	case CSM_EV_CON_ESTABLISHED:
		return "CSM_EV_CON_ESTABLISHED";
	case CSM_EV_BEACON_COMPLETED:
		return "CSM_EV_BEACON_COMPLETED";
	case CSM_EV_SESS_CLOSING:
		return "CSM_EV_SESS_CLOSING";
	case CSM_EV_CON_DISCONNECTED:
		return "CSM_EV_CON_DISCONNECTED";
	case CSM_EV_WC_ERROR:
		return "CSM_EV_WC_ERROR";
	case CSM_EV_CON_ERROR:
		return "CSM_EV_CON_ERROR";
	default:
		return "UNKNOWN";
	}
}

/* rdma_req which connect iu with sglist received from user */
struct rdma_req {
	struct list_head        list;
	struct ibtrs_iu		*iu;
	struct scatterlist	*sglist; /* list holding user data */
	unsigned int		sg_cnt;
	unsigned int		sg_size;
	u32			data_len;
	void			*priv;
	bool			in_use;
	struct ibtrs_con	*con;
	union {
		struct ib_pool_fmr	**fmr_list;
		struct ibtrs_fr_desc	**fr_list;
	};
	void			*map_page;
	struct ibtrs_tag	*tag;
	u16			nmdesc;
	enum dma_data_direction dir;
	unsigned long		start_time;
} ____cacheline_aligned;

struct ibtrs_con {
	enum  csm_state		state;
	short			cpu;
	bool			user; /* true if con is for user msg only */
	atomic_t		io_cnt;
	struct ibtrs_session	*sess;
	struct ib_con		ib_con;
	struct ibtrs_fr_pool	*fr_pool;
	struct rdma_cm_id	*cm_id;
	struct work_struct	cq_work;
	struct workqueue_struct *cq_wq;
	struct tasklet_struct	cq_tasklet;
	struct ib_wc		wcs[WC_ARRAY_SIZE];
	bool			device_being_removed;
};

struct sess_destroy_sm_wq_work {
	struct work_struct	work;
	struct ibtrs_session	*sess;
};

struct con_sm_work {
	struct work_struct	work;
	struct ibtrs_con	*con;
	enum csm_ev		ev;
};

struct sess_sm_work {
	struct work_struct	work;
	struct ibtrs_session	*sess;
	enum ssm_ev		ev;
};

struct msg_work {
	struct work_struct	work;
	struct ibtrs_con	*con;
	void                    *msg;
};

static void ibtrs_clt_free_sg_list_distr_stats(struct ibtrs_session *sess)
{
	int i;

	for (i = 0; i < num_online_cpus(); i++)
		kfree(sess->stats.sg_list_distr[i]);
	kfree(sess->stats.sg_list_distr);
	sess->stats.sg_list_distr = NULL;
	kfree(sess->stats.sg_list_total);
	sess->stats.sg_list_total = NULL;
}

static void ibtrs_clt_free_cpu_migr_stats(struct ibtrs_session *sess)
{
	kfree(sess->stats.cpu_migr.to);
	sess->stats.cpu_migr.to = NULL;
	kfree(sess->stats.cpu_migr.from);
	sess->stats.cpu_migr.from = NULL;
}

static void ibtrs_clt_free_rdma_lat_stats(struct ibtrs_session *sess)
{
	int i;

	for (i = 0; i < num_online_cpus(); i++)
		kfree(sess->stats.rdma_lat_distr[i]);

	kfree(sess->stats.rdma_lat_distr);
	sess->stats.rdma_lat_distr = NULL;
	kfree(sess->stats.rdma_lat_max);
	sess->stats.rdma_lat_max = NULL;
}

static void ibtrs_clt_free_wc_comp_stats(struct ibtrs_session *sess)
{
	kfree(sess->stats.wc_comp);
	sess->stats.wc_comp = NULL;
}

static void ibtrs_clt_free_rdma_stats(struct ibtrs_session *sess)
{
	kfree(sess->stats.rdma_stats);
	sess->stats.rdma_stats = NULL;
}

static void ibtrs_clt_free_stats(struct ibtrs_session *sess)
{
	ibtrs_clt_free_rdma_stats(sess);
	ibtrs_clt_free_rdma_lat_stats(sess);
	ibtrs_clt_free_cpu_migr_stats(sess);
	ibtrs_clt_free_sg_list_distr_stats(sess);
	ibtrs_clt_free_wc_comp_stats(sess);
}

static inline int get_sess(struct ibtrs_session *sess)
{
	return atomic_inc_not_zero(&sess->refcount);
}

static void free_con_fast_pool(struct ibtrs_con *con);

static void sess_deinit_cons(struct ibtrs_session *sess)
{
	int i;

	for (i = 0; i < CONS_PER_SESSION; i++) {
		struct ibtrs_con *con = &sess->con[i];

		if (!i)
			destroy_workqueue(con->cq_wq);
		else
			tasklet_kill(&con->cq_tasklet);
	}
}

static void put_sess(struct ibtrs_session *sess)
{
	if (!atomic_dec_if_positive(&sess->refcount)) {
		struct completion *destroy_completion;

		destroy_workqueue(sess->sm_wq);
		sess_deinit_cons(sess);
		kfree(sess->con);
		sess->con = NULL;
		ibtrs_clt_free_stats(sess);
		destroy_completion = sess->destroy_completion;
		mutex_lock(&sess_mutex);
		list_del(&sess->list);
		mutex_unlock(&sess_mutex);
		INFO(sess, "Session is disconnected\n");
		kfree(sess);
		if (destroy_completion)
			complete_all(destroy_completion);
	}
}

inline int ibtrs_clt_get_user_queue_depth(struct ibtrs_session *sess)
{
	return sess->user_queue_depth;
}

inline int ibtrs_clt_set_user_queue_depth(struct ibtrs_session *sess,
					  u16 queue_depth)
{
	if (queue_depth < 1 ||
	    queue_depth > sess->queue_depth) {
		ERR(sess, "Queue depth %u is out of range (1 - %u)",
		    queue_depth,
		    sess->queue_depth);
		return -EINVAL;
	}

	sess->user_queue_depth = queue_depth;
	return 0;
}

static void csm_resolving_addr(struct ibtrs_con *con, enum csm_ev ev);
static void csm_resolving_route(struct ibtrs_con *con, enum csm_ev ev);
static void csm_connecting(struct ibtrs_con *con, enum csm_ev ev);
static void csm_connected(struct ibtrs_con *con, enum csm_ev ev);
static void csm_flushing(struct ibtrs_con *con, enum csm_ev ev);
static void csm_closing(struct ibtrs_con *con, enum csm_ev ev);

static int init_con(struct ibtrs_session *sess, struct ibtrs_con *con,
		    short cpu, bool user);
/* ignore all event for safefy */
static void csm_closed(struct ibtrs_con *con, enum csm_ev ev)
{
}

typedef void (ibtrs_clt_csm_ev_handler_fn)(struct ibtrs_con *, enum csm_ev);

static ibtrs_clt_csm_ev_handler_fn *ibtrs_clt_csm_ev_handlers[] = {
	[CSM_STATE_RESOLVING_ADDR]	= csm_resolving_addr,
	[CSM_STATE_RESOLVING_ROUTE]	= csm_resolving_route,
	[CSM_STATE_CONNECTING]		= csm_connecting,
	[CSM_STATE_CONNECTED]		= csm_connected,
	[CSM_STATE_CLOSING]		= csm_closing,
	[CSM_STATE_FLUSHING]		= csm_flushing,
	[CSM_STATE_CLOSED]		= csm_closed
};

static void csm_trigger_event(struct work_struct *work)
{
	struct con_sm_work *w;
	struct ibtrs_con *con;
	enum csm_ev ev;

	w = container_of(work, struct con_sm_work, work);
	con = w->con;
	ev = w->ev;
	kfree(w);

	if (WARN_ON_ONCE(con->state <= _CSM_STATE_MIN ||
			 con->state >= _CSM_STATE_MAX)) {
		WRN(con->sess, "Connection state is out of range\n");
		return;
	}

	ibtrs_clt_csm_ev_handlers[con->state](con, ev);
}

static void csm_set_state(struct ibtrs_con *con, enum csm_state s)
{
	if (WARN(s <= _CSM_STATE_MIN || s >= _CSM_STATE_MAX,
		 "Unknown CSM state %d\n", s))
		return;
	smp_wmb(); /* fence con->state change */
	if (con->state != s) {
		pr_debug("changing con %p csm state from %s to %s\n", con,
		    csm_state_str(con->state), csm_state_str(s));
		con->state = s;
	}
}

inline bool ibtrs_clt_sess_is_connected(const struct ibtrs_session *sess)
{
	return sess->state == SSM_STATE_CONNECTED;
}

static void ssm_idle(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_idle_reconnect(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_open(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_open_reconnect(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_connected(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_reconnect(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_close_destroy(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_close_reconnect(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_close_reconnect_imm(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_disconnected(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_destroyed(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_wf_info(struct ibtrs_session *sess, enum ssm_ev ev);
static void ssm_wf_info_reconnect(struct ibtrs_session *sess, enum ssm_ev ev);

typedef void (ibtrs_clt_ssm_ev_handler_fn)(struct ibtrs_session *, enum ssm_ev);

static ibtrs_clt_ssm_ev_handler_fn *ibtrs_clt_ev_handlers[] = {
	[SSM_STATE_IDLE]		= ssm_idle,
	[SSM_STATE_IDLE_RECONNECT]	= ssm_idle_reconnect,
	[SSM_STATE_WF_INFO]		= ssm_wf_info,
	[SSM_STATE_WF_INFO_RECONNECT]	= ssm_wf_info_reconnect,
	[SSM_STATE_OPEN]		= ssm_open,
	[SSM_STATE_OPEN_RECONNECT]	= ssm_open_reconnect,
	[SSM_STATE_CONNECTED]		= ssm_connected,
	[SSM_STATE_RECONNECT]		= ssm_reconnect,
	[SSM_STATE_CLOSE_DESTROY]	= ssm_close_destroy,
	[SSM_STATE_CLOSE_RECONNECT]	= ssm_close_reconnect,
	[SSM_STATE_CLOSE_RECONNECT_IMM]	= ssm_close_reconnect_imm,
	[SSM_STATE_DISCONNECTED]	= ssm_disconnected,
	[SSM_STATE_DESTROYED]		= ssm_destroyed,
};

typedef int (ibtrs_clt_ssm_state_init_fn)(struct ibtrs_session *);
static ibtrs_clt_ssm_state_init_fn	ssm_open_init;
static ibtrs_clt_ssm_state_init_fn	ssm_close_destroy_init;
static ibtrs_clt_ssm_state_init_fn	ssm_destroyed_init;
static ibtrs_clt_ssm_state_init_fn	ssm_connected_init;
static ibtrs_clt_ssm_state_init_fn	ssm_reconnect_init;
static ibtrs_clt_ssm_state_init_fn	ssm_idle_reconnect_init;
static ibtrs_clt_ssm_state_init_fn	ssm_disconnected_init;
static ibtrs_clt_ssm_state_init_fn	ssm_wf_info_init;

static ibtrs_clt_ssm_state_init_fn *ibtrs_clt_ssm_state_init[] = {
	[SSM_STATE_IDLE]		= NULL,
	[SSM_STATE_IDLE_RECONNECT]	= ssm_idle_reconnect_init,
	[SSM_STATE_WF_INFO]		= ssm_wf_info_init,
	[SSM_STATE_WF_INFO_RECONNECT]	= ssm_wf_info_init,
	[SSM_STATE_OPEN]		= ssm_open_init,
	[SSM_STATE_OPEN_RECONNECT]	= ssm_open_init,
	[SSM_STATE_CONNECTED]		= ssm_connected_init,
	[SSM_STATE_RECONNECT]		= ssm_reconnect_init,
	[SSM_STATE_CLOSE_DESTROY]	= ssm_close_destroy_init,
	[SSM_STATE_CLOSE_RECONNECT]	= ssm_close_destroy_init,
	[SSM_STATE_CLOSE_RECONNECT_IMM]	= ssm_close_destroy_init,
	[SSM_STATE_DISCONNECTED]	= ssm_disconnected_init,
	[SSM_STATE_DESTROYED]		= ssm_destroyed_init,
};

static int ssm_init_state(struct ibtrs_session *sess, enum ssm_state state)
{
	int err;

	if (WARN(state <= _SSM_STATE_MIN || state >= _SSM_STATE_MAX,
		 "Unknown SSM state %d\n", state))
		return -EINVAL;

	smp_rmb(); /* fence sess->state change */
	if (sess->state == state)
		return 0;

	/* Call the init function of the new state only if:
	 * - it is defined
	 *   and
	 * - it is different from the init function of the current state
	 */
	if (ibtrs_clt_ssm_state_init[state] &&
	    ibtrs_clt_ssm_state_init[state] !=
	    ibtrs_clt_ssm_state_init[sess->state]) {
		err = ibtrs_clt_ssm_state_init[state](sess);
		if (err) {
			ERR(sess, "Failed to init ssm state %s from %s: %s\n",
			    ssm_state_str(state), ssm_state_str(sess->state),
			    strerror(err));
			return err;
		}
	}

	pr_debug("changing sess %p ssm state from %s to %s\n", sess,
	    ssm_state_str(sess->state), ssm_state_str(state));

	smp_wmb(); /* fence sess->state change */
	sess->state = state;

	return 0;
}

static void ssm_trigger_event(struct work_struct *work)
{
	struct sess_sm_work *w;
	struct ibtrs_session *sess;
	enum ssm_ev ev;

	w = container_of(work, struct sess_sm_work, work);
	sess = w->sess;
	ev = w->ev;
	kfree(w);

	if (WARN_ON_ONCE(sess->state <= _SSM_STATE_MIN || sess->state >=
			 _SSM_STATE_MAX)) {
		WRN(sess, "Session state is out of range\n");
		return;
	}

	ibtrs_clt_ev_handlers[sess->state](sess, ev);
}

static void csm_schedule_event(struct ibtrs_con *con, enum csm_ev ev)
{
	struct con_sm_work *w = NULL;

	if (in_softirq()) {
		w = kmalloc(sizeof(*w), GFP_ATOMIC);
		BUG_ON(!w);
		goto out;
	}
	while (!w) {
		w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
		if (!w)
			cond_resched();
	}
out:
	w->con = con;
	w->ev = ev;
	INIT_WORK(&w->work, csm_trigger_event);
	WARN_ON(!queue_work_on(0, con->sess->sm_wq, &w->work));
}

static void ssm_schedule_event(struct ibtrs_session *sess, enum ssm_ev ev)
{
	struct sess_sm_work *w = NULL;

	while (!w) {
		w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
		if (!w)
			cond_resched();
	}

	w->sess = sess;
	w->ev = ev;
	INIT_WORK(&w->work, ssm_trigger_event);
	WARN_ON(!queue_work_on(0, sess->sm_wq, &w->work));
}

static inline bool clt_ops_are_valid(const struct ibtrs_clt_ops *ops)
{
	return ops && ops->rdma_ev && ops->sess_ev && ops->recv;
}

/**
 * struct ibtrs_fr_desc - fast registration work request arguments
 * @entry: Entry in ibtrs_fr_pool.free_list.
 * @mr:    Memory region.
 * @frpl:  Fast registration page list.
 */
struct ibtrs_fr_desc {
	struct list_head		entry;
	struct ib_mr			*mr;
};

/**
 * struct ibtrs_fr_pool - pool of fast registration descriptors
 *
 * An entry is available for allocation if and only if it occurs in @free_list.
 *
 * @size:      Number of descriptors in this pool.
 * @max_page_list_len: Maximum fast registration work request page list length.
 * @lock:      Protects free_list.
 * @free_list: List of free descriptors.
 * @desc:      Fast registration descriptor pool.
 */
struct ibtrs_fr_pool {
	int			size;
	int			max_page_list_len;
	/* lock for free_list*/
	spinlock_t		lock ____cacheline_aligned;
	struct list_head	free_list;
	struct ibtrs_fr_desc	desc[0];
};

/**
 * struct ibtrs_map_state - per-request DMA memory mapping state
 * @desc:	    Pointer to the element of the SRP buffer descriptor array
 *		    that is being filled in.
 * @pages:	    Array with DMA addresses of pages being considered for
 *		    memory registration.
 * @base_dma_addr:  DMA address of the first page that has not yet been mapped.
 * @dma_len:	    Number of bytes that will be registered with the next
 *		    FMR or FR memory registration call.
 * @total_len:	    Total number of bytes in the sg-list being mapped.
 * @npages:	    Number of page addresses in the pages[] array.
 * @nmdesc:	    Number of FMR or FR memory descriptors used for mapping.
 * @ndesc:	    Number of buffer descriptors that have been filled in.
 */
struct ibtrs_map_state {
	union {
		struct ib_pool_fmr	**next_fmr;
		struct ibtrs_fr_desc	**next_fr;
	};
	struct ibtrs_sg_desc	*desc;
	union {
		u64			*pages;
		struct scatterlist      *sg;
	};
	dma_addr_t		base_dma_addr;
	u32			dma_len;
	u32			total_len;
	u32			npages;
	u32			nmdesc;
	u32			ndesc;
	enum dma_data_direction dir;
};

static void free_io_bufs(struct ibtrs_session *sess);

static int process_open_rsp(struct ibtrs_con *con, const void *resp)
{
	int i;
	const struct ibtrs_msg_sess_open_resp *msg = resp;
	struct ibtrs_session *sess = con->sess;
	u32 chunk_size;

	rcu_read_lock();
	smp_rmb(); /* fence con->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		rcu_read_unlock();
		INFO(sess, "Process open response failed, disconnected."
		     " Connection state is %s, Session state is %s\n",
		     csm_state_str(con->state),
		     ssm_state_str(sess->state));
		return -ECOMM;
	}
	rcu_read_unlock();

	chunk_size = msg->max_io_size + msg->max_req_size;
	/* check if IB immediate data size is enough to hold the mem_id and the
	 * offset inside the memory chunk
	 */
	if (ilog2(msg->cnt - 1) + ilog2(chunk_size - 1) >
		IB_IMM_SIZE_BITS) {
		ERR(sess, "RDMA immediate size (%db) not enough to encode "
		    "%d buffers of size %dB\n", IB_IMM_SIZE_BITS, msg->cnt,
		    chunk_size);
		return -EINVAL;
	}

	strlcpy(sess->hostname, msg->hostname, sizeof(sess->hostname));
	sess->srv_rdma_buf_rkey = msg->rkey;
	sess->user_queue_depth = msg->max_inflight_msg;
	sess->max_io_size = msg->max_io_size;
	sess->max_req_size = msg->max_req_size;
	sess->chunk_size = chunk_size;
	sess->max_desc = (msg->max_req_size - IBTRS_HDR_LEN - sizeof(u32)
			  - sizeof(u32) - IO_MSG_SIZE) / IBTRS_SG_DESC_LEN;
	sess->ver = min_t(u8, msg->ver, IBTRS_VERSION);

	/* if the server changed the queue_depth between the reconnect,
	 * we need to reallocate all buffers that depend on it
	 */
	if (sess->queue_depth &&
	    sess->queue_depth != msg->max_inflight_msg) {
		free_io_bufs(sess);
		kfree(sess->srv_rdma_addr);
		sess->srv_rdma_addr = NULL;
	}

	sess->queue_depth = msg->max_inflight_msg;
	if (!sess->srv_rdma_addr) {
		sess->srv_rdma_addr = kcalloc(sess->queue_depth,
					      sizeof(*sess->srv_rdma_addr),
					      GFP_KERNEL);
		if (!sess->srv_rdma_addr) {
			ERR(sess, "Failed to allocate memory for server RDMA"
			    " addresses\n");
			return -ENOMEM;
		}
	}

	for (i = 0; i < msg->cnt; i++) {
		sess->srv_rdma_addr[i] = msg->addr[i];
		pr_debug("Adding contiguous buffer %d, size %u, addr: 0x%p,"
		    " rkey: 0x%x\n", i, sess->chunk_size,
		    (void *)sess->srv_rdma_addr[i],
		    sess->srv_rdma_buf_rkey);
	}

	return 0;
}

static int wait_for_ssm_state(struct ibtrs_session *sess, enum ssm_state state)
{
	pr_debug("Waiting for state %s...\n", ssm_state_str(state));
	wait_event(sess->wait_q, sess->state >= state);

	if (unlikely(sess->state != state)) {
		ERR(sess,
		    "Waited for session state '%s', but state is '%s'\n",
		    ssm_state_str(state), ssm_state_str(sess->state));
		return -EHOSTUNREACH;
	}

	return 0;
}

static inline struct ibtrs_tag *__ibtrs_get_tag(struct ibtrs_session *sess,
						int cpu_id)
{
	size_t max_depth = sess->user_queue_depth;
	struct ibtrs_tag *tag;
	int cpu, bit;

	cpu = get_cpu();
	do {
		bit = find_first_zero_bit(sess->tags_map, max_depth);
		if (unlikely(bit >= max_depth)) {
			put_cpu();
			return NULL;
		}

	} while (unlikely(test_and_set_bit_lock(bit, sess->tags_map)));
	put_cpu();

	tag = GET_TAG(sess, bit);
	WARN_ON(tag->mem_id != bit);
	tag->cpu_id = (cpu_id != -1 ? cpu_id : cpu);

	return tag;
}

static inline void __ibtrs_put_tag(struct ibtrs_session *sess,
				   struct ibtrs_tag *tag)
{
	clear_bit_unlock(tag->mem_id, sess->tags_map);
}

struct ibtrs_tag *ibtrs_get_tag(struct ibtrs_session *sess, int cpu_id,
				size_t nr_bytes, int can_wait)
{
	struct ibtrs_tag *tag;
	DEFINE_WAIT(wait);

	/* Is not used for now */
	(void)nr_bytes;

	tag = __ibtrs_get_tag(sess, cpu_id);
	if (likely(tag) || !can_wait)
		return tag;

	do {
		prepare_to_wait(&sess->tags_wait, &wait, TASK_UNINTERRUPTIBLE);
		tag = __ibtrs_get_tag(sess, cpu_id);
		if (likely(tag))
			break;

		io_schedule();
	} while (1);

	finish_wait(&sess->tags_wait, &wait);

	return tag;
}
EXPORT_SYMBOL(ibtrs_get_tag);

void ibtrs_put_tag(struct ibtrs_session *sess, struct ibtrs_tag *tag)
{
	if (WARN_ON(tag->mem_id >= sess->queue_depth))
		return;
	if (WARN_ON(!test_bit(tag->mem_id, sess->tags_map)))
		return;

	__ibtrs_put_tag(sess, tag);

	/* Putting a tag is a barrier, so we will observe
	 * new entry in the wait list, no worries.
	 */
	if (waitqueue_active(&sess->tags_wait))
		wake_up(&sess->tags_wait);
}
EXPORT_SYMBOL(ibtrs_put_tag);

static void put_u_msg_iu(struct ibtrs_session *sess, struct ibtrs_iu *iu)
{
	unsigned long flags;

	spin_lock_irqsave(&sess->u_msg_ius_lock, flags);
	ibtrs_iu_put(&sess->u_msg_ius_list, iu);
	spin_unlock_irqrestore(&sess->u_msg_ius_lock, flags);
}

static struct ibtrs_iu *get_u_msg_iu(struct ibtrs_session *sess)
{
	struct ibtrs_iu *iu;
	unsigned long flags;

	spin_lock_irqsave(&sess->u_msg_ius_lock, flags);
	iu = ibtrs_iu_get(&sess->u_msg_ius_list);
	spin_unlock_irqrestore(&sess->u_msg_ius_lock, flags);

	return iu;
}

/**
 * ibtrs_destroy_fr_pool() - free the resources owned by a pool
 * @pool: Fast registration pool to be destroyed.
 */
static void ibtrs_destroy_fr_pool(struct ibtrs_fr_pool *pool)
{
	int i;
	struct ibtrs_fr_desc *d;
	int ret;

	if (!pool)
		return;

	for (i = 0, d = &pool->desc[0]; i < pool->size; i++, d++) {
		if (d->mr) {
			ret = ib_dereg_mr(d->mr);
			if (ret)
				pr_err("Failed to deregister memory region,"
				       " err: %s\n", strerror(ret));
		}
	}
	kfree(pool);
}

/**
 * ibtrs_create_fr_pool() - allocate and initialize a pool for fast registration
 * @device:            IB device to allocate fast registration descriptors for.
 * @pd:                Protection domain associated with the FR descriptors.
 * @pool_size:         Number of descriptors to allocate.
 * @max_page_list_len: Maximum fast registration work request page list length.
 */
static struct ibtrs_fr_pool *ibtrs_create_fr_pool(struct ib_device *device,
						  struct ib_pd *pd,
						  int pool_size,
						  int max_page_list_len)
{
	struct ibtrs_fr_pool *pool;
	struct ibtrs_fr_desc *d;
	struct ib_mr *mr;
	int i, ret;

	if (pool_size <= 0) {
		pr_warn("Creating fr pool failed, invalid pool size %d\n",
		       pool_size);
		ret = -EINVAL;
		goto err;
	}

	pool = kzalloc(sizeof(*pool) + pool_size * sizeof(*d), GFP_KERNEL);
	if (!pool) {
		ret = -ENOMEM;
		goto err;
	}

	pool->size = pool_size;
	pool->max_page_list_len = max_page_list_len;
	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->free_list);

	for (i = 0, d = &pool->desc[0]; i < pool->size; i++, d++) {
		mr = ib_alloc_mr(pd, IB_MR_TYPE_MEM_REG, max_page_list_len);
		if (IS_ERR(mr)) {
			pr_warn("Failed to allocate fast region memory\n");
			ret = PTR_ERR(mr);
			goto destroy_pool;
		}
		d->mr = mr;
		list_add_tail(&d->entry, &pool->free_list);
	}

	return pool;

destroy_pool:
	ibtrs_destroy_fr_pool(pool);
err:
	return ERR_PTR(ret);
}

/**
 * ibtrs_fr_pool_get() - obtain a descriptor suitable for fast registration
 * @pool: Pool to obtain descriptor from.
 */
static struct ibtrs_fr_desc *ibtrs_fr_pool_get(struct ibtrs_fr_pool *pool)
{
	struct ibtrs_fr_desc *d = NULL;

	spin_lock_bh(&pool->lock);
	if (!list_empty(&pool->free_list)) {
		d = list_first_entry(&pool->free_list, typeof(*d), entry);
		list_del(&d->entry);
	}
	spin_unlock_bh(&pool->lock);

	return d;
}

/**
 * ibtrs_fr_pool_put() - put an FR descriptor back in the free list
 * @pool: Pool the descriptor was allocated from.
 * @desc: Pointer to an array of fast registration descriptor pointers.
 * @n:    Number of descriptors to put back.
 *
 * Note: The caller must already have queued an invalidation request for
 * desc->mr->rkey before calling this function.
 */
static void ibtrs_fr_pool_put(struct ibtrs_fr_pool *pool,
			      struct ibtrs_fr_desc **desc, int n)
{
	int i;

	spin_lock_bh(&pool->lock);
	for (i = 0; i < n; i++)
		list_add(&desc[i]->entry, &pool->free_list);
	spin_unlock_bh(&pool->lock);
}

static inline struct ibtrs_fr_pool *alloc_fr_pool(struct ibtrs_session *sess)
{
	return ibtrs_create_fr_pool(sess->ib_device, sess->ib_sess.pd,
				    sess->queue_depth,
				    sess->max_pages_per_mr);
}

static void ibtrs_map_desc(struct ibtrs_map_state *state, dma_addr_t dma_addr,
			   u32 dma_len, u32 rkey, u32 max_desc)
{
	struct ibtrs_sg_desc *desc = state->desc;

	pr_debug("dma_addr %llu, key %u, dma_len %u\n", dma_addr, rkey, dma_len);
	desc->addr	= dma_addr;
	desc->key	= rkey;
	desc->len	= dma_len;

	state->total_len += dma_len;
	if (state->ndesc < max_desc) {
		state->desc++;
		state->ndesc++;
	} else {
		state->ndesc = INT_MIN;
		pr_err("Could not fit S/G list into buffer descriptor %d.\n",
		       max_desc);
	}
}

static int ibtrs_map_finish_fmr(struct ibtrs_map_state *state,
				struct ibtrs_con *con)
{
	struct ib_pool_fmr *fmr;
	u64 io_addr = 0;
	dma_addr_t dma_addr;

	fmr = ib_fmr_pool_map_phys(con->sess->fmr_pool, state->pages,
				   state->npages, io_addr);
	if (IS_ERR(fmr)) {
		WRN_RL(con->sess, "Failed to map FMR from FMR pool, "
		       "err: %s\n", strerror(PTR_ERR(fmr)));
		return PTR_ERR(fmr);
	}

	*state->next_fmr++ = fmr;
	state->nmdesc++;
	dma_addr = state->base_dma_addr & ~con->sess->mr_page_mask;
	pr_debug("ndesc = %d, nmdesc = %d, npages = %d\n",
	    state->ndesc, state->nmdesc, state->npages);
	if (state->dir == DMA_TO_DEVICE)
		ibtrs_map_desc(state, dma_addr, state->dma_len, fmr->fmr->lkey,
			       con->sess->max_desc);
	else
		ibtrs_map_desc(state, dma_addr, state->dma_len, fmr->fmr->rkey,
			       con->sess->max_desc);

	return 0;
}
/* TODO */
static int ibtrs_map_finish_fr(struct ibtrs_map_state *state,
			       struct ibtrs_con *con, int sg_cnt,
			       unsigned int *sg_offset_p)
{
	struct ib_send_wr *bad_wr;
	struct ib_reg_wr wr;
	struct ibtrs_fr_desc *desc;
	struct ib_pd *pd = con->sess->ib_sess.pd;
	u32 rkey;
	int n;

	if (sg_cnt == 1 && (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY)) {
		unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;

		ibtrs_map_desc(state, sg_dma_address(state->sg) + sg_offset,
			     sg_dma_len(state->sg) - sg_offset,
			     pd->unsafe_global_rkey, con->sess->max_desc);
		if (sg_offset_p)
			*sg_offset_p = 0;
		return 1;
	}

	desc = ibtrs_fr_pool_get(con->fr_pool);
	if (!desc) {
		WRN_RL(con->sess, "Failed to get descriptor from FR pool\n");
		return -ENOMEM;
	}

	rkey = ib_inc_rkey(desc->mr->rkey);
	ib_update_fast_reg_key(desc->mr, rkey);

	memset(&wr, 0, sizeof(wr));
	n = ib_map_mr_sg(desc->mr, state->sg, sg_cnt, sg_offset_p,
			 con->sess->mr_page_size);
	if (unlikely(n < 0)) {
		ibtrs_fr_pool_put(con->fr_pool, &desc, 1);
		return n;
	}

	wr.wr.next = NULL;
	wr.wr.opcode = IB_WR_REG_MR;
	wr.wr.wr_id = FAST_REG_WR_ID_MASK;
	wr.wr.num_sge = 0;
	wr.wr.send_flags = 0;
	wr.mr = desc->mr;
	wr.key = desc->mr->rkey;
	wr.access = (IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE);

	*state->next_fr++ = desc;
	state->nmdesc++;

	ibtrs_map_desc(state, state->base_dma_addr, state->dma_len,
		       desc->mr->rkey, con->sess->max_desc);

	return ib_post_send(con->ib_con.qp, &wr.wr, &bad_wr);
}

static int ibtrs_finish_fmr_mapping(struct ibtrs_map_state *state,
				    struct ibtrs_con *con)
{
	int ret = 0;
	struct ib_pd *pd = con->sess->ib_sess.pd;

	if (state->npages == 0)
		return 0;

	if (state->npages == 1 && (pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY))
		ibtrs_map_desc(state, state->base_dma_addr, state->dma_len,
			       pd->unsafe_global_rkey,
			       con->sess->max_desc);
	else
		ret = ibtrs_map_finish_fmr(state, con);

	if (ret == 0) {
		state->npages = 0;
		state->dma_len = 0;
	}

	return ret;
}

static int ibtrs_map_sg_entry(struct ibtrs_map_state *state,
			      struct ibtrs_con *con, struct scatterlist *sg,
			      int sg_count)
{
	struct ib_device *ibdev = con->sess->ib_device;
	dma_addr_t dma_addr = ib_sg_dma_address(ibdev, sg);
	unsigned int dma_len = ib_sg_dma_len(ibdev, sg);
	unsigned int len;
	int ret;

	if (!dma_len)
		return 0;

	while (dma_len) {
		unsigned offset = dma_addr & ~con->sess->mr_page_mask;

		if (state->npages == con->sess->max_pages_per_mr ||
		    offset != 0) {
			ret = ibtrs_finish_fmr_mapping(state, con);
			if (ret)
				return ret;
		}

		len = min_t(unsigned int, dma_len,
			    con->sess->mr_page_size - offset);

		if (!state->npages)
			state->base_dma_addr = dma_addr;
		state->pages[state->npages++] =
			dma_addr & con->sess->mr_page_mask;
		state->dma_len += len;
		dma_addr += len;
		dma_len -= len;
	}

	/*
	 * If the last entry of the MR wasn't a full page, then we need to
	 * close it out and start a new one -- we can only merge at page
	 * boundaries.
	 */
	ret = 0;
	if (len != con->sess->mr_page_size)
		ret = ibtrs_finish_fmr_mapping(state, con);
	return ret;
}

static int ibtrs_map_fr(struct ibtrs_map_state *state, struct ibtrs_con *con,
			struct scatterlist *sg, int sg_count)
{
	unsigned int sg_offset = 0;
	state->sg = sg;

	while (sg_count) {
		int i, n;

		n = ibtrs_map_finish_fr(state, con, sg_count, &sg_offset);
		if (unlikely(n < 0))
			return n;

		sg_count -= n;
		for (i = 0; i < n; i++)
			state->sg = sg_next(state->sg);
	}

	return 0;
}
static int ibtrs_map_fmr(struct ibtrs_map_state *state, struct ibtrs_con *con,
			 struct scatterlist *sg_first_entry, int
			 sg_first_entry_index, int sg_count)
{
	int i, ret;
	struct scatterlist *sg;

	for (i = sg_first_entry_index, sg = sg_first_entry; i < sg_count;
	     i++, sg = sg_next(sg)) {
		ret = ibtrs_map_sg_entry(state, con, sg, sg_count);
		if (ret)
			return ret;
	}
	return 0;
}

static int ibtrs_map_sg(struct ibtrs_map_state *state, struct ibtrs_con *con,
			struct rdma_req *req)
{
	int ret = 0;

	state->pages = req->map_page;
	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		state->next_fr = req->fr_list;
		ret = ibtrs_map_fr(state, con, req->sglist, req->sg_cnt);
		if (ret)
			goto out;
	} else if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
		state->next_fmr = req->fmr_list;
		ret = ibtrs_map_fmr(state, con, req->sglist, 0,
				    req->sg_cnt);
		if (ret)
			goto out;
		ret = ibtrs_finish_fmr_mapping(state, con);
		if (ret)
			goto out;
	}



out:
	req->nmdesc = state->nmdesc;
	return ret;
}

static int ibtrs_inv_rkey(struct ibtrs_con *con, u32 rkey)
{
	struct ib_send_wr *bad_wr;
	struct ib_send_wr wr = {
		.opcode		    = IB_WR_LOCAL_INV,
		.wr_id		    = LOCAL_INV_WR_ID_MASK,
		.next		    = NULL,
		.num_sge	    = 0,
		.send_flags	    = 0,
		.ex.invalidate_rkey = rkey,
	};

	return ib_post_send(con->ib_con.qp, &wr, &bad_wr);
}

static void ibtrs_unmap_fast_reg_data(struct ibtrs_con *con,
				      struct rdma_req *req)
{
	int i, ret;

	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		struct ibtrs_fr_desc **pfr;

		for (i = req->nmdesc, pfr = req->fr_list; i > 0; i--, pfr++) {
			ret = ibtrs_inv_rkey(con, (*pfr)->mr->rkey);
			if (ret < 0) {
				ERR(con->sess,
				    "Invalidating registered RDMA memory for"
				    " rkey %#x failed, err: %s\n",
				    (*pfr)->mr->rkey, strerror(ret));
			}
		}
		if (req->nmdesc)
			ibtrs_fr_pool_put(con->fr_pool, req->fr_list,
					  req->nmdesc);
	} else {
		struct ib_pool_fmr **pfmr;

		for (i = req->nmdesc, pfmr = req->fmr_list; i > 0; i--, pfmr++)
			ib_fmr_pool_unmap(*pfmr);
	}
	req->nmdesc = 0;
}

/*
 * We have more scatter/gather entries, so use fast_reg_map
 * trying to merge as many entries as we can.
 */
static int ibtrs_fast_reg_map_data(struct ibtrs_con *con,
				   struct ibtrs_sg_desc *desc,
				   struct rdma_req *req)
{
	struct ibtrs_map_state state;
	int ret;

	memset(&state, 0, sizeof(state));
	state.desc	= desc;
	state.dir	= req->dir;
	ret = ibtrs_map_sg(&state, con, req);

	if (unlikely(ret))
		goto unmap;

	if (unlikely(state.ndesc <= 0)) {
		ERR(con->sess,
		    "Could not fit S/G list into buffer descriptor %d\n",
		    state.ndesc);
		ret = -EIO;
		goto unmap;
	}

	return state.ndesc;
unmap:
	ibtrs_unmap_fast_reg_data(con, req);
	return ret;
}

static int ibtrs_post_send_rdma(struct ibtrs_con *con, struct rdma_req *req,
				u64 addr, u32 off, u32 imm)
{
	struct ib_sge list[1];
	u32 cnt = atomic_inc_return(&con->io_cnt);

	pr_debug("called, imm: %x\n", imm);
	if (unlikely(!req->sg_size)) {
		WRN(con->sess, "Doing RDMA Write failed, no data supplied\n");
		return -EINVAL;
	}

	/* user data and user message in the first list element */
	list[0].addr   = req->iu->dma_addr;
	list[0].length = req->sg_size;
	list[0].lkey   = con->sess->ib_sess.pd->local_dma_lkey;

	return ib_post_rdma_write_imm(con->ib_con.qp, list, 1,
				      con->sess->srv_rdma_buf_rkey,
				      addr + off, (u64)req->iu, imm,
				      cnt % (con->sess->queue_depth) ?
				      0 : IB_SEND_SIGNALED);
}

static void ibtrs_set_sge_with_desc(struct ib_sge *list,
				    struct ibtrs_sg_desc *desc)
{
	list->addr   = desc->addr;
	list->length = desc->len;
	list->lkey   = desc->key;
	pr_debug("dma_addr %llu, key %u, dma_len %u\n",
	    desc->addr, desc->key, desc->len);
}

static void ibtrs_set_rdma_desc_last(struct ibtrs_con *con, struct ib_sge *list,
				     struct rdma_req *req,
				     struct ib_rdma_wr *wr, int offset,
				     struct ibtrs_sg_desc *desc, int m,
				     int n, u64 addr, u32 size, u32 imm)
{
	int i;
	struct ibtrs_session *sess = con->sess;
	u32 cnt = atomic_inc_return(&con->io_cnt);

	for (i = m; i < n; i++, desc++)
		ibtrs_set_sge_with_desc(&list[i], desc);

	list[i].addr   = req->iu->dma_addr;
	list[i].length = size;
	list[i].lkey   = sess->ib_sess.pd->local_dma_lkey;
	wr->wr.wr_id = (uintptr_t)req->iu;
	wr->wr.sg_list = &list[m];
	wr->wr.num_sge = n - m + 1;
	wr->remote_addr	= addr + offset;
	wr->rkey	= sess->srv_rdma_buf_rkey;

	wr->wr.opcode	= IB_WR_RDMA_WRITE_WITH_IMM;
	wr->wr.send_flags   = cnt % (sess->queue_depth) ? 0 :
		IB_SEND_SIGNALED;
	wr->wr.ex.imm_data	= cpu_to_be32(imm);
}

static int ibtrs_post_send_rdma_desc_more(struct ibtrs_con *con,
					  struct ib_sge *list,
					  struct rdma_req *req,
					  struct ibtrs_sg_desc *desc, int n,
					  u64 addr, u32 size, u32 imm)
{
	int ret;
	size_t num_sge = 1 + n;
	struct ibtrs_session *sess = con->sess;
	int max_sge = sess->max_sge;
	int num_wr =  DIV_ROUND_UP(num_sge, max_sge);
	struct ib_send_wr *bad_wr;
	struct ib_rdma_wr *wrs, *wr;
	int j = 0, k, offset = 0, len = 0;
	int m = 0;

	wrs = kcalloc(num_wr, sizeof(*wrs), GFP_ATOMIC);
	if (!wrs)
		return -ENOMEM;

	if (num_wr == 1)
		goto last_one;

	for (; j < num_wr; j++) {
		wr = &wrs[j];
		for (k = 0; k < max_sge; k++, desc++) {
			m = k + j * max_sge;
			ibtrs_set_sge_with_desc(&list[m], desc);
			len +=  desc->len;
		}
		wr->wr.wr_id = (uintptr_t)req->iu;
		wr->wr.sg_list = &list[m];
		wr->wr.num_sge = max_sge;
		wr->remote_addr	= addr + offset;
		wr->rkey	= sess->srv_rdma_buf_rkey;

		offset += len;
		wr->wr.next	= &wrs[j + 1].wr;
		wr->wr.opcode	= IB_WR_RDMA_WRITE;
	}

last_one:
	wr = &wrs[j];

	ibtrs_set_rdma_desc_last(con, list, req, wr, offset, desc, m, n, addr,
				 size, imm);

	ret = ib_post_send(con->ib_con.qp, &wrs[0].wr, &bad_wr);
	if (unlikely(ret))
		ERR(sess, "Posting RDMA-Write-Request to QP failed,"
		    " err: %s\n", strerror(ret));
	kfree(wrs);
	return ret;
}

static int ibtrs_post_send_rdma_desc(struct ibtrs_con *con,
				     struct rdma_req *req,
				     struct ibtrs_sg_desc *desc, int n,
				     u64 addr, u32 size, u32 imm)
{
	size_t num_sge = 1 + n;
	struct ib_sge *list;
	int ret, i;
	struct ibtrs_session *sess = con->sess;

	list = kmalloc_array(num_sge, sizeof(*list), GFP_ATOMIC);

	if (!list)
		return -ENOMEM;

	pr_debug("n is %d\n", n);
	if (num_sge < sess->max_sge) {
		u32 cnt = atomic_inc_return(&con->io_cnt);

		for (i = 0; i < n; i++, desc++)
			ibtrs_set_sge_with_desc(&list[i], desc);
		list[i].addr   = req->iu->dma_addr;
		list[i].length = size;
		list[i].lkey   = sess->ib_sess.pd->local_dma_lkey;

		ret = ib_post_rdma_write_imm(con->ib_con.qp, list, num_sge,
					     sess->srv_rdma_buf_rkey,
					     addr, (u64)req->iu, imm,
					     cnt %
					     (sess->queue_depth) ?
					     0 : IB_SEND_SIGNALED);
	} else
		ret = ibtrs_post_send_rdma_desc_more(con, list, req, desc, n,
						     addr, size, imm);

	kfree(list);
	return ret;
}

static int ibtrs_post_send_rdma_more(struct ibtrs_con *con,
				     struct rdma_req *req,
				     u64 addr, u32 size, u32 imm)
{
	int i, ret;
	struct scatterlist *sg;
	struct ib_device *ibdev = con->sess->ib_device;
	size_t num_sge = 1 + req->sg_cnt;
	struct ib_sge *list;
	u32 cnt = atomic_inc_return(&con->io_cnt);

	list = kmalloc_array(num_sge, sizeof(*list), GFP_ATOMIC);

	if (!list)
		return -ENOMEM;

	for_each_sg(req->sglist, sg, req->sg_cnt, i) {
		list[i].addr   = ib_sg_dma_address(ibdev, sg);
		list[i].length = ib_sg_dma_len(ibdev, sg);
		list[i].lkey   = con->sess->ib_sess.pd->local_dma_lkey;
	}
	list[i].addr   = req->iu->dma_addr;
	list[i].length = size;
	list[i].lkey   = con->sess->ib_sess.pd->local_dma_lkey;

	ret = ib_post_rdma_write_imm(con->ib_con.qp, list, num_sge,
				     con->sess->srv_rdma_buf_rkey,
				     addr, (uintptr_t)req->iu, imm,
				     cnt % (con->sess->queue_depth) ?
				     0 : IB_SEND_SIGNALED);

	kfree(list);
	return ret;
}

static int ibtrs_post_recv(struct ibtrs_con *con, struct ibtrs_iu *iu)
{
	int err;
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge list;

	list.addr   = iu->dma_addr;
	list.length = iu->size;
	list.lkey   = con->sess->ib_sess.pd->local_dma_lkey;

	if (WARN_ON(list.length == 0)) {
		WRN(con->sess, "Posting receive work request failed,"
		    " sg list is empty\n");
		return -EINVAL;
	}

	wr.next     = NULL;
	wr.wr_id    = (uintptr_t)iu;
	wr.sg_list  = &list;
	wr.num_sge  = 1;

	err = ib_post_recv(con->ib_con.qp, &wr, &bad_wr);
	if (unlikely(err))
		ERR(con->sess, "Posting receive work request failed, err:"
		    " %s\n", strerror(err));

	return err;
}

static inline int ibtrs_clt_ms_to_id(unsigned long ms)
{
	int id = ms ? ilog2(ms) - MIN_LOG_LATENCY + 1 : 0;

	return clamp(id, 0, MAX_LOG_LATENCY - MIN_LOG_LATENCY + 1);
}

static void ibtrs_clt_update_rdma_lat(struct ibtrs_clt_stats *s, bool read,
				      unsigned long ms)
{
	const int id = ibtrs_clt_ms_to_id(ms);
	const int cpu = raw_smp_processor_id();

	if (read) {
		s->rdma_lat_distr[cpu][id].read++;
		if (s->rdma_lat_max[cpu].read < ms)
			s->rdma_lat_max[cpu].read = ms;
	} else {
		s->rdma_lat_distr[cpu][id].write++;
		if (s->rdma_lat_max[cpu].write < ms)
			s->rdma_lat_max[cpu].write = ms;
	}
}

static inline unsigned long ibtrs_clt_get_raw_ms(void)
{
	struct timespec ts;

	getrawmonotonic(&ts);

	return timespec_to_ms(&ts);
}

static inline void ibtrs_clt_decrease_inflight(struct ibtrs_clt_stats *s)
{
	s->rdma_stats[raw_smp_processor_id()].inflight--;
}

static void process_io_rsp(struct ibtrs_session *sess, u32 msg_id, s16 errno)
{
	struct rdma_req *req;
	void *priv;
	enum dma_data_direction dir;

	if (unlikely(msg_id >= sess->queue_depth)) {
		ERR(sess,
		    "Immediate message with invalid msg id received: %d\n",
		    msg_id);
		return;
	}

	req = &sess->reqs[msg_id];

	pr_debug("Processing io resp for msg_id: %u, %s\n", msg_id,
	    req->dir == DMA_FROM_DEVICE ? "read" : "write");

	if (req->sg_cnt > fmr_sg_cnt)
		ibtrs_unmap_fast_reg_data(req->con, req);
	if (req->sg_cnt)
		ib_dma_unmap_sg(sess->ib_device, req->sglist,
				req->sg_cnt, req->dir);
	if (sess->enable_rdma_lat)
		ibtrs_clt_update_rdma_lat(&sess->stats,
					  req->dir == DMA_FROM_DEVICE,
					  ibtrs_clt_get_raw_ms() -
					  req->start_time);
	ibtrs_clt_decrease_inflight(&sess->stats);

	req->in_use = false;
	req->con    = NULL;
	priv = req->priv;
	dir = req->dir;

	clt_ops->rdma_ev(priv, dir == DMA_FROM_DEVICE ?
			 IBTRS_CLT_RDMA_EV_RDMA_REQUEST_WRITE_COMPL :
			 IBTRS_CLT_RDMA_EV_RDMA_WRITE_COMPL, errno);
}

static int ibtrs_send_msg_user_ack(struct ibtrs_con *con)
{
	int err;

	rcu_read_lock();
	smp_rmb(); /* fence con->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		rcu_read_unlock();
		INFO(con->sess, "Sending user msg ack failed, disconnected"
		     " Connection state is %s, Session state is %s\n",
		     csm_state_str(con->state),
		     ssm_state_str(con->sess->state));
		return -ECOMM;
	}

	err = ibtrs_write_empty_imm(con->ib_con.qp, UINT_MAX - 1,
				    IB_SEND_SIGNALED);
	rcu_read_unlock();
	if (unlikely(err)) {
		ERR_RL(con->sess, "Sending user msg ack failed, err: %s\n",
		       strerror(err));
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&con->sess->heartbeat);
	return 0;
}

static void process_msg_user(struct ibtrs_con *con, struct ibtrs_msg_user *msg)
{
	int len;
	struct ibtrs_session *sess = con->sess;

	len = msg->hdr.tsize - IBTRS_HDR_LEN;

	sess->stats.user_ib_msgs.recv_msg_cnt++;
	sess->stats.user_ib_msgs.recv_size += len;

	clt_ops->recv(sess->priv, (const void *)msg->payl, len);
}

static void process_msg_user_ack(struct ibtrs_con *con)
{
	struct ibtrs_session *sess = con->sess;

	atomic_inc(&sess->peer_usr_msg_bufs);
	wake_up(&con->sess->mu_buf_wait_q);
}

static void msg_worker(struct work_struct *work)
{
	struct msg_work *w;
	struct ibtrs_con *con;
	struct ibtrs_msg_user *msg;

	w = container_of(work, struct msg_work, work);
	con = w->con;
	msg = w->msg;
	kfree(w);
	process_msg_user(con, msg);
	kfree(msg);
}

static int ibtrs_schedule_msg(struct ibtrs_con *con, struct ibtrs_msg_user *msg)
{
	struct msg_work *w;

	w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
	if (!w)
		return -ENOMEM;

	w->con = con;
	w->msg = kmalloc(msg->hdr.tsize, GFP_KERNEL | __GFP_REPEAT);
	if (!w->msg) {
		kfree(w);
		return -ENOMEM;
	}
	memcpy(w->msg, msg, msg->hdr.tsize);
	INIT_WORK(&w->work, msg_worker);
	queue_work(con->sess->msg_wq, &w->work);
	return 0;
}

static void ibtrs_handle_recv(struct ibtrs_con *con, struct ibtrs_iu *iu)
{
	struct ibtrs_msg_hdr *hdr;
	struct ibtrs_session *sess = con->sess;
	int ret;

	hdr = (struct ibtrs_msg_hdr *)iu->buf;
	if (unlikely(ibtrs_validate_message(sess->queue_depth, hdr)))
		goto err1;

	pr_debug("recv completion, type 0x%02x\n",
	    hdr->type);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 8, 1, iu->buf,
			     IBTRS_HDR_LEN, true);

	switch (hdr->type) {
	case IBTRS_MSG_USER:
		ret = ibtrs_schedule_msg(con, iu->buf);
		if (unlikely(ret)) {
			ERR_RL(sess, "Scheduling worker of user message "
			       "to user module failed, err: %s\n",
			       strerror(ret));
			goto err1;
		}
		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret)) {
			ERR_RL(sess, "Posting receive buffer of user message "
			       "to HCA failed, err: %s\n", strerror(ret));
			goto err2;
		}
		ret = ibtrs_send_msg_user_ack(con);
		if (unlikely(ret)) {
			ERR_RL(sess, "Sending ACK for user message failed, "
			       "err: %s\n", strerror(ret));
			goto err2;
		}
		return;
	case IBTRS_MSG_SESS_OPEN_RESP: {
		int err;

		err = process_open_rsp(con, iu->buf);
		if (unlikely(err))
			ssm_schedule_event(con->sess, SSM_EV_CON_ERROR);
		else
			ssm_schedule_event(con->sess, SSM_EV_GOT_RDMA_INFO);
		return;
	}
	default:
		WRN(sess, "Received message of unknown type: 0x%02x\n",
		    hdr->type);
		goto err1;
	}

err1:
	ibtrs_post_recv(con, iu);
err2:
	ERR(sess, "Failed to processes IBTRS message\n");
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static void process_err_wc(struct ibtrs_con *con, struct ib_wc *wc)
{
	struct ibtrs_iu *iu;

	if (wc->wr_id == (uintptr_t)&con->ib_con.beacon) {
		csm_schedule_event(con, CSM_EV_BEACON_COMPLETED);
		return;
	}

	if (wc->wr_id == FAST_REG_WR_ID_MASK ||
	    wc->wr_id == LOCAL_INV_WR_ID_MASK) {
		ERR_RL(con->sess, "Fast registration wr failed: wr_id: %d,"
		       "status: %s\n", (int)wc->wr_id,
		       ib_wc_status_msg(wc->status));
		csm_schedule_event(con, CSM_EV_WC_ERROR);
		return;
	}
	/* only wc->wr_id is ensured to be correct in erroneous WCs,
	 * we can't rely on wc->opcode, use iu->direction to determine if it's
	 * an tx or rx IU
	 */
	iu = (struct ibtrs_iu *)wc->wr_id;
	if (iu && iu->direction == DMA_TO_DEVICE && iu->is_msg)
		put_u_msg_iu(con->sess, iu);

	/* suppress FLUSH_ERR log when the connection is being disconnected */
	if (unlikely(wc->status != IB_WC_WR_FLUSH_ERR ||
		     (con->state != CSM_STATE_CLOSING &&
		      con->state != CSM_STATE_FLUSHING)))
		ERR_RL(con->sess, "wr_id: 0x%llx status: %d (%s),"
		       " type: %d (%s), vendor_err: %x, len: %u,"
		       " connection status: %s\n", wc->wr_id,
		       wc->status, ib_wc_status_msg(wc->status),
		       wc->opcode, ib_wc_opcode_str(wc->opcode),
		       wc->vendor_err, wc->byte_len, csm_state_str(con->state));

	csm_schedule_event(con, CSM_EV_WC_ERROR);
}

static int process_wcs(struct ibtrs_con *con, struct ib_wc *wcs, size_t len)
{
	int i, ret;
	u32 imm;

	for (i = 0; i < len; i++) {
		u32 msg_id;
		s16 errno;
		struct ibtrs_msg_hdr *hdr;
		struct ibtrs_iu *iu;
		struct ib_wc wc = wcs[i];

		if (unlikely(wc.status != IB_WC_SUCCESS)) {
			process_err_wc(con, &wc);
			continue;
		}

		pr_debug("cq complete with wr_id 0x%llx "
		    "status %d (%s) type %d (%s) len %u\n",
		    wc.wr_id, wc.status, ib_wc_status_msg(wc.status), wc.opcode,
		    ib_wc_opcode_str(wc.opcode), wc.byte_len);

		iu = (struct ibtrs_iu *)wc.wr_id;

		switch (wc.opcode) {
		case IB_WC_SEND:
			if (con->user) {
				if (iu == con->sess->sess_info_iu)
					break;
				put_u_msg_iu(con->sess, iu);
				wake_up(&con->sess->mu_iu_wait_q);
			}
			break;
		case IB_WC_RDMA_WRITE:
			break;
		case IB_WC_RECV_RDMA_WITH_IMM:
			ibtrs_set_last_heartbeat(&con->sess->heartbeat);
			imm = be32_to_cpu(wc.ex.imm_data);
			ret = ibtrs_post_recv(con, iu);
			if (ret) {
				ERR(con->sess, "Failed to post receive "
				    "buffer\n");
				csm_schedule_event(con, CSM_EV_CON_ERROR);
			}

			if (imm == UINT_MAX) {
				break;
			} else if (imm == UINT_MAX - 1) {
				process_msg_user_ack(con);
				break;
			}
			msg_id = imm >> 16;
			errno = (imm << 16) >> 16;
			process_io_rsp(con->sess, msg_id, errno);
			break;

		case IB_WC_RECV:
			ibtrs_set_last_heartbeat(&con->sess->heartbeat);

			hdr = (struct ibtrs_msg_hdr *)iu->buf;
			ibtrs_deb_msg_hdr("Received: ", hdr);
			ibtrs_handle_recv(con, iu);
			break;

		default:
			WRN(con->sess, "Unexpected WC type: %s\n",
			    ib_wc_opcode_str(wc.opcode));
		}
	}

	return 0;
}

static void ibtrs_clt_update_wc_stats(struct ibtrs_con *con, int cnt)
{
	short cpu = con->cpu;

	if (cnt > con->sess->stats.wc_comp[cpu].max_wc_cnt)
		con->sess->stats.wc_comp[cpu].max_wc_cnt = cnt;
	con->sess->stats.wc_comp[cpu].cnt++;
	con->sess->stats.wc_comp[cpu].total_cnt += cnt;
}

static int get_process_wcs(struct ibtrs_con *con)
{
	int cnt, err;
	struct ib_wc *wcs = con->wcs;

	do {
		cnt = ib_poll_cq(con->ib_con.cq, ARRAY_SIZE(con->wcs), wcs);
		if (unlikely(cnt < 0)) {
			ERR(con->sess, "Getting work requests from completion"
			    " queue failed, err: %s\n", strerror(cnt));
			return cnt;
		}
		pr_debug("Retrieved %d wcs from CQ\n", cnt);

		if (likely(cnt > 0)) {
			err = process_wcs(con, wcs, cnt);
			if (unlikely(err))
				return err;
			ibtrs_clt_update_wc_stats(con, cnt);
		}
	} while (cnt > 0);

	return 0;
}

static void process_con_rejected(struct ibtrs_con *con,
				 struct rdma_cm_event *event)
{
	const struct ibtrs_msg_error *msg;

	msg = event->param.conn.private_data;
	/* Check if the server has sent some message on the private data.
	 * IB_CM_REJ_CONSUMER_DEFINED is set not only when ibtrs_server
	 * provided private data for the rdma_reject() call, so the data len
	 * needs also to be checked.
	 */
	if (event->status != IB_CM_REJ_CONSUMER_DEFINED ||
	    msg->hdr.type != IBTRS_MSG_ERROR)
		return;

	if (unlikely(ibtrs_validate_message(con->sess->queue_depth, msg))) {
		ERR(con->sess,
		    "Received invalid connection rejected message\n");
		return;
	}

	if (con == &con->sess->con[0] && msg->errno == -EEXIST)
		ERR(con->sess, "Connection rejected by the server,"
		    " session already exists, err: %s\n", strerror(msg->errno));
	else
		ERR(con->sess, "Connection rejected by the server, err: %s\n",
		    strerror(msg->errno));
}

static int ibtrs_clt_rdma_cm_ev_handler(struct rdma_cm_id *cm_id,
					struct rdma_cm_event *event)
{
	struct ibtrs_con *con = cm_id->context;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		pr_debug("addr resolved on cma_id is %p\n", cm_id);
		csm_schedule_event(con, CSM_EV_ADDR_RESOLVED);
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED: {
		struct sockaddr_storage *peer_addr = &con->sess->peer_addr;
		struct sockaddr_storage *self_addr = &con->sess->self_addr;

		pr_debug("route resolved on cma_id is %p\n", cm_id);
		/* initiator is src, target is dst */
		memcpy(peer_addr, &cm_id->route.addr.dst_addr,
		       sizeof(*peer_addr));
		memcpy(self_addr, &cm_id->route.addr.src_addr,
		       sizeof(*self_addr));

		switch (peer_addr->ss_family) {
		case AF_INET:
			pr_debug("Route %pI4->%pI4 resolved\n",
			    &((struct sockaddr_in *)
			      self_addr)->sin_addr.s_addr,
			    &((struct sockaddr_in *)
			      peer_addr)->sin_addr.s_addr);
			break;
		case AF_INET6:
			pr_debug("Route %pI6->%pI6 resolved\n",
			    &((struct sockaddr_in6 *)self_addr)->sin6_addr,
			    &((struct sockaddr_in6 *)peer_addr)->sin6_addr);
			break;
		case AF_IB:
			pr_debug("Route %pI6->%pI6 resolved\n",
			    &((struct sockaddr_ib *)self_addr)->sib_addr,
			    &((struct sockaddr_ib *)peer_addr)->sib_addr);
			break;
		default:
			pr_debug("Route resolved (unknown address family)\n");
		}

		csm_schedule_event(con, CSM_EV_ROUTE_RESOLVED);
		}
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		pr_debug("Connection established\n");

		csm_schedule_event(con, CSM_EV_CON_ESTABLISHED);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
		ERR(con->sess, "Connection establishment error"
		    " (CM event: %s, err: %s)\n",
		    rdma_event_msg(event->event), strerror(event->status));
		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		csm_schedule_event(con, CSM_EV_CON_DISCONNECTED);
		break;

	case RDMA_CM_EVENT_REJECTED:
		/* reject status is defined in enum, not errno */
		ERR_RL(con->sess,
		       "Connection rejected (CM event: %s, err: %s)\n",
		       rdma_event_msg(event->event),
		       rdma_reject_msg(cm_id, event->status));
		process_con_rejected(con, event);
		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;

	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_ADDR_CHANGE: {
		ERR_RL(con->sess, "CM error (CM event: %s, err: %s)\n",
		       rdma_event_msg(event->event), strerror(event->status));

		csm_schedule_event(con, CSM_EV_CON_ERROR);
		break;
	}
	case RDMA_CM_EVENT_DEVICE_REMOVAL: {
		struct completion dc;

		ERR_RL(con->sess, "CM error (CM event: %s, err: %s)\n",
		       rdma_event_msg(event->event), strerror(event->status));

		con->device_being_removed = true;
		init_completion(&dc);
		con->sess->ib_sess_destroy_completion = &dc;

		/* Generating a CON_ERROR event will cause the SSM to close all
		 * the connections and try to reconnect. Wait until all
		 * connections are closed and the ib session destroyed before
		 * returning to the ib core code.
		 */
		csm_schedule_event(con, CSM_EV_CON_ERROR);
		wait_for_completion(&dc);
		con->sess->ib_sess_destroy_completion = NULL;

		/* return 1 so cm_id is destroyed afterwards */
		return 1;
	}
	default:
		WRN(con->sess, "Ignoring unexpected CM event %s, err: %s\n",
		    rdma_event_msg(event->event), strerror(event->status));
		break;
	}
	return 0;
}

static void handle_cq_comp(struct ibtrs_con *con)
{
	int err;

	err = get_process_wcs(con);
	if (unlikely(err))
		goto error;

	while ((err = ib_req_notify_cq(con->ib_con.cq, IB_CQ_NEXT_COMP |
				       IB_CQ_REPORT_MISSED_EVENTS)) > 0) {
		pr_debug("Missed %d CQ notifications, processing missed WCs...\n",
		    err);
		err = get_process_wcs(con);
		if (unlikely(err))
			goto error;
	}

	if (unlikely(err))
		goto error;

	return;

error:
	ERR(con->sess, "Failed to get WCs from CQ, err: %s\n", strerror(err));
	csm_schedule_event(con, CSM_EV_CON_ERROR);
}

static inline void tasklet_handle_cq_comp(unsigned long data)
{
	struct ibtrs_con *con = (struct ibtrs_con *)data;

	handle_cq_comp(con);
}

static inline void wrapper_handle_cq_comp(struct work_struct *work)
{
	struct ibtrs_con *con = container_of(work, struct ibtrs_con, cq_work);

	handle_cq_comp(con);
}

static void cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct ibtrs_con *con = ctx;
	int cpu = raw_smp_processor_id();

	if (unlikely(con->cpu != cpu)) {
		pr_debug_ratelimited("WC processing is migrated from CPU %d to %d, cstate %s,"
		       " sstate %s, user: %s\n", con->cpu,
		       cpu, csm_state_str(con->state),
		       ssm_state_str(con->sess->state),
		       con->user ? "true" : "false");
		atomic_inc(&con->sess->stats.cpu_migr.from[con->cpu]);
		con->sess->stats.cpu_migr.to[cpu]++;
	}

	/* queue_work() can return False here.
	 * The work can be already queued, When CQ notifications were already
	 * activiated and are activated again after the beacon was posted.
	 */
	if (con->user)
		queue_work(con->cq_wq, &con->cq_work);
	else
		tasklet_schedule(&con->cq_tasklet);
}

static int post_io_con_recv(struct ibtrs_con *con)
{
	int i, ret;
	struct ibtrs_iu *dummy_rx_iu = con->sess->dummy_rx_iu;

	for (i = 0; i < con->sess->queue_depth; i++) {
		ret = ibtrs_post_recv(con, dummy_rx_iu);
		if (unlikely(ret)) {
			WRN(con->sess,
			    "Posting receive buffers to HCA failed, err:"
			    " %s\n", strerror(ret));
			return ret;
		}
	}
	return 0;
}

static int post_usr_con_recv(struct ibtrs_con *con)
{
	int i, ret;

	for (i = 0; i < USR_CON_BUF_SIZE; i++) {
		struct ibtrs_iu *iu = con->sess->usr_rx_ring[i];

		ret = ibtrs_post_recv(con, iu);
		if (unlikely(ret)) {
			WRN(con->sess,
			    "Posting receive buffers to HCA failed, err:"
			    " %s\n", strerror(ret));
			return ret;
		}
	}
	return 0;
}

static int post_init_con_recv(struct ibtrs_con *con)
{
	int ret;

	ret = ibtrs_post_recv(con, con->sess->rdma_info_iu);
	if (unlikely(ret))
		WRN(con->sess,
		    "Posting rdma info iu to HCA failed, err: %s\n",
		    strerror(ret));
	return ret;
}

static int post_recv(struct ibtrs_con *con)
{
	if (con->user)
		return post_init_con_recv(con);
	else
		return post_io_con_recv(con);
}

static void fail_outstanding_req(struct ibtrs_con *con, struct rdma_req *req)
{
	void *priv;
	enum dma_data_direction dir;

	if (!req->in_use)
		return;

	if (req->sg_cnt > fmr_sg_cnt)
		ibtrs_unmap_fast_reg_data(con, req);
	if (req->sg_cnt)
		ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
				req->sg_cnt, req->dir);
	ibtrs_clt_decrease_inflight(&con->sess->stats);

	req->in_use = false;
	req->con    = NULL;
	priv = req->priv;
	dir = req->dir;

	clt_ops->rdma_ev(priv, dir == DMA_FROM_DEVICE ?
			 IBTRS_CLT_RDMA_EV_RDMA_REQUEST_WRITE_COMPL :
			 IBTRS_CLT_RDMA_EV_RDMA_WRITE_COMPL, -ECONNABORTED);

	pr_debug("Canceled outstanding request\n");
}

static void fail_outstanding_reqs(struct ibtrs_con *con)
{
	struct ibtrs_session *sess = con->sess;
	int i;

	if (!sess->reqs)
		return;
	for (i = 0; i < sess->queue_depth; ++i) {
		if (sess->reqs[i].con == con)
			fail_outstanding_req(con, &sess->reqs[i]);
	}
}

static void fail_all_outstanding_reqs(struct ibtrs_session *sess)
{
	int i;

	if (!sess->reqs)
		return;
	for (i = 0; i < sess->queue_depth; ++i)
		fail_outstanding_req(sess->reqs[i].con, &sess->reqs[i]);
}

static void ibtrs_free_reqs(struct ibtrs_session *sess)
{
	struct rdma_req *req;
	int i;

	if (!sess->reqs)
		return;

	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];

		if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
			kfree(req->fr_list);
			req->fr_list = NULL;
		} else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
			kfree(req->fmr_list);
			req->fmr_list = NULL;
		}

		kfree(req->map_page);
		req->map_page = NULL;
	}

	kfree(sess->reqs);
	sess->reqs = NULL;
}

static int ibtrs_alloc_reqs(struct ibtrs_session *sess)
{
	struct rdma_req *req = NULL;
	void *mr_list = NULL;
	int i;

	sess->reqs = kcalloc(sess->queue_depth, sizeof(*sess->reqs),
			     GFP_KERNEL);
	if (!sess->reqs)
		return -ENOMEM;

	for (i = 0; i < sess->queue_depth; ++i) {
		req = &sess->reqs[i];
		mr_list = kmalloc_array(sess->max_pages_per_mr,
					sizeof(void *), GFP_KERNEL);
		if (!mr_list)
			goto out;

		if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR)
			req->fr_list = mr_list;
		else if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
			req->fmr_list = mr_list;

		req->map_page = kmalloc(sess->max_pages_per_mr *
					sizeof(void *), GFP_KERNEL);
		if (!req->map_page)
			goto out;
	}

	return 0;

out:
	ibtrs_free_reqs(sess);
	return -ENOMEM;
}

static void free_sess_rx_bufs(struct ibtrs_session *sess)
{
	int i;

	if (!sess->usr_rx_ring)
		return;

	for (i = 0; i < USR_CON_BUF_SIZE; ++i)
		if (sess->usr_rx_ring[i])
			ibtrs_iu_free(sess->usr_rx_ring[i],
				      DMA_FROM_DEVICE,
				      sess->ib_device);

	kfree(sess->usr_rx_ring);
	sess->usr_rx_ring = NULL;
}

static void free_sess_tx_bufs(struct ibtrs_session *sess, bool check)
{
	struct ibtrs_iu *e, *next;
	int i;

	if (!sess->io_tx_ius)
		return;

	for (i = 0; i < sess->queue_depth; i++)
		if (sess->io_tx_ius[i])
			ibtrs_iu_free(sess->io_tx_ius[i], DMA_TO_DEVICE,
				      sess->ib_device);

	kfree(sess->io_tx_ius);
	sess->io_tx_ius = NULL;

	i = 0;
	list_for_each_entry_safe(e, next, &sess->u_msg_ius_list, list) {
		list_del(&e->list);
		ibtrs_iu_free(e, DMA_TO_DEVICE, sess->ib_device);
		i++;
	}
	WARN_ON(check && i != USR_CON_BUF_SIZE);

}

static void free_sess_fast_pool(struct ibtrs_session *sess)
{
	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
		if (sess->fmr_pool)
			ib_destroy_fmr_pool(sess->fmr_pool);
		sess->fmr_pool = NULL;
	}
}

static void free_sess_tr_bufs(struct ibtrs_session *sess)
{
	free_sess_rx_bufs(sess);
	free_sess_tx_bufs(sess, true);
}

static void free_sess_init_bufs(struct ibtrs_session *sess)
{
	if (sess->rdma_info_iu) {
		ibtrs_iu_free(sess->rdma_info_iu, DMA_FROM_DEVICE,
			      sess->ib_device);
		sess->rdma_info_iu = NULL;
	}

	if (sess->dummy_rx_iu) {
		ibtrs_iu_free(sess->dummy_rx_iu, DMA_FROM_DEVICE,
			      sess->ib_device);
		sess->dummy_rx_iu = NULL;
	}

	if (sess->sess_info_iu) {
		ibtrs_iu_free(sess->sess_info_iu, DMA_TO_DEVICE,
			      sess->ib_device);
		sess->sess_info_iu = NULL;
	}
}

static void free_io_bufs(struct ibtrs_session *sess)
{
	ibtrs_free_reqs(sess);
	free_sess_fast_pool(sess);
	kfree(sess->tags_map);
	sess->tags_map = NULL;
	kfree(sess->tags);
	sess->tags = NULL;
	sess->io_bufs_initialized = false;
}

static void free_sess_bufs(struct ibtrs_session *sess)
{
	free_sess_init_bufs(sess);
	free_io_bufs(sess);
}

static struct ib_fmr_pool *alloc_fmr_pool(struct ibtrs_session *sess)
{
	struct ib_fmr_pool_param fmr_param;

	memset(&fmr_param, 0, sizeof(fmr_param));
	fmr_param.pool_size	    = sess->queue_depth *
				      sess->max_pages_per_mr;
	fmr_param.dirty_watermark   = fmr_param.pool_size / 4;
	fmr_param.cache		    = 0;
	fmr_param.max_pages_per_fmr = sess->max_pages_per_mr;
	fmr_param.page_shift	    = ilog2(sess->mr_page_size);
	fmr_param.access	    = (IB_ACCESS_LOCAL_WRITE |
				       IB_ACCESS_REMOTE_WRITE);

	return ib_create_fmr_pool(sess->ib_sess.pd, &fmr_param);
}

static int alloc_sess_rx_bufs(struct ibtrs_session *sess)
{
	int i;
	u32 max_req_size = sess->max_req_size;

	sess->usr_rx_ring = kcalloc(USR_CON_BUF_SIZE,
				    sizeof(*sess->usr_rx_ring),
				    GFP_KERNEL);
	if (!sess->usr_rx_ring)
		goto err;

	for (i = 0; i < USR_CON_BUF_SIZE; ++i) {
		/* alloc recv buffer, open rep is the biggest */
		sess->usr_rx_ring[i] = ibtrs_iu_alloc(i, max_req_size,
						      GFP_KERNEL,
						      sess->ib_device,
						      DMA_FROM_DEVICE, true);
		if (!sess->usr_rx_ring[i]) {
			WRN(sess, "Failed to allocate IU for RX ring\n");
			goto err;
		}
	}

	return 0;

err:
	free_sess_rx_bufs(sess);

	return -ENOMEM;
}

static int alloc_sess_fast_pool(struct ibtrs_session *sess)
{
	int err = 0;
	struct ib_fmr_pool *fmr_pool;

	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR) {
		fmr_pool = alloc_fmr_pool(sess);
		if (IS_ERR(fmr_pool)) {
			err = PTR_ERR(fmr_pool);
			ERR(sess, "FMR pool allocation failed, err: %s\n",
			    strerror(err));
			return err;
		}
		sess->fmr_pool = fmr_pool;
	}
	return err;
}

static int alloc_sess_init_bufs(struct ibtrs_session *sess)
{
	sess->sess_info_iu = ibtrs_iu_alloc(0, MSG_SESS_INFO_SIZE, GFP_KERNEL,
			       sess->ib_device, DMA_TO_DEVICE, true);
	if (unlikely(!sess->sess_info_iu)) {
		ERR_RL(sess, "Can't allocate transfer buffer for "
			     "sess hostname\n");
		return -ENOMEM;
	}
	sess->rdma_info_iu =
		ibtrs_iu_alloc(0,
			       IBTRS_MSG_SESS_OPEN_RESP_LEN(MAX_SESS_QUEUE_DEPTH),
			       GFP_KERNEL, sess->ib_device,
			       DMA_FROM_DEVICE, true);
	if (!sess->rdma_info_iu) {
		WRN(sess, "Failed to allocate IU to receive "
			  "RDMA INFO message\n");
		goto err;
	}

	sess->dummy_rx_iu =
		ibtrs_iu_alloc(0, IBTRS_HDR_LEN,
			       GFP_KERNEL, sess->ib_device,
			       DMA_FROM_DEVICE, true);
	if (!sess->dummy_rx_iu) {
		WRN(sess, "Failed to allocate IU to receive "
			  "immediate messages on io connections\n");
		goto err;
	}

	return 0;

err:
	free_sess_init_bufs(sess);

	return -ENOMEM;
}

static int alloc_sess_tx_bufs(struct ibtrs_session *sess)
{
	int i;
	struct ibtrs_iu *iu;
	u32 max_req_size = sess->max_req_size;

	INIT_LIST_HEAD(&sess->u_msg_ius_list);
	spin_lock_init(&sess->u_msg_ius_lock);

	sess->io_tx_ius = kcalloc(sess->queue_depth, sizeof(*sess->io_tx_ius),
				  GFP_KERNEL);
	if (!sess->io_tx_ius)
		goto err;

	for (i = 0; i < sess->queue_depth; ++i) {
		iu = ibtrs_iu_alloc(i, max_req_size, GFP_KERNEL,
				    sess->ib_device, DMA_TO_DEVICE,false);
		if (!iu) {
			WRN(sess, "Failed to allocate IU for TX buffer\n");
			goto err;
		}
		sess->io_tx_ius[i] = iu;
	}

	for (i = 0; i < USR_CON_BUF_SIZE; ++i) {
		iu = ibtrs_iu_alloc(i, max_req_size, GFP_KERNEL,
				    sess->ib_device, DMA_TO_DEVICE,
				    true);
		if (!iu) {
			WRN(sess, "Failed to allocate IU for TX buffer\n");
			goto err;
		}
		list_add(&iu->list, &sess->u_msg_ius_list);
	}
	return 0;

err:
	free_sess_tx_bufs(sess, false);

	return -ENOMEM;
}

static int alloc_sess_tr_bufs(struct ibtrs_session *sess)
{
	int err;

	err = alloc_sess_rx_bufs(sess);
	if (!err)
		err = alloc_sess_tx_bufs(sess);

	return err;
}

static int alloc_sess_tags(struct ibtrs_session *sess)
{
	int err, i;

	sess->tags_map = kzalloc(BITS_TO_LONGS(sess->queue_depth) *
				 sizeof(long), GFP_KERNEL);
	if (!sess->tags_map) {
		ERR(sess, "Failed to alloc tags bitmap\n");
		err = -ENOMEM;
		goto out_err;
	}

	sess->tags = kcalloc(sess->queue_depth, TAG_SIZE(sess),
			     GFP_KERNEL);
	if (!sess->tags) {
		ERR(sess, "Failed to alloc memory for tags\n");
		err = -ENOMEM;
		goto err_map;
	}

	for (i = 0; i < sess->queue_depth; i++) {
		struct ibtrs_tag *tag;

		tag = GET_TAG(sess, i);
		tag->mem_id = i;
		tag->mem_id_mask = i << ((IB_IMM_SIZE_BITS - 1) -
					 ilog2(sess->queue_depth - 1));
	}

	return 0;

err_map:
	kfree(sess->tags_map);
	sess->tags_map = NULL;
out_err:
	return err;
}

static int connect_qp(struct ibtrs_con *con)
{
	int err;
	struct rdma_conn_param conn_param;
	struct ibtrs_msg_sess_open somsg;
	struct ibtrs_msg_con_open comsg;

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.retry_count = retry_count;

	if (con->user) {
		if (CONS_PER_SESSION > U8_MAX)
			return -EINVAL;
		fill_ibtrs_msg_sess_open(&somsg, CONS_PER_SESSION, &uuid);
		conn_param.private_data		= &somsg;
		conn_param.private_data_len	= sizeof(somsg);
		conn_param.rnr_retry_count	= 7;
	} else {
		fill_ibtrs_msg_con_open(&comsg, &uuid);
		conn_param.private_data		= &comsg;
		conn_param.private_data_len	= sizeof(comsg);
	}
	err = rdma_connect(con->cm_id, &conn_param);
	if (err) {
		ERR(con->sess, "Establishing RDMA connection failed, err:"
		    " %s\n", strerror(err));
		return err;
	}

	pr_debug("rdma_connect successful\n");
	return 0;
}

static int resolve_addr(struct ibtrs_con *con,
			const struct sockaddr_storage *addr)
{
	int err;

	err = rdma_resolve_addr(con->cm_id, NULL,
				(struct sockaddr *)addr, 1000);
	if (err)
		/* TODO: Include the address in message that was
		 * tried to resolve can be a AF_INET, AF_INET6
		 * or an AF_IB address
		 */
		ERR(con->sess, "Resolving server address failed, err: %s\n",
		    strerror(err));
	return err;
}

static int resolve_route(struct ibtrs_con *con)
{
	int err;

	err = rdma_resolve_route(con->cm_id, 1000);
	if (err)
		ERR(con->sess, "Resolving route failed, err: %s\n",
		    strerror(err));

	return err;
}

static int query_fast_reg_mode(struct ibtrs_con *con)
{
	struct ib_device *ibdev = con->sess->ib_device;
	struct ib_device_attr *dev_attr = &ibdev->attrs;
	int mr_page_shift;
	u64 max_pages_per_mr;


	if (ibdev->alloc_fmr && ibdev->dealloc_fmr &&
	    ibdev->map_phys_fmr && ibdev->unmap_fmr) {
		con->sess->fast_reg_mode = IBTRS_FAST_MEM_FMR;
		INFO(con->sess, "Device %s supports FMR\n", ibdev->name);
	}
	if (dev_attr->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS &&
	    use_fr) {
		con->sess->fast_reg_mode = IBTRS_FAST_MEM_FR;
		INFO(con->sess, "Device %s supports FR\n", ibdev->name);
	}

	/*
	 * Use the smallest page size supported by the HCA, down to a
	 * minimum of 4096 bytes. We're unlikely to build large sglists
	 * out of smaller entries.
	 */
	mr_page_shift		= max(12, ffs(dev_attr->page_size_cap) - 1);
	con->sess->mr_page_size	= 1 << mr_page_shift;
	con->sess->max_sge	= dev_attr->max_sge;
	con->sess->mr_page_mask	= ~((u64)con->sess->mr_page_size - 1);
	max_pages_per_mr	= dev_attr->max_mr_size;
	do_div(max_pages_per_mr, con->sess->mr_page_size);
	con->sess->max_pages_per_mr = min_t(u64, con->sess->max_pages_per_mr,
					    max_pages_per_mr);
	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		con->sess->max_pages_per_mr =
			min_t(u32, con->sess->max_pages_per_mr,
			      dev_attr->max_fast_reg_page_list_len);
	}
	con->sess->mr_max_size	= con->sess->mr_page_size *
				  con->sess->max_pages_per_mr;
	pr_debug("%s: mr_page_shift = %d, dev_attr->max_mr_size = %#llx, "
	    "dev_attr->max_fast_reg_page_list_len = %u, max_pages_per_mr = %d, "
	    "mr_max_size = %#x\n", ibdev->name, mr_page_shift,
	    dev_attr->max_mr_size, dev_attr->max_fast_reg_page_list_len,
	    con->sess->max_pages_per_mr, con->sess->mr_max_size);
	return 0;
}

static int send_heartbeat(struct ibtrs_session *sess)
{
	int err;
	struct ibtrs_con *con;

	con = &sess->con[0];

	rcu_read_lock();
	smp_rmb(); /* fence con->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		rcu_read_unlock();
		ERR_RL(sess, "Sending heartbeat message failed, not connected."
		       " Connection state changed to %s!\n",
		       csm_state_str(con->state));
		return -ECOMM;
	}

	err = ibtrs_write_empty_imm(con->ib_con.qp, UINT_MAX, IB_SEND_SIGNALED);
	rcu_read_unlock();
	if (unlikely(err)) {
		WRN(sess, "Sending heartbeat failed, posting msg to QP failed,"
		    " err: %s\n", strerror(err));
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);

	return err;
}

static void heartbeat_work(struct work_struct *work)
{
	int err;
	struct ibtrs_session *sess;

	sess = container_of(to_delayed_work(work), struct ibtrs_session,
			    heartbeat_dwork);

	if (ibtrs_heartbeat_timeout_is_expired(&sess->heartbeat)) {
		ssm_schedule_event(sess, SSM_EV_RECONNECT_HEARTBEAT);
		return;
	}

	ibtrs_heartbeat_warn(&sess->heartbeat);

	if (ibtrs_heartbeat_send_ts_diff_ms(&sess->heartbeat) >=
	    HEARTBEAT_INTV_MS) {
		err = send_heartbeat(sess);
		if (unlikely(err))
			WRN(sess, "Sending heartbeat failed, err: %s\n",
			    strerror(err));
	}

	if (!schedule_delayed_work(&sess->heartbeat_dwork,
				   HEARTBEAT_INTV_JIFFIES))
		WRN(sess, "Schedule heartbeat work failed, already queued?\n");
}

static int create_cm_id_con(const struct sockaddr_storage *addr,
			    struct ibtrs_con *con)
{
	int err;

	if (addr->ss_family == AF_IB)
		con->cm_id = rdma_create_id(&init_net,
					    ibtrs_clt_rdma_cm_ev_handler, con,
					    RDMA_PS_IB, IB_QPT_RC);
	else
		con->cm_id = rdma_create_id(&init_net,
					    ibtrs_clt_rdma_cm_ev_handler, con,
					    RDMA_PS_TCP, IB_QPT_RC);

	if (IS_ERR(con->cm_id)) {
		err = PTR_ERR(con->cm_id);
		WRN(con->sess, "Failed to create CM ID, err: %s\n",
		    strerror(err));
		con->cm_id = NULL;
		return err;
	}

	return 0;
}

static int create_ib_sess(struct ibtrs_con *con)
{
	int err;
	struct ibtrs_session *sess = con->sess;

	if (atomic_read(&sess->ib_sess_initialized) == 1)
		return 0;

	if (WARN_ON(!con->cm_id->device)) {
		WRN(sess, "Invalid CM ID device\n");
		return -EINVAL;
	}

	// TODO ib_device_hold(con->cm_id->device);
	sess->ib_device = con->cm_id->device;

	/* For performance reasons, we don't allow a session to be created if
	 * the number of completion vectors available in the hardware is not
	 * enough to have one interrupt per CPU.
	 */
	if (sess->ib_device->num_comp_vectors < num_online_cpus()) {
		WRN(sess,
		    "%d cq vectors available, not enough to have one IRQ per"
		    " CPU, >= %d vectors required, contine anyway.\n",
		    sess->ib_device->num_comp_vectors, num_online_cpus());
	}

	err = ib_session_init(sess->ib_device, &sess->ib_sess);
	if (err) {
		WRN(sess, "Failed to initialize IB session, err: %s\n",
		    strerror(err));
		goto err_out;
	}

	err = query_fast_reg_mode(con);
	if (err) {
		WRN(sess, "Failed to query fast registration mode, err: %s\n",
		    strerror(err));
		goto err_sess;
	}

	err = alloc_sess_init_bufs(sess);
	if (err) {
		ERR(sess, "Failed to allocate session buffers, err: %s\n",
		    strerror(err));
		goto err_sess;
	}

	sess->msg_wq = alloc_ordered_workqueue("sess_msg_wq", 0);
	if (!sess->msg_wq) {
		ERR(sess, "Failed to create user message workqueue\n");
		err = -ENOMEM;
		goto err_buff;
	}

	atomic_set(&sess->ib_sess_initialized, 1);

	return 0;

err_buff:
	free_sess_init_bufs(sess);
err_sess:
	ib_session_destroy(&sess->ib_sess);
err_out:
	// TODO ib_device_put(sess->ib_device);
	sess->ib_device = NULL;
	return err;
}

static void ibtrs_clt_destroy_ib_session(struct ibtrs_session *sess)
{
	if (sess->ib_device) {
		free_sess_bufs(sess);
		destroy_workqueue(sess->msg_wq);
		// TODO ib_device_put(sess->ib_device);
		sess->ib_device = NULL;
	}

	if (atomic_cmpxchg(&sess->ib_sess_initialized, 1, 0) == 1)
		ib_session_destroy(&sess->ib_sess);

	if (sess->ib_sess_destroy_completion)
		complete_all(sess->ib_sess_destroy_completion);
}

static void free_con_fast_pool(struct ibtrs_con *con)
{
	if (con->user)
		return;
	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
		return;
	if (con->sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		ibtrs_destroy_fr_pool(con->fr_pool);
		con->fr_pool = NULL;
	}
}

static int alloc_con_fast_pool(struct ibtrs_con *con)
{
	int err = 0;
	struct ibtrs_fr_pool *fr_pool;
	struct ibtrs_session *sess = con->sess;

	if (con->user)
		return 0;

	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FMR)
		return 0;

	if (sess->fast_reg_mode == IBTRS_FAST_MEM_FR) {
		fr_pool = alloc_fr_pool(sess);
		if (IS_ERR(fr_pool)) {
			err = PTR_ERR(fr_pool);
			ERR(sess, "FR pool allocation failed, err: %s\n",
			    strerror(err));
			return err;
		}
		con->fr_pool = fr_pool;
	}

	return err;
}

static void ibtrs_clt_destroy_cm_id(struct ibtrs_con *con)
{
	if (!con->device_being_removed) {
		rdma_destroy_id(con->cm_id);
		con->cm_id = NULL;
	}
}

static void con_destroy(struct ibtrs_con *con)
{
	if (con->user) {
		cancel_delayed_work_sync(&con->sess->heartbeat_dwork);
		drain_workqueue(con->cq_wq);
		cancel_work_sync(&con->cq_work);
	}
	fail_outstanding_reqs(con);
	ib_con_destroy(&con->ib_con);
	free_con_fast_pool(con);
	if (con->user)
		free_sess_tr_bufs(con->sess);
	ibtrs_clt_destroy_cm_id(con);

	/* notify possible user msg ACK thread waiting for a tx iu or user msg
	 * buffer so they can check the connection state, give up waiting and
	 * put back any tx_iu reserved
	 */
	if (con->user) {
		wake_up(&con->sess->mu_buf_wait_q);
		wake_up(&con->sess->mu_iu_wait_q);
	}
}

int ibtrs_clt_stats_migration_cnt_to_str(struct ibtrs_session *sess, char *buf,
					 size_t len)
{
	int i;
	size_t used = 0;

	used += scnprintf(buf + used, len - used, "    ");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " CPU%u", i);

	used += scnprintf(buf + used, len - used, "\nfrom:");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " %d",
				 atomic_read(&sess->stats.cpu_migr.from[i]));

	used += scnprintf(buf + used, len - used, "\n"
			 "to  :");

	for (i = 0; i < num_online_cpus(); i++)
		used += scnprintf(buf + used, len - used, " %d",
				 sess->stats.cpu_migr.to[i]);

	used += scnprintf(buf + used, len - used, "\n");

	return used;
}

int ibtrs_clt_reset_reconnects_stat(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.reconnects, 0,
		       sizeof(sess->stats.reconnects));
		return 0;
	} else {
		return -EINVAL;
	}
}

int ibtrs_clt_stats_reconnects_to_str(struct ibtrs_session *sess, char *buf,
				      size_t len)
{
	return scnprintf(buf, len, "%u %u\n",
			sess->stats.reconnects.successful_cnt,
			sess->stats.reconnects.fail_cnt);
}

int ibtrs_clt_reset_user_ib_msgs_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		memset(&sess->stats.user_ib_msgs, 0,
		       sizeof(sess->stats.user_ib_msgs));
		return 0;
	} else {
		return -EINVAL;
	}
}

int ibtrs_clt_stats_user_ib_msgs_to_str(struct ibtrs_session *sess, char *buf,
					size_t len)
{
	return scnprintf(buf, len, "%u %llu %u %llu\n",
			sess->stats.user_ib_msgs.recv_msg_cnt,
			sess->stats.user_ib_msgs.recv_size,
			sess->stats.user_ib_msgs.sent_msg_cnt,
			sess->stats.user_ib_msgs.sent_size);
}

static u32 ibtrs_clt_stats_get_max_wc_cnt(struct ibtrs_session *sess)
{
	int i;
	u32 max = 0;

	for (i = 0; i < num_online_cpus(); i++)
		if (max < sess->stats.wc_comp[i].max_wc_cnt)
			max = sess->stats.wc_comp[i].max_wc_cnt;
	return max;
}

static u32 ibtrs_clt_stats_get_avg_wc_cnt(struct ibtrs_session *sess)
{
	int i;
	u32 cnt = 0;
	u64 sum = 0;

	for (i = 0; i < num_online_cpus(); i++) {
		sum += sess->stats.wc_comp[i].total_cnt;
		cnt += sess->stats.wc_comp[i].cnt;
	}

	return cnt ? sum / cnt : 0;
}

int ibtrs_clt_stats_wc_completion_to_str(struct ibtrs_session *sess, char *buf,
					 size_t len)
{
	return scnprintf(buf, len, "%u %u\n",
			ibtrs_clt_stats_get_max_wc_cnt(sess),
			ibtrs_clt_stats_get_avg_wc_cnt(sess));
}

static void sess_destroy_handler(struct work_struct *work)
{
	struct sess_destroy_sm_wq_work *w;

	w = container_of(work, struct sess_destroy_sm_wq_work, work);

	put_sess(w->sess);
	kfree(w);
}

static void sess_schedule_destroy(struct ibtrs_session *sess)
{
	struct sess_destroy_sm_wq_work *w;

	while (true) {
		w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_REPEAT);
		if (w)
			break;
		cond_resched();
	}

	w->sess = sess;
	INIT_WORK(&w->work, sess_destroy_handler);
	ibtrs_clt_destroy_sess_files(&sess->kobj, &sess->kobj_stats);
	queue_work(ibtrs_wq, &w->work);
}

int ibtrs_clt_reset_wc_comp_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		memset(sess->stats.wc_comp, 0,
		       num_online_cpus() * sizeof(*sess->stats.wc_comp));
		return 0;
	} else {
		return -EINVAL;
	}
}

static int ibtrs_clt_init_wc_comp_stats(struct ibtrs_session *sess)
{
	sess->stats.wc_comp = kcalloc(num_online_cpus(),
				      sizeof(*sess->stats.wc_comp),
				      GFP_KERNEL);
	if (!sess->stats.wc_comp)
		return -ENOMEM;

	return 0;
}

int ibtrs_clt_reset_cpu_migr_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		memset(sess->stats.cpu_migr.from, 0,
		       num_online_cpus() *
		       sizeof(*sess->stats.cpu_migr.from));

		memset(sess->stats.cpu_migr.to, 0,
		       num_online_cpus() * sizeof(*sess->stats.cpu_migr.to));
		return 0;
	} else {
		return -EINVAL;
	}
}

static int ibtrs_clt_init_cpu_migr_stats(struct ibtrs_session *sess)
{
	sess->stats.cpu_migr.from = kcalloc(num_online_cpus(),
					    sizeof(*sess->stats.cpu_migr.from),
					    GFP_KERNEL);
	if (!sess->stats.cpu_migr.from)
		return -ENOMEM;

	sess->stats.cpu_migr.to = kcalloc(num_online_cpus(),
					  sizeof(*sess->stats.cpu_migr.to),
					  GFP_KERNEL);
	if (!sess->stats.cpu_migr.to) {
		kfree(sess->stats.cpu_migr.from);
		sess->stats.cpu_migr.from = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int ibtrs_clt_init_sg_list_distr_stats(struct ibtrs_session *sess)
{
	int i;

	sess->stats.sg_list_distr = kmalloc_array(num_online_cpus(),
					    sizeof(*sess->stats.sg_list_distr),
					    GFP_KERNEL);

	if (!sess->stats.sg_list_distr)
		return -ENOMEM;

	for (i = 0; i < num_online_cpus(); i++) {
		sess->stats.sg_list_distr[i] =
			kzalloc_node(sizeof(*sess->stats.sg_list_distr[0]) *
				     (SG_DISTR_LEN + 1),
				     GFP_KERNEL, cpu_to_node(i));
		if (!sess->stats.sg_list_distr[i])
			goto err;
	}

	sess->stats.sg_list_total = kcalloc(num_online_cpus(),
					sizeof(*sess->stats.sg_list_total),
					GFP_KERNEL);
	if (!sess->stats.sg_list_total)
		goto err;

	return 0;

err:
	for (; i > 0; i--)
		kfree(sess->stats.sg_list_distr[i - 1]);

	kfree(sess->stats.sg_list_distr);
	sess->stats.sg_list_distr = NULL;

	return -ENOMEM;
}

int ibtrs_clt_reset_sg_list_distr_stats(struct ibtrs_session *sess,
					bool enable)
{
	int i;

	if (enable) {
		memset(sess->stats.sg_list_total, 0,
		       num_online_cpus() *
		       sizeof(*sess->stats.sg_list_total));

		for (i = 0; i < num_online_cpus(); i++)
			memset(sess->stats.sg_list_distr[i], 0,
			       sizeof(*sess->stats.sg_list_distr[0]) *
			       (SG_DISTR_LEN + 1));
		return 0;
	} else {
		return -EINVAL;
	}
}

ssize_t ibtrs_clt_stats_rdma_lat_distr_to_str(struct ibtrs_session *sess,
					      char *page, size_t len)
{
	ssize_t cnt = 0;
	int i, cpu;
	struct ibtrs_clt_stats *s = &sess->stats;
	struct ibtrs_clt_stats_rdma_lat_entry res[MAX_LOG_LATENCY -
						  MIN_LOG_LATENCY + 2];
	struct ibtrs_clt_stats_rdma_lat_entry max;

	max.write	= 0;
	max.read	= 0;
	for (cpu = 0; cpu < num_online_cpus(); cpu++) {
		if (max.write < s->rdma_lat_max[cpu].write)
			max.write = s->rdma_lat_max[cpu].write;
		if (max.read < s->rdma_lat_max[cpu].read)
			max.read = s->rdma_lat_max[cpu].read;
	}

	for (i = 0; i < ARRAY_SIZE(res); i++) {
		res[i].write	= 0;
		res[i].read	= 0;
		for (cpu = 0; cpu < num_online_cpus(); cpu++) {
			res[i].write += s->rdma_lat_distr[cpu][i].write;
			res[i].read += s->rdma_lat_distr[cpu][i].read;
		}
	}

	for (i = 0; i < ARRAY_SIZE(res) - 1; i++)
		cnt += scnprintf(page + cnt, len - cnt,
				 "< %6d ms: %llu %llu\n",
				 1 << (i + MIN_LOG_LATENCY), res[i].read,
				 res[i].write);
	cnt += scnprintf(page + cnt, len - cnt, ">= %5d ms: %llu %llu\n",
			 1 << (i - 1 + MIN_LOG_LATENCY), res[i].read,
			 res[i].write);
	cnt += scnprintf(page + cnt, len - cnt, " maximum ms: %llu %llu\n",
			 max.read, max.write);

	return cnt;
}

int ibtrs_clt_reset_rdma_lat_distr_stats(struct ibtrs_session *sess,
					 bool enable)
{
	int i;
	struct ibtrs_clt_stats *s = &sess->stats;

	if (enable) {
		memset(s->rdma_lat_max, 0,
		       num_online_cpus() * sizeof(*s->rdma_lat_max));

		for (i = 0; i < num_online_cpus(); i++)
			memset(s->rdma_lat_distr[i], 0,
			       sizeof(*s->rdma_lat_distr[0]) *
			       (MAX_LOG_LATENCY - MIN_LOG_LATENCY + 2));
	}
	sess->enable_rdma_lat = enable;
	return 0;
}

static int ibtrs_clt_init_rdma_lat_distr_stats(struct ibtrs_session *sess)
{
	int i;
	struct ibtrs_clt_stats *s = &sess->stats;

	s->rdma_lat_max = kzalloc(num_online_cpus() *
				  sizeof(*s->rdma_lat_max), GFP_KERNEL);
	if (!s->rdma_lat_max)
		return -ENOMEM;

	s->rdma_lat_distr = kmalloc_array(num_online_cpus(),
					  sizeof(*s->rdma_lat_distr),
					  GFP_KERNEL);
	if (!s->rdma_lat_distr)
		goto err1;

	for (i = 0; i < num_online_cpus(); i++) {
		s->rdma_lat_distr[i] =
			kzalloc_node(sizeof(*s->rdma_lat_distr[0]) *
				     (MAX_LOG_LATENCY - MIN_LOG_LATENCY + 2),
				     GFP_KERNEL, cpu_to_node(i));
		if (!s->rdma_lat_distr[i])
			goto err2;
	}

	return 0;

err2:
	for (; i >= 0; i--)
		kfree(s->rdma_lat_distr[i]);

	kfree(s->rdma_lat_distr);
	s->rdma_lat_distr = NULL;
err1:
	kfree(s->rdma_lat_max);
	s->rdma_lat_max = NULL;

	return -ENOMEM;
}

int ibtrs_clt_reset_rdma_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		struct ibtrs_clt_stats *s = &sess->stats;

		memset(s->rdma_stats, 0,
		       num_online_cpus() * sizeof(*s->rdma_stats));
		return 0;
	} else {
		return -EINVAL;
	}
}

static int ibtrs_clt_init_rdma_stats(struct ibtrs_session *sess)
{
	struct ibtrs_clt_stats *s = &sess->stats;

	s->rdma_stats = kcalloc(num_online_cpus(), sizeof(*s->rdma_stats),
				GFP_KERNEL);
	if (!s->rdma_stats)
		return -ENOMEM;

	return 0;
}

ssize_t ibtrs_clt_reset_all_help(struct ibtrs_session *sess,
				 char *page, size_t len)
{
	return scnprintf(page, len, "echo 1 to reset all statistics\n");
}

int ibtrs_clt_reset_all_stats(struct ibtrs_session *sess, bool enable)
{
	if (enable) {
		ibtrs_clt_reset_rdma_stats(sess, enable);
		ibtrs_clt_reset_rdma_lat_distr_stats(sess, enable);
		ibtrs_clt_reset_sg_list_distr_stats(sess, enable);
		ibtrs_clt_reset_cpu_migr_stats(sess, enable);
		ibtrs_clt_reset_user_ib_msgs_stats(sess, enable);
		ibtrs_clt_reset_reconnects_stat(sess, enable);
		ibtrs_clt_reset_wc_comp_stats(sess, enable);
		return 0;
	} else {
		return -EINVAL;
	}
}

static int ibtrs_clt_init_stats(struct ibtrs_session *sess)
{
	int err;

	err = ibtrs_clt_init_sg_list_distr_stats(sess);
	if (err) {
		ERR(sess,
		    "Failed to init S/G list distribution stats, err: %s\n",
		    strerror(err));
		return err;
	}

	err = ibtrs_clt_init_cpu_migr_stats(sess);
	if (err) {
		ERR(sess, "Failed to init CPU migration stats, err: %s\n",
		    strerror(err));
		goto err_sg_list;
	}

	err = ibtrs_clt_init_rdma_lat_distr_stats(sess);
	if (err) {
		ERR(sess,
		    "Failed to init RDMA lat distribution stats, err: %s\n",
		    strerror(err));
		goto err_migr;
	}

	err = ibtrs_clt_init_wc_comp_stats(sess);
	if (err) {
		ERR(sess, "Failed to init WC completion stats, err: %s\n",
		    strerror(err));
		goto err_rdma_lat;
	}

	err = ibtrs_clt_init_rdma_stats(sess);
	if (err) {
		ERR(sess, "Failed to init RDMA stats, err: %s\n",
		    strerror(err));
		goto err_wc_comp;
	}

	return 0;

err_wc_comp:
	ibtrs_clt_free_wc_comp_stats(sess);
err_rdma_lat:
	ibtrs_clt_free_rdma_lat_stats(sess);
err_migr:
	ibtrs_clt_free_cpu_migr_stats(sess);
err_sg_list:
	ibtrs_clt_free_sg_list_distr_stats(sess);
	return err;
}

static void ibtrs_clt_sess_reconnect_worker(struct work_struct *work)
{
	struct ibtrs_session *sess = container_of(to_delayed_work(work),
						  struct ibtrs_session,
						  reconnect_dwork);

	ssm_schedule_event(sess, SSM_EV_RECONNECT);
}

static int sess_init_cons(struct ibtrs_session *sess)
{
	int i;

	for (i = 0; i < CONS_PER_SESSION; i++) {
		struct ibtrs_con *con = &sess->con[i];

		csm_set_state(con, CSM_STATE_CLOSED);
		con->sess = sess;
		if (!i) {
			INIT_WORK(&con->cq_work, wrapper_handle_cq_comp);
			con->cq_wq =
				alloc_ordered_workqueue("ibtrs_clt_wq",
							WQ_HIGHPRI);
			if (!con->cq_wq) {
				ERR(sess, "Failed to allocate cq workqueue.\n");
				return -ENOMEM;
			}
		} else {
			tasklet_init(&con->cq_tasklet,
				     tasklet_handle_cq_comp, (unsigned
							      long)(con));
		}
	}

	return 0;
}

static struct ibtrs_session *sess_init(const struct sockaddr_storage *addr,
				       size_t pdu_sz, void *priv,
				       u8 reconnect_delay_sec,
				       u16 max_segments,
				       s16 max_reconnect_attempts)
{
	int err;
	struct ibtrs_session *sess;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		err = -ENOMEM;
		goto err;
	}
	atomic_set(&sess->refcount, 1);
	sess->sm_wq = create_workqueue("sess_sm_wq");

	if (!sess->sm_wq) {
		pr_err("Failed to create SSM workqueue\n");
		err = -ENOMEM;
		goto err_free_sess;
	}

	sess->peer_addr	= *addr;
	sess->pdu_sz	= pdu_sz;
	sess->priv	= priv;
	sess->con	= kcalloc(CONS_PER_SESSION, sizeof(*sess->con),
				  GFP_KERNEL);
	if (!sess->con) {
		err = -ENOMEM;
		goto err_free_sm_wq;
	}

	sess->rdma_info_iu = NULL;
	err = sess_init_cons(sess);
	if (err) {
		pr_err("Failed to initialize cons\n");
		goto err_free_con;
	}

	err = ibtrs_clt_init_stats(sess);
	if (err) {
		pr_err("Failed to initialize statistics\n");
		goto err_cons;
	}

	sess->reconnect_delay_sec	= reconnect_delay_sec;
	sess->max_reconnect_attempts	= max_reconnect_attempts;
	sess->max_pages_per_mr		= max_segments;
	init_waitqueue_head(&sess->wait_q);
	init_waitqueue_head(&sess->mu_iu_wait_q);
	init_waitqueue_head(&sess->mu_buf_wait_q);

	init_waitqueue_head(&sess->tags_wait);
	sess->state = SSM_STATE_IDLE;
	mutex_lock(&sess_mutex);
	list_add(&sess->list, &sess_list);
	mutex_unlock(&sess_mutex);

	ibtrs_set_heartbeat_timeout(&sess->heartbeat,
				    default_heartbeat_timeout_ms <
				    MIN_HEARTBEAT_TIMEOUT_MS ?
				    MIN_HEARTBEAT_TIMEOUT_MS :
				    default_heartbeat_timeout_ms);
	atomic64_set(&sess->heartbeat.send_ts_ms, 0);
	atomic64_set(&sess->heartbeat.recv_ts_ms, 0);
	sess->heartbeat.addr = sess->addr;
	sess->heartbeat.hostname = sess->hostname;

	INIT_DELAYED_WORK(&sess->heartbeat_dwork, heartbeat_work);
	INIT_DELAYED_WORK(&sess->reconnect_dwork,
			  ibtrs_clt_sess_reconnect_worker);

	return sess;

err_cons:
	sess_deinit_cons(sess);
err_free_con:
	kfree(sess->con);
	sess->con = NULL;
err_free_sm_wq:
	destroy_workqueue(sess->sm_wq);
err_free_sess:
	kfree(sess);
err:
	return ERR_PTR(err);
}

static int init_con(struct ibtrs_session *sess, struct ibtrs_con *con,
		    short cpu, bool user)
{
	int err;

	con->sess			= sess;
	con->cpu			= cpu;
	con->user			= user;
	con->device_being_removed	= false;

	err = create_cm_id_con(&sess->peer_addr, con);
	if (err) {
		ERR(sess, "Failed to create CM ID for connection\n");
		return err;
	}

	csm_set_state(con, CSM_STATE_RESOLVING_ADDR);
	err = resolve_addr(con, &sess->peer_addr);
	if (err) {
		ERR(sess, "Failed to resolve address, err: %s\n",
		    strerror(err));
		goto err_cm_id;
	}

	sess->active_cnt++;

	return 0;

err_cm_id:
	csm_set_state(con, CSM_STATE_CLOSED);
	ibtrs_clt_destroy_cm_id(con);

	return err;
}

static int create_con(struct ibtrs_con *con)
{
	int err, cq_vector;
	u16 cq_size, wr_queue_size;
	struct ibtrs_session *sess = con->sess;
	int num_wr = DIV_ROUND_UP(con->sess->max_pages_per_mr,
				  con->sess->max_sge);

	if (con->user) {
		err = create_ib_sess(con);
		if (err) {
			ERR(sess,
			    "Failed to create IB session, err: %s\n",
			    strerror(err));
			goto err_cm_id;
		}
		cq_size		= USR_CON_BUF_SIZE + 1;
		wr_queue_size	= USR_CON_BUF_SIZE + 1;
	} else {
		err = ib_get_max_wr_queue_size(sess->ib_device);
		if (err < 0)
			goto err_cm_id;
		cq_size		= sess->queue_depth;
		wr_queue_size	= min_t(int, err - 1,
					sess->queue_depth * num_wr *
					(use_fr ? 3 : 2));
	}

	err = alloc_con_fast_pool(con);
	if (err) {
		ERR(sess, "Failed to allocate fast memory "
		    "pool, err: %s\n", strerror(err));
		goto err_cm_id;
	}
	con->ib_con.addr = sess->addr;
	con->ib_con.hostname = sess->hostname;
	cq_vector = con->cpu % sess->ib_device->num_comp_vectors;
	err = ib_con_init(&con->ib_con, con->cm_id,
			  sess->max_sge, cq_event_handler, con, cq_vector,
			  cq_size, wr_queue_size, &sess->ib_sess);
	if (err) {
		ERR(sess,
		    "Failed to initialize IB connection, err: %s\n",
		    strerror(err));
		goto err_pool;
	}

	pr_debug("setup_buffers successful\n");
	err = post_recv(con);
	if (err)
		goto err_ib_con;

	err = connect_qp(con);
	if (err) {
		ERR(con->sess, "Failed to connect QP, err: %s\n",
		    strerror(err));
		goto err_wq;
	}

	pr_debug("connect qp successful\n");
	atomic_set(&con->io_cnt, 0);
	return 0;

err_wq:
	rdma_disconnect(con->cm_id);
err_ib_con:
	ib_con_destroy(&con->ib_con);
err_pool:
	free_con_fast_pool(con);
err_cm_id:
	ibtrs_clt_destroy_cm_id(con);

	return err;
}

struct ibtrs_session *ibtrs_clt_open(const struct sockaddr_storage *addr,
				     size_t pdu_sz, void *priv,
				     u8 reconnect_delay_sec, u16 max_segments,
				     s16 max_reconnect_attempts)
{
	int err;
	struct ibtrs_session *sess;
	char str_addr[IBTRS_ADDRLEN];

	if (!clt_ops_are_valid(clt_ops)) {
		pr_err("User module did not register ops callbacks\n");
		err = -EINVAL;
		goto err;
	}

	err = ibtrs_addr_to_str(addr, str_addr, sizeof(str_addr));
	if (err < 0) {
		pr_err("Establishing session to server failed, converting"
		       " addr from binary to string failed, err: %s\n",
		       strerror(err));
		return ERR_PTR(err);
	}

	pr_info("Establishing session to server %s\n", str_addr);

	sess = sess_init(addr, pdu_sz, priv, reconnect_delay_sec,
			 max_segments, max_reconnect_attempts);
	if (IS_ERR(sess)) {
		pr_err("Establishing session to %s failed, err: %s\n",
		       str_addr, strerror(PTR_ERR(sess)));
		err = PTR_ERR(sess);
		goto err;
	}

	get_sess(sess);
	strlcpy(sess->addr, str_addr, sizeof(sess->addr));
	err = init_con(sess, &sess->con[0], 0, true);
	if (err) {
		ERR(sess, "Establishing session to server failed,"
		    " failed to init user connection, err: %s\n",
		    strerror(err));
		/* Always return 'No route to host' when the connection can't be
		 * established.
		 */
		err = -EHOSTUNREACH;
		goto err1;
	}

	err = wait_for_ssm_state(sess, SSM_STATE_CONNECTED);
	if (err) {
		ERR(sess, "Establishing session to server failed,"
		    " failed to establish connections, err: %s\n",
		    strerror(err));
		put_sess(sess);
		goto err; /* state machine will do the clean up. */
	}
	err = ibtrs_clt_create_sess_files(&sess->kobj, &sess->kobj_stats,
					  sess->addr);
	if (err) {
		ERR(sess, "Establishing session to server failed,"
		    " failed to create session sysfs files, err: %s\n",
		    strerror(err));
		put_sess(sess);
		ibtrs_clt_close(sess);
		goto err;
	}

	put_sess(sess);
	return sess;

err1:
	destroy_workqueue(sess->sm_wq);
	sess_deinit_cons(sess);
	kfree(sess->con);
	sess->con = NULL;
	ibtrs_clt_free_stats(sess);
	mutex_lock(&sess_mutex);
	list_del(&sess->list);
	mutex_unlock(&sess_mutex);
	kfree(sess);
err:
	return ERR_PTR(err);
}
EXPORT_SYMBOL(ibtrs_clt_open);

int ibtrs_clt_close(struct ibtrs_session *sess)
{
	struct completion dc;

	INFO(sess, "Session will be disconnected\n");

	init_completion(&dc);
	sess->destroy_completion = &dc;
	ssm_schedule_event(sess, SSM_EV_SESS_CLOSE);
	wait_for_completion(&dc);

	return 0;
}
EXPORT_SYMBOL(ibtrs_clt_close);

int ibtrs_clt_reconnect(struct ibtrs_session *sess)
{
	ssm_schedule_event(sess, SSM_EV_RECONNECT_USER);

	INFO(sess, "Session reconnect event queued\n");

	return 0;
}

void ibtrs_clt_set_max_reconnect_attempts(struct ibtrs_session *sess, s16 value)
{
	sess->max_reconnect_attempts = value;
}

s16
inline ibtrs_clt_get_max_reconnect_attempts(const struct ibtrs_session *sess)
{
	return sess->max_reconnect_attempts;
}

static inline
void ibtrs_clt_record_sg_distr(u64 *stat, u64 *total, unsigned int cnt)
{
	int i;

	i = cnt > MAX_LIN_SG ? ilog2(cnt) + MAX_LIN_SG - MIN_LOG_SG + 1 : cnt;
	i = i > SG_DISTR_LEN ? SG_DISTR_LEN : i;

	stat[i]++;
	(*total)++;
}

static int ibtrs_clt_rdma_write_desc(struct ibtrs_con *con,
				     struct rdma_req *req, u64 buf,
				     size_t u_msg_len, u32 imm,
				     struct ibtrs_msg_rdma_write *msg)
{
	int ret;
	size_t ndesc = con->sess->max_pages_per_mr;
	struct ibtrs_sg_desc *desc;

	desc = kmalloc_array(ndesc, sizeof(*desc), GFP_ATOMIC);
	if (!desc) {
		ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
				req->sg_cnt, req->dir);
		return -ENOMEM;
	}
	ret = ibtrs_fast_reg_map_data(con, desc, req);
	if (unlikely(ret < 0)) {
		ERR_RL(con->sess,
		       "RDMA-Write failed, fast reg. data mapping"
		       " failed, err: %s\n", strerror(ret));
		ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
				req->sg_cnt, req->dir);
		kfree(desc);
		return ret;
	}
	ret = ibtrs_post_send_rdma_desc(con, req, desc, ret, buf,
					u_msg_len + sizeof(*msg), imm);
	if (unlikely(ret)) {
		ERR(con->sess, "RDMA-Write failed, posting work"
		    " request failed, err: %s\n", strerror(ret));
		ibtrs_unmap_fast_reg_data(con, req);
		ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
				req->sg_cnt, req->dir);
	}
	kfree(desc);
	return ret;
}

static int ibtrs_clt_rdma_write_sg(struct ibtrs_con *con, struct rdma_req *req,
				   const struct kvec *vec, size_t u_msg_len,
				   size_t data_len)
{
	int count = 0;
	struct ibtrs_msg_rdma_write *msg;
	u32 imm;
	int ret;
	int buf_id;
	u64 buf;

	const u32 tsize = sizeof(*msg) + data_len + u_msg_len;

	if (unlikely(tsize > con->sess->chunk_size)) {
		WRN_RL(con->sess, "RDMA-Write failed, data size too big %d >"
		       " %d\n", tsize, con->sess->chunk_size);
		return -EMSGSIZE;
	}
	if (req->sg_cnt) {
		count = ib_dma_map_sg(con->sess->ib_device, req->sglist,
				      req->sg_cnt, req->dir);
		if (unlikely(!count)) {
			WRN_RL(con->sess,
			       "RDMA-Write failed, dma map failed\n");
			return -EINVAL;
		}
	}

	copy_from_kvec(req->iu->buf, vec, u_msg_len);

	/* put ibtrs msg after sg and user message */
	msg		= req->iu->buf + u_msg_len;
	msg->hdr.type	= IBTRS_MSG_RDMA_WRITE;
	msg->hdr.tsize	= tsize;

	/* ibtrs message on server side will be after user data and message */
	imm = req->tag->mem_id_mask + data_len + u_msg_len;
	buf_id = req->tag->mem_id;
	req->sg_size = data_len + u_msg_len + sizeof(*msg);

	buf = con->sess->srv_rdma_addr[buf_id];
	if (count > fmr_sg_cnt)
		return ibtrs_clt_rdma_write_desc(con, req, buf, u_msg_len, imm,
						 msg);

	ret = ibtrs_post_send_rdma_more(con, req, buf, u_msg_len + sizeof(*msg),
					imm);
	if (unlikely(ret)) {
		ERR(con->sess, "RDMA-Write failed, posting work"
		    " request failed, err: %s\n", strerror(ret));
		if (count)
			ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
					req->sg_cnt, req->dir);
	}
	return ret;
}

static void ibtrs_clt_update_rdma_stats(struct ibtrs_clt_stats *s,
					size_t size, bool read)
{
	int cpu = raw_smp_processor_id();

	if (read) {
		s->rdma_stats[cpu].cnt_read++;
		s->rdma_stats[cpu].size_total_read += size;
	} else {
		s->rdma_stats[cpu].cnt_write++;
		s->rdma_stats[cpu].size_total_write += size;
	}

	s->rdma_stats[cpu].inflight++;
}

/**
 * ibtrs_rdma_con_id() - returns RDMA connection id
 *
 * Note:
 *     RDMA connection starts from 1.
 *     0 connection is for user messages.
 */
static inline int ibtrs_rdma_con_id(struct ibtrs_tag *tag)
{
	return (tag->cpu_id % (CONS_PER_SESSION - 1)) + 1;
}

int ibtrs_clt_rdma_write(struct ibtrs_session *sess, struct ibtrs_tag *tag,
			 void *priv, const struct kvec *vec, size_t nr,
			 size_t data_len, struct scatterlist *sg,
			 unsigned int sg_len)
{
	struct ibtrs_iu *iu;
	struct rdma_req *req;
	int err;
	struct ibtrs_con *con;
	int con_id;
	size_t u_msg_len;

	smp_rmb(); /* fence sess->state check */
	if (unlikely(sess->state != SSM_STATE_CONNECTED)) {
		ERR_RL(sess,
		       "RDMA-Write failed, not connected (session state %s)\n",
		       ssm_state_str(sess->state));
		return -ECOMM;
	}

	u_msg_len = kvec_length(vec, nr);
	if (unlikely(u_msg_len > IO_MSG_SIZE)) {
		WRN_RL(sess, "RDMA-Write failed, user message size"
		       " is %zu B big, max size is %d B\n", u_msg_len,
		       IO_MSG_SIZE);
		return -EMSGSIZE;
	}

	con_id = ibtrs_rdma_con_id(tag);
	if (WARN_ON(con_id >= CONS_PER_SESSION))
		return -EINVAL;
	con = &sess->con[con_id];
	rcu_read_lock();
	smp_rmb(); /* fence con->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		rcu_read_unlock();
		ERR_RL(sess, "RDMA-Write failed, not connected"
		       " (connection %d state %s)\n",
		       con_id,
		       csm_state_str(con->state));
		return -ECOMM;
	}

	iu = sess->io_tx_ius[tag->mem_id];
	req = &sess->reqs[tag->mem_id];
	req->con	= con;
	req->tag	= tag;
	if (sess->enable_rdma_lat)
		req->start_time = ibtrs_clt_get_raw_ms();
	req->in_use	= true;

	req->iu		= iu;
	req->sglist	= sg;
	req->sg_cnt	= sg_len;
	req->priv	= priv;
	req->dir        = DMA_TO_DEVICE;

	err = ibtrs_clt_rdma_write_sg(con, req, vec, u_msg_len, data_len);
	rcu_read_unlock();
	if (unlikely(err)) {
		req->in_use = false;
		ERR_RL(sess, "RDMA-Write failed, failed to transfer scatter"
		       " gather list, err: %s\n", strerror(err));
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
	ibtrs_clt_record_sg_distr(sess->stats.sg_list_distr[tag->cpu_id],
				  &sess->stats.sg_list_total[tag->cpu_id],
				  sg_len);
	ibtrs_clt_update_rdma_stats(&sess->stats, u_msg_len + data_len, false);

	return err;
}
EXPORT_SYMBOL(ibtrs_clt_rdma_write);

static int ibtrs_clt_request_rdma_write_sg(struct ibtrs_con *con,
					   struct rdma_req *req,
					   const struct kvec *vec,
					   size_t u_msg_len,
					   size_t result_len)
{
	int count, i, ret;
	struct ibtrs_msg_req_rdma_write *msg;
	u32 imm;
	int buf_id;
	struct scatterlist *sg;
	struct ib_device *ibdev = con->sess->ib_device;
	const u32 tsize = sizeof(*msg) + result_len + u_msg_len;

	if (unlikely(tsize > con->sess->chunk_size)) {
		WRN_RL(con->sess, "Request-RDMA-Write failed, message size is"
		       " %d, bigger than CHUNK_SIZE %d\n", tsize,
			con->sess->chunk_size);
		return -EMSGSIZE;
	}

	count = ib_dma_map_sg(ibdev, req->sglist, req->sg_cnt, req->dir);

	if (unlikely(!count)) {
		WRN_RL(con->sess,
		       "Request-RDMA-Write failed, dma map failed\n");
		return -EINVAL;
	}

	req->data_len = result_len;
	copy_from_kvec(req->iu->buf, vec, u_msg_len);

	/* put our message into req->buf after user message*/
	msg		= req->iu->buf + u_msg_len;
	msg->hdr.type	= IBTRS_MSG_REQ_RDMA_WRITE;
	msg->hdr.tsize	= tsize;
	msg->sg_cnt	= count;

	if (WARN_ON(msg->hdr.tsize > con->sess->chunk_size))
		return -EINVAL;
	if (count > fmr_sg_cnt) {
		ret = ibtrs_fast_reg_map_data(con, msg->desc, req);
		if (ret < 0) {
			ERR_RL(con->sess,
			       "Request-RDMA-Write failed, failed to map fast"
			       " reg. data, err: %s\n", strerror(ret));
			ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
					req->sg_cnt, req->dir);
			return ret;
		}
		msg->sg_cnt = ret;
	} else {
		for_each_sg(req->sglist, sg, req->sg_cnt, i) {
			msg->desc[i].addr = ib_sg_dma_address(ibdev, sg);
			msg->desc[i].key = con->sess->ib_sess.mr->rkey;
			msg->desc[i].len = ib_sg_dma_len(ibdev, sg);
			pr_debug("desc addr %llu, len %u, i %d tsize %u\n",
			    msg->desc[i].addr, msg->desc[i].len, i,
			    msg->hdr.tsize);
		}
		req->nmdesc = 0;
	}
	/* ibtrs message will be after the space reserved for disk data and
	 * user message
	 */
	imm = req->tag->mem_id_mask + result_len + u_msg_len;
	buf_id = req->tag->mem_id;

	req->sg_size = sizeof(*msg) + msg->sg_cnt * IBTRS_SG_DESC_LEN +
		u_msg_len;
	ret = ibtrs_post_send_rdma(con, req, con->sess->srv_rdma_addr[buf_id],
				   result_len, imm);
	if (unlikely(ret)) {
		ERR(con->sess, "Request-RDMA-Write failed,"
		    " posting work request failed, err: %s\n", strerror(ret));

		if (unlikely(count > fmr_sg_cnt)) {
			ibtrs_unmap_fast_reg_data(con, req);
			ib_dma_unmap_sg(con->sess->ib_device, req->sglist,
					req->sg_cnt, req->dir);
		}
	}
	return ret;
}

int ibtrs_clt_request_rdma_write(struct ibtrs_session *sess,
				 struct ibtrs_tag *tag, void *priv,
				 const struct kvec *vec, size_t nr,
				 size_t result_len,
				 struct scatterlist *recv_sg,
				 unsigned int recv_sg_len)
{
	struct ibtrs_iu *iu;
	struct rdma_req *req;
	int err;
	struct ibtrs_con *con;
	int con_id;
	size_t u_msg_len;

	smp_rmb(); /* fence sess->state check */
	if (unlikely(sess->state != SSM_STATE_CONNECTED)) {
		ERR_RL(sess,
		       "Request-RDMA-Write failed, not connected (session"
		       " state %s)\n", ssm_state_str(sess->state));
		return -ECOMM;
	}

	u_msg_len = kvec_length(vec, nr);
	if (unlikely(u_msg_len > IO_MSG_SIZE ||
		     sizeof(struct ibtrs_msg_req_rdma_write) +
		     recv_sg_len * IBTRS_SG_DESC_LEN > sess->max_req_size)) {
		WRN_RL(sess, "Request-RDMA-Write failed, user message size"
		       " is %zu B big, max size is %d B\n", u_msg_len,
		       IO_MSG_SIZE);
		return -EMSGSIZE;
	}

	con_id = ibtrs_rdma_con_id(tag);
	if (WARN_ON(con_id >= CONS_PER_SESSION))
		return -EINVAL;
	con = &sess->con[con_id];
	rcu_read_lock();
	smp_rmb(); /* fence con->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		rcu_read_unlock();
		ERR_RL(sess, "RDMA-Write failed, not connected"
		       " (connection %d state %s)\n",
		       con_id,
		       csm_state_str(con->state));
		return -ECOMM;
	}

	iu = sess->io_tx_ius[tag->mem_id];
	req = &sess->reqs[tag->mem_id];
	req->con	= con;
	req->tag	= tag;
	if (sess->enable_rdma_lat)
		req->start_time = ibtrs_clt_get_raw_ms();
	req->in_use	= true;

	req->iu		= iu;
	req->sglist	= recv_sg;
	req->sg_cnt	= recv_sg_len;
	req->priv	= priv;
	req->dir        = DMA_FROM_DEVICE;

	err = ibtrs_clt_request_rdma_write_sg(con, req, vec,
					      u_msg_len, result_len);
	rcu_read_unlock();
	if (unlikely(err)) {
		req->in_use = false;
		ERR_RL(sess, "Request-RDMA-Write failed, failed to transfer"
		       " scatter gather list, err: %s\n", strerror(err));
		return err;
	}

	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);
	ibtrs_clt_record_sg_distr(sess->stats.sg_list_distr[tag->cpu_id],
				  &sess->stats.sg_list_total[tag->cpu_id],
				  recv_sg_len);
	ibtrs_clt_update_rdma_stats(&sess->stats, u_msg_len + result_len, true);

	return err;
}
EXPORT_SYMBOL(ibtrs_clt_request_rdma_write);

static bool ibtrs_clt_get_usr_msg_buf(struct ibtrs_session *sess)
{
	return atomic_dec_if_positive(&sess->peer_usr_msg_bufs) >= 0;
}

int ibtrs_clt_send(struct ibtrs_session *sess, const struct kvec *vec,
		   size_t nr)
{
	struct ibtrs_con *con;
	struct ibtrs_iu *iu = NULL;
	struct ibtrs_msg_user *msg;
	size_t len;
	bool closed_st = false;
	int err = 0;

	con = &sess->con[0];

	smp_rmb(); /* fence sess->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED ||
		     sess->state != SSM_STATE_CONNECTED)) {
		ERR_RL(sess, "Sending user message failed, not connected,"
		       " Connection state is %s, Session state is %s\n",
		       csm_state_str(con->state), ssm_state_str(sess->state));
		return -ECOMM;
	}

	len = kvec_length(vec, nr);

	pr_debug("send user msg length=%zu, peer_msg_buf %d\n", len,
	    atomic_read(&sess->peer_usr_msg_bufs));
	if (len > sess->max_req_size - IBTRS_HDR_LEN) {
		ERR_RL(sess, "Sending user message failed,"
		       " user message length too large (len: %zu)\n", len);
		return -EMSGSIZE;
	}

	wait_event(sess->mu_buf_wait_q,
		   (closed_st = (con->state != CSM_STATE_CONNECTED ||
				 sess->state != SSM_STATE_CONNECTED)) ||
		   ibtrs_clt_get_usr_msg_buf(sess));

	if (unlikely(closed_st)) {
		ERR_RL(sess, "Sending user message failed, not connected"
		       " Connection state is %s, Session state is %s\n",
		       csm_state_str(con->state), ssm_state_str(sess->state));
		return -ECOMM;
	}

	wait_event(sess->mu_iu_wait_q,
		   (closed_st = (con->state != CSM_STATE_CONNECTED ||
				 sess->state != SSM_STATE_CONNECTED)) ||
		   (iu = get_u_msg_iu(sess)) != NULL);

	if (unlikely(closed_st)) {
		ERR_RL(sess, "Sending user message failed, not connected"
		       " Connection state is %s, Session state is %s\n",
		       csm_state_str(con->state), ssm_state_str(sess->state));
		err = -ECOMM;
		goto err_iu;
	}

	rcu_read_lock();
	smp_rmb(); /* fence con->state check */
	if (unlikely(con->state != CSM_STATE_CONNECTED)) {
		rcu_read_unlock();
		ERR_RL(sess, "Sending user message failed, not connected,"
		       " Connection state is %s, Session state is %s\n",
		       csm_state_str(con->state), ssm_state_str(sess->state));
		err = -ECOMM;
		goto err_post_send;
	}

	msg		= iu->buf;
	msg->hdr.type	= IBTRS_MSG_USER;
	msg->hdr.tsize	= IBTRS_HDR_LEN + len;
	copy_from_kvec(msg->payl, vec, len);

	ibtrs_deb_msg_hdr("Sending: ", &msg->hdr);
	err = ibtrs_post_send(con->ib_con.qp, con->sess->ib_sess.mr, iu,
			      msg->hdr.tsize);
	rcu_read_unlock();
	if (unlikely(err)) {
		ERR_RL(sess, "Sending user message failed, posting work"
		       " request failed, err: %s\n", strerror(err));
		goto err_post_send;
	}

	sess->stats.user_ib_msgs.sent_msg_cnt++;
	sess->stats.user_ib_msgs.sent_size += len;

	ibtrs_heartbeat_set_send_ts(&sess->heartbeat);

	return 0;

err_post_send:
	put_u_msg_iu(sess, iu);
	wake_up(&sess->mu_iu_wait_q);
err_iu:
	atomic_inc(&sess->peer_usr_msg_bufs);
	wake_up(&sess->mu_buf_wait_q);
	return err;
}
EXPORT_SYMBOL(ibtrs_clt_send);

static void csm_resolving_addr(struct ibtrs_con *con, enum csm_ev ev)
{
	pr_debug("con %p, state %s event %s\n", con, csm_state_str(con->state),
	    csm_event_str(ev));
	switch (ev) {
	case CSM_EV_ADDR_RESOLVED: {
		int err;

		csm_set_state(con, CSM_STATE_RESOLVING_ROUTE);
		err = resolve_route(con);
		if (err) {
			ERR(con->sess, "Failed to resolve route, err: %s\n",
			    strerror(err));
			ibtrs_clt_destroy_cm_id(con);
			csm_set_state(con, CSM_STATE_CLOSED);
			ssm_schedule_event(con->sess, SSM_EV_CON_CLOSED);
		}
		break;
		}
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING:
		ibtrs_clt_destroy_cm_id(con);
		csm_set_state(con, CSM_STATE_CLOSED);
		ssm_schedule_event(con->sess, SSM_EV_CON_CLOSED);
		break;
	default:
		WRN(con->sess,
		    "Unexpected CSM Event '%s' in state '%s' received\n",
		    csm_event_str(ev), csm_state_str(con->state));
		return;
	}
}

static void csm_resolving_route(struct ibtrs_con *con, enum csm_ev ev)
{
	int err;

	pr_debug("con %p, state %s event %s\n", con, csm_state_str(con->state),
	    csm_event_str(ev));
	switch (ev) {
	case CSM_EV_ROUTE_RESOLVED:
		err = create_con(con);
		if (err) {
			ERR(con->sess,
			    "Failed to create connection, err: %s\n",
			    strerror(err));
			csm_set_state(con, CSM_STATE_CLOSED);
			ssm_schedule_event(con->sess, SSM_EV_CON_CLOSED);
			return;
		}
		csm_set_state(con, CSM_STATE_CONNECTING);
		break;
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING:
		ibtrs_clt_destroy_cm_id(con);
		csm_set_state(con, CSM_STATE_CLOSED);
		ssm_schedule_event(con->sess, SSM_EV_CON_CLOSED);
		break;
	default:
		WRN(con->sess,
		    "Unexpected CSM Event '%s' in state '%s' received\n",
		    csm_event_str(ev), csm_state_str(con->state));
		return;
	}
}

static int con_disconnect(struct ibtrs_con *con)
{
	int err;

	err = rdma_disconnect(con->cm_id);
	if (err)
		ERR(con->sess,
		    "Failed to disconnect RDMA connection, err: %s\n",
		    strerror(err));
	return err;
}

static int send_msg_sess_info(struct ibtrs_con *con)
{
	struct ibtrs_msg_sess_info *msg;
	int err;
	struct ibtrs_session *sess = con->sess;

	msg = sess->sess_info_iu->buf;

	fill_ibtrs_msg_sess_info(msg, hostname);

	err = ibtrs_post_send(con->ib_con.qp, con->sess->ib_sess.mr,
			      sess->sess_info_iu, msg->hdr.tsize);
	if (unlikely(err))
		ERR(sess, "Sending sess info failed, "
			  "posting msg to QP failed, err: %s\n", strerror(err));

	return err;
}

static void csm_connecting(struct ibtrs_con *con, enum csm_ev ev)
{
	pr_debug("con %p, state %s event %s\n", con, csm_state_str(con->state),
	    csm_event_str(ev));
	switch (ev) {
	case CSM_EV_CON_ESTABLISHED:
		csm_set_state(con, CSM_STATE_CONNECTED);
		if (con->user) {
			if (send_msg_sess_info(con))
				goto destroy;
		}
		ssm_schedule_event(con->sess, SSM_EV_CON_CONNECTED);
		break;
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING:
	case CSM_EV_WC_ERROR:
	case CSM_EV_CON_DISCONNECTED:
destroy:
		csm_set_state(con, CSM_STATE_CLOSING);
		con_disconnect(con);
		/* No CM_DISCONNECTED after rdma_disconnect, triger sm*/
		csm_schedule_event(con, CSM_EV_CON_DISCONNECTED);
		break;
	default:
		WRN(con->sess,
		    "Unexpected CSM Event '%s' in state '%s' received\n",
		    csm_event_str(ev), csm_state_str(con->state));
		return;
	}
}

static void csm_connected(struct ibtrs_con *con, enum csm_ev ev)
{
	pr_debug("con %p, state %s event %s\n", con, csm_state_str(con->state),
	    csm_event_str(ev));
	switch (ev) {
	case CSM_EV_WC_ERROR:
	case CSM_EV_CON_ERROR:
	case CSM_EV_CON_DISCONNECTED:
		ssm_schedule_event(con->sess, SSM_EV_CON_ERROR);
		csm_set_state(con, CSM_STATE_CLOSING);
		con_disconnect(con);
		break;
	case CSM_EV_SESS_CLOSING:
		csm_set_state(con, CSM_STATE_CLOSING);
		con_disconnect(con);
		break;
	default:
		WRN(con->sess,
		    "Unexpected CSM Event '%s' in state '%s' received\n",
		    csm_event_str(ev), csm_state_str(con->state));
		return;
	}
}

static void csm_closing(struct ibtrs_con *con, enum csm_ev ev)
{
	pr_debug("con %p, state %s event %s\n", con, csm_state_str(con->state),
	    csm_event_str(ev));
	switch (ev) {
	case CSM_EV_CON_DISCONNECTED:
	case CSM_EV_CON_ERROR:
	case CSM_EV_SESS_CLOSING: {
		int err;

		csm_set_state(con, CSM_STATE_FLUSHING);
		synchronize_rcu();

		err = post_beacon(&con->ib_con);
		if (err) {
			WRN(con->sess, "Failed to post BEACON,"
			    " will destroy connection directly\n");
			goto destroy;
		}

		err = ibtrs_request_cq_notifications(&con->ib_con);
		if (unlikely(err < 0)) {
			WRN(con->sess, "Requesting CQ Notification for"
			    " ib_con failed. Connection will be destroyed\n");
			goto destroy;
		} else if (err > 0) {
			err = get_process_wcs(con);
			if (unlikely(err))
				goto destroy;
			break;
		}
		break;
destroy:
		con_destroy(con);
		csm_set_state(con, CSM_STATE_CLOSED);
		ssm_schedule_event(con->sess, SSM_EV_CON_CLOSED);
		break;
		}
	case CSM_EV_CON_ESTABLISHED:
	case CSM_EV_WC_ERROR:
		/* ignore WC errors */
		break;
	default:
		WRN(con->sess,
		    "Unexpected CSM Event '%s' in state '%s' received\n",
		    csm_event_str(ev), csm_state_str(con->state));
		return;
	}
}

static void csm_flushing(struct ibtrs_con *con, enum csm_ev ev)
{
	pr_debug("con %p, state %s event %s\n", con, csm_state_str(con->state),
	    csm_event_str(ev));
	switch (ev) {
	case CSM_EV_BEACON_COMPLETED:
		con_destroy(con);
		csm_set_state(con, CSM_STATE_CLOSED);
		ssm_schedule_event(con->sess, SSM_EV_CON_CLOSED);
		break;
	case CSM_EV_WC_ERROR:
	case CSM_EV_CON_ERROR:
		/* ignore WC and CON errors */
	case CSM_EV_CON_DISCONNECTED:
		/* Ignore CSM_EV_CON_DISCONNECTED. At this point we could have
		 * already received a CSM_EV_CON_DISCONNECTED for the same
		 * connection, but an additional RDMA_CM_EVENT_DISCONNECTED or
		 * RDMA_CM_EVENT_TIMEWAIT_EXIT could be generated.
		 */
	case CSM_EV_SESS_CLOSING:
		break;
	default:
		WRN(con->sess,
		    "Unexpected CSM Event '%s' in state '%s' received\n",
		    csm_event_str(ev), csm_state_str(con->state));
		return;
	}
}

static void schedule_all_cons_close(struct ibtrs_session *sess)
{
	int i;

	for (i = 0; i < CONS_PER_SESSION; i++)
		csm_schedule_event(&sess->con[i], CSM_EV_SESS_CLOSING);
}

static void ssm_idle(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_CONNECTED:
		WARN_ON(++sess->connected_cnt != 1);
		if (ssm_init_state(sess, SSM_STATE_WF_INFO))
			ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		WARN_ON(sess->active_cnt);
		/* fall through */
	case SSM_EV_CON_ERROR:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_idle_reconnect_init(struct ibtrs_session *sess)
{
	int err, i;

	sess->retry_cnt++;
	INFO(sess, "Reconnecting session."
	     " Retry counter=%d, max reconnect attempts=%d\n",
	     sess->retry_cnt, sess->max_reconnect_attempts);

	for (i = 0; i < CONS_PER_SESSION; i++) {
		struct ibtrs_con *con = &sess->con[i];

		csm_set_state(con, CSM_STATE_CLOSED);
		con->sess = sess;
	}
	sess->connected_cnt = 0;
	err = init_con(sess, &sess->con[0], 0, true);
	if (err)
		INFO(sess, "Reconnecting session failed, err: %s\n",
		     strerror(err));
	return err;
}

static void ssm_idle_reconnect(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_CONNECTED:
		WARN_ON(++sess->connected_cnt != 1);
		if (ssm_init_state(sess, SSM_STATE_WF_INFO_RECONNECT))
			ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
		break;
	case SSM_EV_SESS_CLOSE:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		WARN_ON(sess->active_cnt);
		/* fall through */
	case SSM_EV_CON_ERROR:
		sess->stats.reconnects.fail_cnt++;
		ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
		break;
	case SSM_EV_RECONNECT_USER:
		sess->retry_cnt = 0;
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_wf_info_init(struct ibtrs_session *sess)
{
	int err;

	err = ibtrs_request_cq_notifications(&sess->con[0].ib_con);
	if (unlikely(err < 0)) {
		return err;
	} else if (err > 0) {
		err = get_process_wcs(&sess->con[0]);
		if (unlikely(err))
			return err;
	} else {
		ibtrs_set_last_heartbeat(&sess->heartbeat);
		WARN_ON(!schedule_delayed_work(&sess->heartbeat_dwork,
					       HEARTBEAT_INTV_JIFFIES));
	}
	return err;
}

static void ssm_wf_info(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_GOT_RDMA_INFO:
		if (ssm_init_state(sess, SSM_STATE_OPEN))
			ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		WARN_ON(sess->active_cnt);
		/* fall through */
	case SSM_EV_CON_ERROR:
	case SSM_EV_RECONNECT_HEARTBEAT:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static void ssm_wf_info_reconnect(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_GOT_RDMA_INFO:
		if (ssm_init_state(sess, SSM_STATE_OPEN_RECONNECT))
			ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
		break;
	case SSM_EV_SESS_CLOSE:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		WARN_ON(sess->active_cnt);
		/* fall through */
	case SSM_EV_CON_ERROR:
	case SSM_EV_RECONNECT_HEARTBEAT:
		sess->stats.reconnects.fail_cnt++;
		ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
		break;
	case SSM_EV_RECONNECT_USER:
		sess->retry_cnt = 0;
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static void queue_destroy_sess(struct ibtrs_session *sess)
{
	kfree(sess->srv_rdma_addr);
	sess->srv_rdma_addr = NULL;
	ibtrs_clt_destroy_ib_session(sess);
	sess_schedule_destroy(sess);
}

static int ibtrs_clt_request_cq_notifications(struct ibtrs_session *sess)
{
	int err, i;

	for (i = 0; i < CONS_PER_SESSION; i++) {
		struct ibtrs_con *con = &sess->con[i];

		err = ibtrs_request_cq_notifications(&con->ib_con);
		if (unlikely(err < 0)) {
			return err;
		} else if (err > 0) {
			err = get_process_wcs(con);
			if (unlikely(err))
				return err;
		}
	}

	return 0;
}

static int ibtrs_alloc_io_bufs(struct ibtrs_session *sess)
{
	int ret;

	if (sess->io_bufs_initialized)
		return 0;

	ret = ibtrs_alloc_reqs(sess);
	if (ret) {
		ERR(sess,
		    "Failed to allocate session request buffers, err: %s\n",
		    strerror(ret));
		return ret;
	}

	ret = alloc_sess_fast_pool(sess);
	if (ret)
		return ret;

	ret = alloc_sess_tags(sess);
	if (ret) {
		ERR(sess, "Failed to allocate session tags, err: %s\n",
		    strerror(ret));
		return ret;
	}

	sess->io_bufs_initialized = true;

	return 0;
}

static int ssm_open_init(struct ibtrs_session *sess)
{
	int i, ret;

	ret = ibtrs_alloc_io_bufs(sess);
	if (ret)
		return ret;

	ret = alloc_sess_tr_bufs(sess);
	if (ret) {
		ERR(sess,
		    "Failed to allocate session transfer buffers, err: %s\n",
		    strerror(ret));
		return ret;
	}

	ret = post_usr_con_recv(&sess->con[0]);
	if (unlikely(ret))
		return ret;
	for (i = 1; i < CONS_PER_SESSION; i++) {
		ret = init_con(sess, &sess->con[i], (i - 1) % num_online_cpus(),
			       false);
		if (ret)
			return ret;
	}
	return 0;
}

static void ssm_open(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_CONNECTED:
		if (++sess->connected_cnt < CONS_PER_SESSION)
			return;

		if (ssm_init_state(sess, SSM_STATE_CONNECTED)) {
			ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
			return;
		}

		INFO(sess, "IBTRS session (QPs: %d) to server established\n",
		     CONS_PER_SESSION);

		wake_up(&sess->wait_q);
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		/* fall through */
	case SSM_EV_CON_ERROR:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static void ssm_open_reconnect(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_CONNECTED:
		if (++sess->connected_cnt < CONS_PER_SESSION)
			return;

		if (ssm_init_state(sess, SSM_STATE_CONNECTED)) {
			ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
			return;
		}

		INFO(sess, "IBTRS session (QPs: %d) to server established\n",
		     CONS_PER_SESSION);

		sess->retry_cnt = 0;
		sess->stats.reconnects.successful_cnt++;
		clt_ops->sess_ev(sess->priv, IBTRS_CLT_SESS_EV_RECONNECT, 0);

		break;
	case SSM_EV_SESS_CLOSE:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		/* fall through */
	case SSM_EV_CON_ERROR:
		sess->stats.reconnects.fail_cnt++;
		ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
		break;
	case SSM_EV_RECONNECT_USER:
		sess->retry_cnt = 0;
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_connected_init(struct ibtrs_session *sess)
{
	int err;

	err = ibtrs_clt_request_cq_notifications(sess);
	if (err) {
		ERR(sess, "Establishing Session failed, requesting"
		    " CQ completion notification failed, err: %s\n",
		    strerror(err));
		return err;
	}

	atomic_set(&sess->peer_usr_msg_bufs, USR_MSG_CNT);

	return 0;
}

static int sess_disconnect_cons(struct ibtrs_session *sess)
{
	int i;

	for (i = 0; i < CONS_PER_SESSION; i++) {
		struct ibtrs_con *con = &sess->con[i];

		rcu_read_lock();
		smp_rmb(); /* fence con->state check */
		if (con->state == CSM_STATE_CONNECTED)
			rdma_disconnect(con->cm_id);
		rcu_read_unlock();
	}

	return 0;
}

static void ssm_connected(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_RECONNECT_USER:
	case SSM_EV_CON_ERROR:
	case SSM_EV_RECONNECT_HEARTBEAT:
		INFO(sess, "Session disconnecting\n");

		if (ev == SSM_EV_RECONNECT_USER)
			ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT_IMM);
		else
			ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);

		wake_up(&sess->mu_buf_wait_q);
		wake_up(&sess->mu_iu_wait_q);
		clt_ops->sess_ev(sess->priv, IBTRS_CLT_SESS_EV_DISCONNECTED, 0);
		sess_disconnect_cons(sess);
		synchronize_rcu();
		fail_all_outstanding_reqs(sess);
		break;
	case SSM_EV_SESS_CLOSE:
		cancel_delayed_work_sync(&sess->heartbeat_dwork);
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_reconnect_init(struct ibtrs_session *sess)
{
	unsigned long delay_jiffies;
	u16 delay_sec = 0;

	if (sess->retry_cnt == 0) {
		/* If there is a connection error, we wait 5
		 * seconds for the first reconnect retry. This is needed
		 * because if the server has initiated the disconnect,
		 * it might not be ready to receive a new session
		 * request immediately.
		 */
		delay_sec = 5;
	} else {
		delay_sec = sess->reconnect_delay_sec + sess->retry_cnt;
	}

	delay_sec = delay_sec + prandom_u32() % RECONNECT_SEED;

	delay_jiffies = msecs_to_jiffies(1000 * (delay_sec));

	INFO(sess, "Session reconnect in %ds\n", delay_sec);
	queue_delayed_work_on(0, sess->sm_wq,
			      &sess->reconnect_dwork, delay_jiffies);
	return 0;
}

static void ssm_reconnect(struct ibtrs_session *sess, enum ssm_ev ev)
{
	int err;

	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_RECONNECT_USER:
		sess->retry_cnt = 0;
		cancel_delayed_work_sync(&sess->reconnect_dwork);
	case SSM_EV_RECONNECT:
		err =  ssm_init_state(sess, SSM_STATE_IDLE_RECONNECT);
		if (err == -ENODEV) {
			cancel_delayed_work_sync(&sess->reconnect_dwork);
			ssm_init_state(sess, SSM_STATE_DISCONNECTED);
		} else if (err) {
			ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT);
		}
		break;
	case SSM_EV_SESS_CLOSE:
		cancel_delayed_work_sync(&sess->reconnect_dwork);
		ssm_init_state(sess, SSM_STATE_DESTROYED);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_close_destroy_init(struct ibtrs_session *sess)
{
	if (!sess->active_cnt)
		ssm_schedule_event(sess, SSM_EV_ALL_CON_CLOSED);
	else
		schedule_all_cons_close(sess);

	return 0;
}

static void ssm_close_destroy(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		if (sess->active_cnt)
			break;
	case SSM_EV_ALL_CON_CLOSED:
		ssm_init_state(sess, SSM_STATE_DESTROYED);
		wake_up(&sess->wait_q);
		break;
	case SSM_EV_SESS_CLOSE:
	case SSM_EV_CON_ERROR:
	case SSM_EV_RECONNECT_USER:
	case SSM_EV_CON_CONNECTED:
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static void ssm_close_reconnect(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_ERROR:
	case SSM_EV_CON_CONNECTED:
		break;
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		if (sess->active_cnt)
			break;
	case SSM_EV_ALL_CON_CLOSED:
		if (!sess->ib_sess_destroy_completion &&
		    (sess->max_reconnect_attempts == -1 ||
		    (sess->max_reconnect_attempts > 0 &&
		     sess->retry_cnt < sess->max_reconnect_attempts))) {
			ssm_init_state(sess, SSM_STATE_RECONNECT);
		} else {
			if (sess->ib_sess_destroy_completion)
				INFO(sess, "Device is being removed, will not"
				     " schedule reconnect of session.\n");
			else
				INFO(sess, "Max reconnect attempts reached, "
				     "will not schedule reconnect of "
				     "session. (Current reconnect attempts=%d,"
				     " max reconnect attempts=%d)\n",
				     sess->retry_cnt,
				     sess->max_reconnect_attempts);
			clt_ops->sess_ev(sess->priv,
					 IBTRS_CLT_SESS_EV_MAX_RECONN_EXCEEDED,
					 0);

			ssm_init_state(sess, SSM_STATE_DISCONNECTED);
		}
		break;
	case SSM_EV_SESS_CLOSE:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_RECONNECT_USER:
		sess->retry_cnt = 0;
		ssm_init_state(sess, SSM_STATE_CLOSE_RECONNECT_IMM);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static void ssm_close_reconnect_imm(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));
	switch (ev) {
	case SSM_EV_CON_CLOSED:
		sess->active_cnt--;
		pr_debug("active_cnt %d\n", sess->active_cnt);
		if (sess->active_cnt)
			break;
	case SSM_EV_ALL_CON_CLOSED:
		if (ssm_init_state(sess, SSM_STATE_IDLE_RECONNECT))
			ssm_init_state(sess, SSM_STATE_DISCONNECTED);
		break;
	case SSM_EV_SESS_CLOSE:
		ssm_init_state(sess, SSM_STATE_CLOSE_DESTROY);
		break;
	case SSM_EV_RECONNECT_USER:
	case SSM_EV_CON_ERROR:
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_disconnected_init(struct ibtrs_session *sess)
{
	ibtrs_clt_destroy_ib_session(sess);

	return 0;
}

static void ssm_disconnected(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));

	switch (ev) {
	case SSM_EV_RECONNECT_USER:
		sess->retry_cnt = 0;
		/* stay in disconnected if can't switch to IDLE_RECONNECT */
		ssm_init_state(sess, SSM_STATE_IDLE_RECONNECT);
		break;
	case SSM_EV_SESS_CLOSE:
		ssm_init_state(sess, SSM_STATE_DESTROYED);
		break;
	default:
		WRN(sess,
		    "Unexpected SSM Event '%s' in state '%s' received\n",
		    ssm_event_str(ev), ssm_state_str(sess->state));
		return;
	}
}

static int ssm_destroyed_init(struct ibtrs_session *sess)
{
	queue_destroy_sess(sess);

	return 0;
}

static void ssm_destroyed(struct ibtrs_session *sess, enum ssm_ev ev)
{
	pr_debug("sess %p, state %s event %s\n", sess, ssm_state_str(sess->state),
	    ssm_event_str(ev));

	/* ignore all events since the session is being destroyed */
}

int ibtrs_clt_register(const struct ibtrs_clt_ops *ops)
{
	if (clt_ops) {
		pr_err("Module %s already registered, only one user module"
		       " supported\n", clt_ops->owner->name);
		return -ENOTSUPP;
	}
	if (!clt_ops_are_valid(ops))
		return -EINVAL;
	clt_ops = ops;

	return 0;
}
EXPORT_SYMBOL(ibtrs_clt_register);

void ibtrs_clt_unregister(const struct ibtrs_clt_ops *ops)
{
	if (WARN_ON(!clt_ops))
		return;

	if (memcmp(clt_ops->owner, ops->owner, sizeof(*clt_ops)))
		return;

	flush_workqueue(ibtrs_wq);

	mutex_lock(&sess_mutex);
	WARN(!list_empty(&sess_list),
	     "BUG: user module didn't close all sessions before calling %s\n",
	     __func__);
	mutex_unlock(&sess_mutex);

	clt_ops = NULL;
}
EXPORT_SYMBOL(ibtrs_clt_unregister);

int ibtrs_clt_query(struct ibtrs_session *sess, struct ibtrs_attrs *attr)
{
	if (unlikely(sess->state != SSM_STATE_CONNECTED))
		return -ECOMM;

	attr->queue_depth      = sess->queue_depth;
	attr->mr_page_mask     = sess->mr_page_mask;
	attr->mr_page_size     = sess->mr_page_size;
	attr->mr_max_size      = sess->mr_max_size;
	attr->max_pages_per_mr = sess->max_pages_per_mr;
	attr->max_sge          = sess->max_sge;
	attr->max_io_size      = sess->max_io_size;
	strlcpy(attr->hostname, sess->hostname, sizeof(attr->hostname));

	return 0;
}
EXPORT_SYMBOL(ibtrs_clt_query);

static int check_module_params(void)
{
	if (fmr_sg_cnt > MAX_SEGMENTS || fmr_sg_cnt < 0) {
		pr_err("invalid fmr_sg_cnt values\n");
		return -EINVAL;
	}
	return 0;
}

ssize_t ibtrs_clt_stats_rdma_to_str(struct ibtrs_session *sess,
				    char *page, size_t len)
{
	struct ibtrs_clt_stats_rdma_stats s;
	struct ibtrs_clt_stats_rdma_stats *r = sess->stats.rdma_stats;
	int i;

	memset(&s, 0, sizeof(s));

	for (i = 0; i < num_online_cpus(); i++) {
		s.cnt_read		+= r[i].cnt_read;
		s.size_total_read	+= r[i].size_total_read;
		s.cnt_write		+= r[i].cnt_write;
		s.size_total_write	+= r[i].size_total_write;
		s.inflight		+= r[i].inflight;
	}

	return scnprintf(page, len, "%llu %llu %llu %llu %u\n",
			 s.cnt_read, s.size_total_read, s.cnt_write,
			 s.size_total_write, s.inflight);
}

int ibtrs_clt_stats_sg_list_distr_to_str(struct ibtrs_session *sess, char *buf,
					 size_t len)
{
	int cnt = 0;
	unsigned p, p_i, p_f;
	u64 *total = sess->stats.sg_list_total;
	u64 **distr = sess->stats.sg_list_distr;
	int i, j;

	cnt += scnprintf(buf + cnt, len - cnt, "n\\cpu:");
	for (j = 0; j < num_online_cpus(); j++)
		cnt += scnprintf(buf + cnt, len - cnt, "%5d", j);

	for (i = 0; i < SG_DISTR_LEN + 1; i++) {
		if (i <= MAX_LIN_SG)
			cnt += scnprintf(buf + cnt, len - cnt, "\n= %3d:", i);
		else if (i < SG_DISTR_LEN)
			cnt += scnprintf(buf + cnt, len - cnt,
					"\n< %3d:",
					1 << (i + MIN_LOG_SG - MAX_LIN_SG));
		else
			cnt += scnprintf(buf + cnt, len - cnt,
					"\n>=%3d:",
					1 << (i + MIN_LOG_SG - MAX_LIN_SG - 1));

		for (j = 0; j < num_online_cpus(); j++) {
			p = total[j] ? distr[j][i] * 1000 / total[j] : 0;
			p_i = p / 10;
			p_f = p % 10;

			if (distr[j][i])
				cnt += scnprintf(buf + cnt, len - cnt,
						 " %2u.%01u", p_i, p_f);
			else
				cnt += scnprintf(buf + cnt, len - cnt, "    0");
		}
	}

	cnt += scnprintf(buf + cnt, len - cnt, "\ntotal:");
	for (j = 0; j < num_online_cpus(); j++)
		cnt += scnprintf(buf + cnt, len - cnt, " %llu", total[j]);
	cnt += scnprintf(buf + cnt, len - cnt, "\n");

	return cnt;
}

static int __init ibtrs_client_init(void)
{
	int err;

	scnprintf(hostname, sizeof(hostname), "%s", utsname()->nodename);
	pr_info("Loading module ibtrs_client, version: " __stringify(IBTRS_VER)
		" (use_fr: %d, retry_count: %d,"
		" fmr_sg_cnt: %d,"
		" default_heartbeat_timeout_ms: %d, hostname: %s)\n", use_fr,
		retry_count, fmr_sg_cnt,
		default_heartbeat_timeout_ms, hostname);
	err = check_module_params();
	if (err) {
		pr_err("Failed to load module, invalid module parameters,"
		       " err: %s\n", strerror(err));
		return err;
	}

	ibtrs_wq = alloc_workqueue("ibtrs_client_wq", 0, 0);
	if (!ibtrs_wq) {
		pr_err("Failed to load module, alloc ibtrs_client_wq failed\n");
		return -ENOMEM;
	}

	err = ibtrs_clt_create_sysfs_files();
	if (err) {
		pr_err("Failed to load module, can't create sysfs files,"
		       " err: %s\n", strerror(err));
		goto out_destroy_wq;
	}
	uuid_le_gen(&uuid);
	return 0;

out_destroy_wq:
	destroy_workqueue(ibtrs_wq);
	return err;
}

static void __exit ibtrs_client_exit(void)
{
	pr_info("Unloading module\n");

	mutex_lock(&sess_mutex);
	WARN(!list_empty(&sess_list),
	     "Session(s) still exist on module unload\n");
	mutex_unlock(&sess_mutex);
	ibtrs_clt_destroy_sysfs_files();
	destroy_workqueue(ibtrs_wq);

	pr_info("Module unloaded\n");
}

module_init(ibtrs_client_init);
module_exit(ibtrs_client_exit);
