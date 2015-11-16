#if 0
#define MPTCP_SM_NAME_MAX 16
struct mptcp_sm_ops {
	struct list_head list;
	void (*on_new_master_session)(struct mptcp_cb *mpcb,
			                      struct sock *meta_sk);
	void (*on_new_sub_session)   (struct mptcp_cb *mpcb,
			                      struct sock *meta_sk);
	void (*on_del_session)       (struct mptcp_cb *mpcb,
			                      struct sock *meta_sk);
	void (*on_destory_session)   (struct mptcp_cb *mpcb, 
			                      struct sock *meta_sk);

	char			name[MPTCP_PM_NAME_MAX];
	struct module		*owner;
};
#endif

#include <net/inet_common.h>
#include <net/inet6_hashtables.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <net/mptcp_v6.h>
#endif
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/transp_v6.h>
#include <net/xfrm.h>

#include <linux/cryptohash.h>
#include <linux/kconfig.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/random.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/sysctl.h>

#include <linux/module.h>
#include <net/mptcp.h>

static DEFINE_SPINLOCK(mptcp_sm_list_lock);
static LIST_HEAD(mptcp_sm_list);

//static void mptcp_sm_nothing(struct mptcp_cb *mpcb, struct sock *sk){}
/* ------------------------------------------------------------------------*/
static void sm_on_new_mas_sess(struct mptcp_cb *mpcb, struct sock *sk)
{
struct tcp_sock *tp = tcp_sk(sk);

	if(sk->sk_family == AF_INET)
	{
		mptcp_sm_debug("SM[%20s][%#x] [pi:%d/%d] src_addr:%pI4:%d dst_addr:%pI4:%d\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, tp->mptcp->path_index, mpcb->cnt_subflows, 
                 &((struct inet_sock *)tp)->inet_saddr, ntohs(((struct inet_sock *)tp)->inet_sport),
                 &((struct inet_sock *)tp)->inet_daddr, ntohs(((struct inet_sock *)tp)->inet_dport));
	}
#if IS_ENABLED(CONFIG_IPV6)
	else
	{
		mptcp_sm_debug("SM[%20s][%#x] [pi:%d/%d] src_addr:%pI6:%d dst_addr:%pI6:%d\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, tp->mptcp->path_index, mpcb->cnt_subflows,
					&inet6_sk((const struct sock *)sk)->saddr, 
					ntohs(((struct inet_sock *)tp)->inet_sport),
                    &sk->sk_v6_daddr, 
					ntohs(((struct inet_sock *)tp)->inet_dport));
	}
#endif

}
/* ------------------------------------------------------------------------*/
static void sm_on_new_sub_sess(struct mptcp_cb *mpcb, struct sock *sk)
{
struct tcp_sock *tp = tcp_sk(sk);

	if(sk->sk_family == AF_INET)
	{
		mptcp_sm_debug("SM[%20s][%#x] [pi:%d/%d] src_addr:%pI4:%d dst_addr:%pI4:%d\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, tp->mptcp->path_index, mpcb->cnt_subflows, 
                 &((struct inet_sock *)tp)->inet_saddr, ntohs(((struct inet_sock *)tp)->inet_sport),
                 &((struct inet_sock *)tp)->inet_daddr, ntohs(((struct inet_sock *)tp)->inet_dport));
	}
#if IS_ENABLED(CONFIG_IPV6)
	else
	{
		mptcp_sm_debug("SM[%20s][%#x] [pi:%d/%d] src_addr:%pI6:%d dst_addr:%pI6:%d\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, tp->mptcp->path_index, mpcb->cnt_subflows, 
					&inet6_sk((const struct sock *)sk)->saddr, 
					ntohs(((struct inet_sock *)tp)->inet_sport),
                    &sk->sk_v6_daddr, 
					ntohs(((struct inet_sock *)tp)->inet_dport));
	}
#endif

}
/* ------------------------------------------------------------------------*/
static void sm_on_del_sess(struct mptcp_cb *mpcb, struct sock *sk)
{

struct tcp_sock *tp = tcp_sk(sk);

	if (sk->sk_family == AF_INET)
	{
		mptcp_sm_debug("SM[%20s][%#x] [pi:%d/%d] src_addr:%pI4:%d dst_addr:%pI4:%d\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, tp->mptcp->path_index, mpcb->cnt_subflows,
                 &((struct inet_sock *)tp)->inet_saddr, ntohs(((struct inet_sock *)tp)->inet_sport),
                 &((struct inet_sock *)tp)->inet_daddr, ntohs(((struct inet_sock *)tp)->inet_dport));

	}
#if IS_ENABLED(CONFIG_IPV6)
	else
	{
		mptcp_sm_debug("SM[%20s][%#x] [pi:%d/%d] src_addr:%pI6:%d dst_addr:%pI6:%d\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, tp->mptcp->path_index, mpcb->cnt_subflows,
					&inet6_sk(sk)->saddr, ntohs(((struct inet_sock *)tp)->inet_sport),
                    &sk->sk_v6_daddr, ntohs(((struct inet_sock *)tp)->inet_dport));
	}
#endif

	mptcp_sm_debug("SM[%20s][%#x]  Rx[%llu, %llu bytes] Tx[%llu, %llu bytes]\n",
				__FUNCTION__,
		    	 mpcb->mptcp_loc_token, 
				 tp->mptcp->nc_stat->rxPkts, tp->mptcp->nc_stat->rxOctets,
				 tp->mptcp->nc_stat->txPkts, tp->mptcp->nc_stat->txOctets);

}
/* ------------------------------------------------------------------------*/
static void sm_on_destroy_sess(struct mptcp_cb *mpcb, struct sock *sk){

	mptcp_sm_debug("SM[%20s][%#x] [cnt:%d]\n",
				__FUNCTION__,
				mpcb->mptcp_loc_token, mpcb->cnt_subflows);
}

/* ------------------------------------------------------------------------*/
struct mptcp_sm_ops mptcp_sm_default = {
#if 0
	.on_new_master_session = mptcp_sm_nothing, /* We do not nothing */
	.on_new_sub_session = mptcp_sm_nothing, /* We do not nothing */
	.on_del_session = mptcp_sm_nothing, /* We do not nothing */
	.on_destory_session = mptcp_sm_nothing, /* We do not nothing */
#else
	.on_new_master_session = sm_on_new_mas_sess, 
	.on_new_sub_session    = sm_on_new_sub_sess, 
	.on_del_session        = sm_on_del_sess, 
	.on_destory_session    = sm_on_destroy_sess, 
#endif
	.name = "default",
	.owner = THIS_MODULE,
};


/* ------------------------------------------------------------------------*/
static struct mptcp_sm_ops *mptcp_sm_find(const char *name)
{
	struct mptcp_sm_ops *e;

	list_for_each_entry_rcu(e, &mptcp_sm_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}
	return NULL;
}

/* ------------------------------------------------------------------------*/
int mptcp_register_session_monitor(struct mptcp_sm_ops *sm)
{
	int ret = 0;

	if (!sm->on_new_master_session ||
	    !sm->on_new_sub_session ||
	    !sm->on_del_session ||
	    !sm->on_destory_session )
		return -EINVAL;

	spin_lock(&mptcp_sm_list_lock);
	if (mptcp_sm_find(sm->name)) {
		pr_notice("%s already registered\n", sm->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&sm->list, &mptcp_sm_list);
		pr_info("%s registered\n", sm->name);
	}
	spin_unlock(&mptcp_sm_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(mptcp_register_session_monitor);

/* ------------------------------------------------------------------------*/
void mptcp_unregister_session_monitor(struct mptcp_sm_ops *sm)
{
	spin_lock(&mptcp_sm_list_lock);
	list_del_rcu(&sm->list);
	spin_unlock(&mptcp_sm_list_lock);
}
EXPORT_SYMBOL_GPL(mptcp_unregister_session_monitor);

/* ------------------------------------------------------------------------*/
void mptcp_get_default_session_monitor(char *name)
{
	struct mptcp_sm_ops *sm;

	BUG_ON(list_empty(&mptcp_sm_list));

	rcu_read_lock();
	sm = list_entry(mptcp_sm_list.next, struct mptcp_sm_ops, list);
	strncpy(name, sm->name, MPTCP_SM_NAME_MAX);
	rcu_read_unlock();
}

/* ------------------------------------------------------------------------*/
int mptcp_set_default_session_monitor(const char *name)
{
	struct mptcp_sm_ops *sm;
	int ret = -ENOENT;

	spin_lock(&mptcp_sm_list_lock);
	sm = mptcp_sm_find(name);
#ifdef CONFIG_MODULES
	if (!sm && capable(CAP_NET_ADMIN)) {
		spin_unlock(&mptcp_sm_list_lock);

		request_module("mptcp_%s", name);
		spin_lock(&mptcp_sm_list_lock);
		sm = mptcp_sm_find(name);
	}
#endif

	if (sm) {
		list_move(&sm->list, &mptcp_sm_list);
		ret = 0;
	} else {
		pr_info("%s is not available\n", name);
	}
	spin_unlock(&mptcp_sm_list_lock);

	return ret;
}

/* ------------------------------------------------------------------------*/
void mptcp_init_session_monitor(struct mptcp_cb *mpcb)
{
	struct mptcp_sm_ops *sm;

	rcu_read_lock();
	list_for_each_entry_rcu(sm, &mptcp_sm_list, list) {
		if (try_module_get(sm->owner)) {
			mpcb->sm_ops = sm;
			break;
		}
	}
	rcu_read_unlock();
}

/* ------------------------------------------------------------------------*/
/* Manage refcounts on socket close. */
void mptcp_cleanup_session_monitor(struct mptcp_cb *mpcb)
{
	module_put(mpcb->sm_ops->owner);
}

/* ------------------------------------------------------------------------*/
/* Fallback to the default session-monitor. */
void mptcp_sm_fallback_default(struct mptcp_cb *mpcb)
{
	struct mptcp_sm_ops *sm;

	mptcp_cleanup_session_monitor(mpcb);
	sm = mptcp_sm_find("default");

	/* Cannot fail - it's the default module */
	try_module_get(sm->owner);
	mpcb->sm_ops = sm;
}
EXPORT_SYMBOL_GPL(mptcp_sm_fallback_default);

/* ------------------------------------------------------------------------*/
/* Set default value from kernel configuration at bootup */
static int __init mptcp_session_monitor_default(void)
{
#if 1 //0907
	/* Just Test */
    rSetRow(0,0x111dfaf,0xff11dfaf);
    rSetRow(1,0x120dfaf,0xff20dfaf);
    rSetRow(2,0x114dfaf,0xff14dfaf);
    rSetRow(3,0x115dfaf,0xff15dfaf);
    rSetRow(4,0x124dfaf,0xff24dfaf);
    rSetRow(5,0x112dfaf,0xff12dfaf);
    rSetRow(6,0x113dfaf,0xff13dfaf);
    rSetRow(7,0x122dfaf,0xff22dfaf);
    rSetRow(8,0x116dfaf,0xff16dfaf);
    rSetRow(9,0x117dfaf,0xff17dfaf);
    rSetRow(10,0x126dfaf,0xff26dfaf);
    rSetRow(11,0x10adfaf,0xff0adfaf);
    rSetRow(12,0x10bdfaf,0xff0bdfaf);
    rSetRow(13,0x11adfaf,0xff1adfaf);
    rSetRow(14,0x11bdfaf,0xff1bdfaf);
    rSetRow(15,0x10edfaf,0xff0edfaf);
    rSetRow(16,0x10fdfaf,0xff0fdfaf);
    rSetRow(17,0x11edfaf,0xff1edfaf);
    rSetRow(18,0x11fdfaf,0xff1fdfaf);
    rSetRow(19,0x102dfaf,0xff02dfaf);
    rSetRow(20,0x103dfaf,0xff03dfaf);
    rSetRow(21,0x130dfaf,0xff30dfaf);
    rSetRow(22,0x131dfaf,0xff31dfaf);
    rSetRow(23,0x12cdfaf,0xff2cdfaf);
    rSetRow(24,0x12ddfaf,0xff2ddfaf);
    rSetRow(25,0x134466e,0xff34466e);
    rSetRow(26,0x135466e,0xff35466e);
    rSetRow(27,0x138466e,0xff38466e);
    rSetRow(28,0x139466e,0xff39466e);
    rSetRow(29,0x136466e,0xff36466e);
    rSetRow(30,0x137466e,0xff37466e);
    rSetRow(31,0x13a466e,0xff3a466e);
    rSetRow(32,0x13b466e,0xff3b466e);
    rSetRow(33,0x12e466e,0xff2e466e);
    rSetRow(34,0x12f466e,0xff2f466e);
    rSetRow(35,0x132466e,0xff32466e);
    rSetRow(36,0x133466e,0xff33466e);
    rSetRow(37,0x11a466e,0xff1a466e);
    rSetRow(38,0x11b466e,0xff1b466e);
    rSetRow(39,0x10e466e,0xff0e466e);
    rSetRow(40,0x10f466e,0xff0f466e);
    rSetRow(41,0x1340727,0xff340727);
    rSetRow(42,0x1350727,0xff350727);
    rSetRow(43,0x1380727,0xff380727);
    rSetRow(44,0x1390727,0xff390727);
    rSetRow(45,0x1360727,0xff360727);
    rSetRow(46,0x1370727,0xff370727);
    rSetRow(47,0x13a0727,0xff3a0727);
    rSetRow(48,0x13b0727,0xff3b0727);
    rSetRow(49,0x12e0727,0xff2e0727);
    rSetRow(50,0x12f0727,0xff2f0727);
    rSetRow(51,0x1320727,0xff320727);
    rSetRow(52,0x1330727,0xff330727);
    rSetRow(53,0x1120727,0xff120727);
    rSetRow(54,0x1130727,0xff130727);
    rSetRow(55,0x10e0727,0xff0e0727);
    rSetRow(56,0x144f6d3,0xff44f6d3);
    rSetRow(57,0x145f6d3,0xff45f6d3);
    rSetRow(58,0x10f0727,0xff0f0727);
    rSetRow(59,0x21dfaf,0xff21dfaf);
    rSetRow(60,0x25dfaf,0xff25dfaf);
    rSetRow(61,0x110dfaf,0xff10dfaf);
    rSetRow(62,0x815ba8c0,0x845ba8c0);
#if 1 //for office
	rSetRow(63,0x8f14a8c0,0x8f14a8c0);
	rSetRow(64,0x7d14a8c0,0x7d14a8c0);
	rSetRow(65,0x8714a8c0,0x8714a8c0);
#endif
#endif

	return mptcp_set_default_session_monitor("default");
}
late_initcall(mptcp_session_monitor_default);
