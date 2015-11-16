/* MPTCP Scheduler module selector. Highly inspired by mptcp_rr.c */

#include <linux/module.h>
#include <net/mptcp.h>


/* if set to 1, the scheduler tries to fill the congestion-window on all subflows */
static bool cwnd_limited __read_mostly = 0;

/* "The number of consecutive segments that are part of a burst */
int sysctl_magw_kt02_num_segments __read_mostly = 1;
int sysctl_magw_kt02_p1_weight    __read_mostly = 5;
int sysctl_magw_kt02_p2_weight    __read_mostly = 1;
int sysctl_magw_kt02_debug 		  __read_mostly = 0;



#define kt02_debug(fmt, args...)		        \
	do {								        \
		if (unlikely(sysctl_magw_kt02_debug))	\
			pr_err(__FILE__ ": " fmt, ##args);	\
	} while (0)



/* ------------------------------------------------------------------------- */
struct rrsched_priv {
	unsigned char quota;
};

/* ------------------------------------------------------------------------- */
static struct rrsched_priv *rrsched_get_priv(const struct tcp_sock *tp)
{
	return (struct rrsched_priv *)&tp->mptcp->mptcp_sched[0];
}

/* ------------------------------------------------------------------------- */
/* If the sub-socket sk available to send the skb? */
static bool kt02_rr_is_available(struct sock *sk, struct sk_buff *skb,
				  bool zero_wnd_test, bool cwnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int space, in_flight;

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}

	if (!cwnd_test)
		goto zero_wnd_test;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

zero_wnd_test:
	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	return true;
}

/* ------------------------------------------------------------------------- */
/* Are we not allowed to reinject this skb on tp? */
static int mptcp_rr_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* ------------------------------------------------------------------------- */
/* We just look for any subflow that is available */
static struct sock *kt02_get_available_subflow(struct sock *meta_sk,
					     struct sk_buff *skb,
					     bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *backupsk = NULL;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    kt02_rr_is_available(sk, skb, zero_wnd_test, true))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (!kt02_rr_is_available(sk, skb, zero_wnd_test, true))
			continue;

		if (mptcp_rr_dont_reinject_skb(tp, skb)) {
			backupsk = sk;
			continue;
		}

		bestsk = sk;
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}

	return sk;
}

/* ------------------------------------------------------------------------- */
/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__kt02_next_segment(struct sock *meta_sk, int *reinject)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb)
		*reinject = 1;
	else
		skb = tcp_send_head(meta_sk);
	return skb;
}

/* ------------------------------------------------------------------------- */
static struct sk_buff *kt02_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct mptcp_tcp_sock *mptcp = NULL;
	struct sock *sk_it, *choose_sk = NULL;
	struct sk_buff *skb = __kt02_next_segment(meta_sk, reinject);
	//unsigned char split = sysctl_magw_kt02_num_segments;
	//
	unsigned char num_segments = 0;
	unsigned char split = 0;
	unsigned char iter = 0, full_subs = 0;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	if (*reinject) {
		*subsk = kt02_get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;

		return skb;
	}

retry:

	/* First, we look for a subflow who is currently being used */
	mptcp_for_each_sk(mpcb, sk_it) {
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct rrsched_priv *rsp = rrsched_get_priv(tp_it);

		if (!kt02_rr_is_available(sk_it, skb, false, cwnd_limited))
			continue;

		iter++;

		/* re-calculate num_segments */
		mptcp = tp_it->mptcp;
		if(mptcp && mptcp->path_index==1)
		{
			num_segments = sysctl_magw_kt02_num_segments *
				 ( (sysctl_magw_kt02_p1_weight<=0)?1:sysctl_magw_kt02_p1_weight);
		}
		else if(mptcp && mptcp->path_index==2)
		{
			num_segments = sysctl_magw_kt02_num_segments *
				 ( (sysctl_magw_kt02_p2_weight<=0)?1:sysctl_magw_kt02_p2_weight);
		}
		else
		{
			num_segments = sysctl_magw_kt02_num_segments;
		}


		/* Is this subflow currently being used? */
		if (rsp->quota > 0 && rsp->quota < num_segments) {
			split = num_segments - rsp->quota;
			choose_sk = sk_it;
			goto found;
		}

		/* Or, it's totally unused */
		if (!rsp->quota) {
			split = num_segments;
			choose_sk = sk_it;
		}

		/* Or, it must then be fully used  */
		if (rsp->quota >= num_segments)
			full_subs++;
	}

	/* All considered subflows have a full quota, and we considered at
	 * least one.
	 */
	if (iter && iter == full_subs) {
		/* So, we restart this round by setting quota to 0 and retry
		 * to find a subflow.
		 */
		mptcp_for_each_sk(mpcb, sk_it) {
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			struct rrsched_priv *rsp = rrsched_get_priv(tp_it);

			if (!kt02_rr_is_available(sk_it, skb, false, cwnd_limited))
				continue;

			rsp->quota = 0;
		}

		goto retry;
	}

found:
	if (choose_sk) {
		unsigned int mss_now;
		struct tcp_sock *choose_tp = tcp_sk(choose_sk);
		struct rrsched_priv *rsp = rrsched_get_priv(choose_tp);

		if (!kt02_rr_is_available(choose_sk, skb, false, true))
			return NULL;

		*subsk = choose_sk;
		mss_now = tcp_current_mss(*subsk);
		*limit = split * mss_now;

		if (skb->len > mss_now)
			rsp->quota += DIV_ROUND_UP(skb->len, mss_now);
		else
			rsp->quota++;

		kt02_debug("KT[%s] pi(%d) quota[%d], skb->len[%d] mss[%u] split[%d] limit[%d] w[%d,%d]\n", 
			__func__, choose_tp->mptcp->path_index, 
			rsp->quota,
			skb->len, mss_now, split, *limit,
			sysctl_magw_kt02_p1_weight, sysctl_magw_kt02_p2_weight
			);


		return skb;
	}

	return NULL;
}


/* ------------------------------------------------------------------------- */
static void kt02_sched_init(struct sock *sk)
{
	struct rrsched_priv *rsp = rrsched_get_priv(tcp_sk(sk));
	rsp->quota = 0;
}

/* ------------------------------------------------------------------------- */
struct mptcp_sched_ops mptcp_sched_kt02 = {
	.get_subflow  = kt02_get_available_subflow,
	.next_segment = kt02_next_segment,
	.init         = kt02_sched_init,
	.flags= MPTCP_SCHED_NON_RESTRICTED,
	.name = "kt02",
	.owner = THIS_MODULE,
};

/* ------------------------------------------------------------------------- */
static struct ctl_table magw_kt02_table[] = {
    {
        .procname = "magw_kt02_num_segments",
        .data = &sysctl_magw_kt02_num_segments,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = &proc_dointvec
    },
    {
        .procname = "magw_kt02_p1_weight",
        .data = &sysctl_magw_kt02_p1_weight,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = &proc_dointvec
    },
    {
        .procname = "magw_kt02_p2_weight",
        .data = &sysctl_magw_kt02_p2_weight,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = &proc_dointvec
    },
    {
        .procname = "magw_kt02_debug",
        .data = &sysctl_magw_kt02_debug,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = &proc_dointvec
    },
};

/* ------------------------------------------------------------------------- */
struct ctl_table_header *mptcp_sysctl_kt02;

static int __init kt02_register(void)
{
	BUILD_BUG_ON(sizeof(struct rrsched_priv) > MPTCP_SCHED_SIZE);

	pr_crit("[%s] KT03:TRY REGISTER\n", __func__);

    mptcp_sysctl_kt02 = register_net_sysctl(&init_net,
                                            "net/mptcp",
                                            magw_kt02_table);

    if (!mptcp_sysctl_kt02)
        goto register_sysctl_failed;


	if (mptcp_register_scheduler(&mptcp_sched_kt02))
		goto register_sched_failed;

	pr_crit("[%s] KT03:REGISTERED\n", __func__);

	return 0;

register_sched_failed:
    unregister_net_sysctl_table(mptcp_sysctl_kt02);
register_sysctl_failed:
    return -1;
}

/* ------------------------------------------------------------------------- */
static void kt02_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_kt02);
	unregister_net_sysctl_table(mptcp_sysctl_kt02);
}

module_init(kt02_register);
module_exit(kt02_unregister);

MODULE_AUTHOR("DON'T YOU KNOW ME STILL?");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCHEDULER FOR KT MAGW AL03");
MODULE_VERSION("0.01");
