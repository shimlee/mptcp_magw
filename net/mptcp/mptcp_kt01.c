/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>




int sysctl_magw_kt01_rttthresh __read_mostly = 30;
int sysctl_magw_kt01_weight __read_mostly = 70;
int sysctl_magw_kt01_debug __read_mostly = 0;

int g_kt01_path1_log = 0;
int g_kt01_path2_log = 0;


#define kt01_debug(fmt, args...)		        \
	do {								        \
		if (unlikely(sysctl_magw_kt01_debug))	\
			pr_err(__FILE__ ": " fmt, ##args);	\
	} while (0)



/* Same as defsched_priv from mptcp_sched.c */
struct defsched_priv {
	u32	last_rbuf_opti;
};

/* Same as defsched_get_priv from mptcp_sched.c */
static struct defsched_priv *defsched_get_priv(const struct tcp_sock *tp)
{
	return (struct defsched_priv *)&tp->mptcp->mptcp_sched[0];
}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_is_available(struct sock *sk, struct sk_buff *skb,
			       bool zero_wnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

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

	/* If TSQ is already throttling us, do not send on this subflow. When
	 * TSQ gets cleared the subflow becomes eligible again.
	 */
	if (test_bit(TSQ_THROTTLED, &tp->tsq_flags))
		return false;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

#if 0
	kt01_debug("KT[%s] sub_pi[%d] skb->len[%d] mss_now[%d] in_flight[%u] space[%u]\n", 
				__func__, tp->mptcp->path_index, skb->len, tcp_current_mss(sk),
				in_flight, space);
#endif

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return false;

	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *kt01_get_avail_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *lowpriosk = NULL, *backupsk = NULL;
	u32 min_time_to_peer = 0xffffffff, lowprio_min_time_to_peer = 0xffffffff;
	int cnt_backups = 0;


	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_available(bestsk, skb, zero_wnd_test))
			bestsk = NULL;
		return bestsk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (tp->mptcp->rcv_low_prio || tp->mptcp->low_prio)
			cnt_backups++;

#if 0
			kt01_debug("KT[%s] pi[%d] srtt[%u] cwnd[%u,%u,%u] prior[%d] ssthresh[%u] [%d]\n", 
						__func__, 
						tp->mptcp->path_index, 
						tp->srtt,
						tp->snd_cwnd,
						tp->snd_cwnd_cnt,
						tp->snd_cwnd_used,
						tp->prior_cwnd,
						tp->snd_ssthresh,
						sysctl_magw_kt01_rttthresh
						);
#endif

		if ((tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) &&
		    tp->srtt < lowprio_min_time_to_peer) {
			if (!mptcp_is_available(sk, skb, zero_wnd_test))
				continue;

			if (mptcp_dont_reinject_skb(tp, skb)) {
				backupsk = sk;
				continue;
			}

			lowprio_min_time_to_peer = tp->srtt;
			lowpriosk = sk;
		} else if (!(tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) &&
			   tp->srtt < min_time_to_peer) {
			if (!mptcp_is_available(sk, skb, zero_wnd_test))
				continue;

			if (mptcp_dont_reinject_skb(tp, skb)) {
				backupsk = sk;
				continue;
			}

			min_time_to_peer = tp->srtt;
			bestsk = sk;
		}
	}


	if (mpcb->cnt_established == cnt_backups && lowpriosk) {
		sk = lowpriosk;
#if 0
		struct tcp_sock *tp = tcp_sk(sk);
		kt01_debug("KT[%s] lowpriosk pi[%d] srtt[%u]\n", 
						__func__, tp->mptcp->path_index, tp->srtt);
#endif

	} else if (bestsk) {
		sk = bestsk;
#if 0
		struct tcp_sock *tp = tcp_sk(sk);
		kt01_debug("KT[%s] BEST SK pi[%d] srtt[%u]\n", 
						__func__, tp->mptcp->path_index, tp->srtt);
#endif

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

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	struct tcp_sock *tp = tcp_sk(sk), *tp_it;
	struct sk_buff *skb_head;
	struct defsched_priv *dsp = defsched_get_priv(tp);

	if (tp->mpcb->cnt_subflows == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_write_queue_head(meta_sk);

	if (!skb_head || skb_head == tcp_send_head(meta_sk))
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	/* Only penalize again after an RTT has elapsed */
	if (tcp_time_stamp - dsp->last_rbuf_opti < tp->srtt >> 3)
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt < tp_it->srtt && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				dsp->last_rbuf_opti = tcp_time_stamp;
			}
			break;
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_tp(tp->mpcb, tp_it) {
			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = true;
					break;
				}

				if (4 * tp->srtt >= tp_it->srtt) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans && mptcp_is_available(sk, skb_head, false))
			return skb_head;
	}
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__kt01_next_segment(struct sock *meta_sk, int *reinject)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = kt01_get_avail_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *kt01_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __kt01_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	unsigned char split = 0;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = kt01_get_avail_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

#if 0
	kt01_debug("KT[%s] sub_pi[%d] srtt[%u] skb->len[%d] mss_now[%d]\n", 
				__func__, subtp->mptcp->path_index, subtp->srtt, skb->len, mss_now);
#endif

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

#if 0
	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;
#endif

	/* KT01 Algorithm.. */
	if(subtp->srtt > sysctl_magw_kt01_rttthresh)
	{
		if(sysctl_magw_kt01_weight == 0)
			return NULL;

		split = (subtp->snd_cwnd*sysctl_magw_kt01_weight)/100;
		if(split==0) split=1;

		*limit = split * mss_now;

		if (skb->len <= mss_now)
			*limit = 0;


		if(subtp->mptcp->path_index == 1 && g_kt01_path1_log == 0)
		{
			g_kt01_path1_log = 1;
			kt01_debug("KT[%s] pi(%d) SLOW PATH START[%u>%u]:skb->len[%d] mss[%u] cwnd[%d-->%d (%d/100)]\n", 
				__func__, subtp->mptcp->path_index, 
				subtp->srtt, sysctl_magw_kt01_rttthresh,
				skb->len, mss_now,
				subtp->snd_cwnd, split, sysctl_magw_kt01_weight
				);
		}
		else if(subtp->mptcp->path_index == 2 && g_kt01_path2_log == 0)
		{
			g_kt01_path2_log = 1;
			kt01_debug("KT[%s] pi(%d) SLOW PATH START[%u>%u]:skb->len[%d] mss[%u] cwnd[%d-->%d (%d/100)]\n", 
				__func__, subtp->mptcp->path_index, 
				subtp->srtt, sysctl_magw_kt01_rttthresh,
				skb->len, mss_now,
				subtp->snd_cwnd, split, sysctl_magw_kt01_weight
				);
		}
#if 0
		else
		{
			kt01_debug("KT[%s] pi(%d) SLOW PATH START[%u>%u]:skb->len[%d] mss[%u] cwnd[%d-->%d (%d/100)]\n", 
				__func__, subtp->mptcp->path_index, 
				subtp->srtt, sysctl_magw_kt01_rttthresh,
				skb->len, mss_now,
				subtp->snd_cwnd, split, sysctl_magw_kt01_weight
				);
		}
#endif

		return skb;
	}
	else
	{
		 if(subtp->mptcp->path_index == 1 && g_kt01_path1_log == 1)
		 {
			g_kt01_path1_log = 0;
			kt01_debug("KT[%s] pi(%d) SLOW PATH END [%u>%u]:skb->len[%d] mss[%u] cwnd[%d]\n", 
				__func__, subtp->mptcp->path_index, 
				subtp->srtt, sysctl_magw_kt01_rttthresh,
				skb->len, mss_now,
				subtp->snd_cwnd
				);
		 }
		 else if(subtp->mptcp->path_index == 2 && g_kt01_path2_log == 1)
		 {
			g_kt01_path2_log = 0;
			kt01_debug("KT[%s] pi(%d) SLOW PATH END [%u>%u]:skb->len[%d] mss[%u] cwnd[%d]\n", 
				__func__, subtp->mptcp->path_index, 
				subtp->srtt, sysctl_magw_kt01_rttthresh,
				skb->len, mss_now,
				subtp->snd_cwnd
				);
		 }
	}


#if 1
	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;
#endif

	/* The following is similar to tcp_mss_split_point, but
	 * we do not care about nagle, because we will anyways
	 * use TCP_NAGLE_PUSH, which overrides this.
	 *
	 * So, we first limit according to the cwnd/gso-size and then according
	 * to the subflow's window.
	 */

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;
	max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
	if (!max_segs)
		return NULL;

	max_len = mss_now * max_segs;
	window = tcp_wnd_end(subtp) - subtp->write_seq;

	needed = min(skb->len, window);
	if (max_len <= skb->len)
		/* Take max_win, which is actually the cwnd/gso-size */
		*limit = max_len;
	else
		/* Or, take the window */
		*limit = needed;

	return skb;
}

/* Same as defsched_init from mptcp_sched.c */
static void defsched_init(struct sock *sk)
{
	struct defsched_priv *dsp = defsched_get_priv(tcp_sk(sk));

	dsp->last_rbuf_opti = tcp_time_stamp;
}


/* ------------------------------------------------------------------------- */
static struct mptcp_sched_ops mptcp_sched_kt01 = {
	.get_subflow = kt01_get_avail_subflow,
	.next_segment = kt01_next_segment,
	.init = defsched_init,
	.flags= MPTCP_SCHED_NON_RESTRICTED,
	.name = "kt01",
	.owner = THIS_MODULE,
};

/* ------------------------------------------------------------------------- */
static struct ctl_table magw_kt01_table[] = {
	{
		.procname = "magw_kt01_rttthresh",
		.data = &sysctl_magw_kt01_rttthresh,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "magw_kt01_weight",
		.data = &sysctl_magw_kt01_weight,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "magw_kt01_debug",
		.data = &sysctl_magw_kt01_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
};

/* ------------------------------------------------------------------------- */
struct ctl_table_header *mptcp_sysctl_kt01;

static int __init kt01_register(void)
{
	BUILD_BUG_ON(sizeof(struct defsched_priv) > MPTCP_SCHED_SIZE);

	pr_crit("[%s] KT01:TRY REGISTER\n", __func__);

	mptcp_sysctl_kt01 = register_net_sysctl(&init_net, 
			                                "net/mptcp", 
											magw_kt01_table);

	if (!mptcp_sysctl_kt01)
		goto register_sysctl_failed;

	if (mptcp_register_scheduler(&mptcp_sched_kt01))
		goto register_sched_failed;

	pr_crit("[%s] KT01:REGISTERED\n", __func__);

	return 0;

register_sched_failed:
	unregister_net_sysctl_table(mptcp_sysctl_kt01);
register_sysctl_failed:
	return -1;
}

static void __exit kt01_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_kt01);
	unregister_net_sysctl_table(mptcp_sysctl_kt01);
}

module_init(kt01_register);
module_exit(kt01_unregister);

MODULE_AUTHOR("YOU DON'T KNOW ME");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCHEDULER FOR KT MAGW AL01");
MODULE_VERSION("0.01");


