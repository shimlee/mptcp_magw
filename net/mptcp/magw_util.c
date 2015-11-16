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
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/sysctl.h>

#include <linux/module.h>
#include <net/mptcp.h>

/* ------------------------------------------------------------------------*/
/*  Global Variables                                                       */
/* ------------------------------------------------------------------------*/

static lfRTB  lfRtb = {
    .idx = 0,
    .tb[0] = {.cnt=0, .r[0] = {0,0,0},},
    .tb[1] = {.cnt=0, .r[0] = {0,0,0},},
};

static lfGwTB lfGwtb = {
    .idx = 0,
    .tb[0]= {.addr4={0,}, .addr6={{{{0,}},}},},
    .tb[1]= {.addr4={0,}, .addr6={{{{0,}},}},},
};

/* ------------------------------------------------------------------------*/
/* Updates the MAGW-Statistics in tcp_sock->mptcp 
 */
void nc_inc_rx_stat(struct tcp_sock *tp, u32 len)
{
	if(!mptcp(tp)) goto END;

	NC_INC_RX(tp->mptcp->nc_stat, len);
END:
	return;
} /* end of function */

/* ------------------------------------------------------------------------*/
/* Updates the MAGW-Statistics in tcp_sock->mptcp 
 */
void nc_inc_tx_stat(struct tcp_sock *tp, u32 len)
{
	if(!mptcp(tp)) goto END;

	NC_INC_TX(tp->mptcp->nc_stat, len);
END:
	return;
} /* end of function */


/* ------------------------------------------------------------------------*/
void gwSetIPv4(u8 idx, const char *addr, int len) {
GwTB *gtb = &lfGwtb.tb[lfGwtb.idx];
	if(idx>=2) return;
	in4_pton(addr, -1, (u8*)&gtb->addr4[idx], -1, NULL);
	return;
} /* end of function */
EXPORT_SYMBOL(gwSetIPv4);

/* ------------------------------------------------------------------------*/
void gwGetIPv4(u8 idx, char *addr, int len) {
GwTB *gtb = &lfGwtb.tb[lfGwtb.idx];
	if(idx>=2) return;
	memset(addr, 0x00, len);	
	snprintf(addr, len, "%pI4", &gtb->addr4[idx]);
	return;
} /* end of function */
EXPORT_SYMBOL(gwGetIPv4);

/* ------------------------------------------------------------------------*/
void gwSetIPv6(u8 idx, const char *addr, int len) {
GwTB *gtb = &lfGwtb.tb[lfGwtb.idx];
	if(idx>=2) return;

	in6_pton(addr, -1, gtb->addr6[idx].s6_addr, -1, NULL);
	return;
} /* end of function */
EXPORT_SYMBOL(gwSetIPv6);

/* ------------------------------------------------------------------------*/
void gwGetIPv6(u8 idx, char *addr, int len) {
GwTB *gtb = &lfGwtb.tb[lfGwtb.idx];
	if(idx>=2) return;
	memset(addr, 0x00, len);	
	snprintf(addr, len, "%pI6", gtb->addr6[idx].s6_addr);
	return;
} /* end of function */
EXPORT_SYMBOL(gwGetIPv6);


#define MAX(_a, _b) ((_a > _b)?_a:_b)
/* ------------------------------------------------------------------------*/
void rSetRow(int idx, u32 uS, u32 uE) {

RTB *rtb = &lfRtb.tb[lfRtb.idx];

    if(idx>=MAX_RTB_ROWS)   return;

    rtb->r[idx].s = ntohl(uS);
    rtb->r[idx].e = ntohl(uE);
    rtb->r[idx].used = 1;
	pr_crit("[%s] %3d [%pI4(%u)]~[%pI4(%u)]\n", __func__, idx, 
			&uS, rtb->r[idx].s, &uE, rtb->r[idx].e);

	rtb->cnt = MAX(rtb->cnt, idx);
    return;
} /* end of function */
EXPORT_SYMBOL(rSetRow);


/* ------------------------------------------------------------------------*/
void lfRTBUpdate(void *param) {
RTB *sR = param;
int  i=0;

int  nIdx = (lfRtb.idx+1)%2;
RTB *dR = &lfRtb.tb[nIdx];

	if(sR == NULL) return;
	if(sR->cnt<0 || sR->cnt>=MAX_RTB_ROWS) return;

	for(i=0; i<MAX_RTB_ROWS; i++)
	{
		if(sR->r[i].used)
		{
			memcpy(dR->r+i, sR->r+i, sizeof(R4L));

			magw_st_debug("[%s] %3d [%pI4]~[%pI4]\n", __func__, i, 
					   &(dR->r[i].s), &(dR->r[i].e));
		}
		else
			memset(dR->r+i, 0x00, sizeof(R4L));
	} /* end of for */

	dR->cnt = sR->cnt;

	magw_st_debug("[%s] New index [%d]->[%d]\n", __func__, lfRtb.idx, nIdx);

	/* Update Index */
	lfRtb.idx = nIdx;

    return;
} /* end of function */
EXPORT_SYMBOL(lfRTBUpdate);

/* ------------------------------------------------------------------------*/
int isIPv4MagwSvc(uint32_t host, u8 *idx) {
GwTB *gtb = &lfGwtb.tb[lfGwtb.idx];
u8 i = 0;
	for(i=0; i<2; i++) {
		if(gtb->addr4[i] == host) {
			*idx = i;
			return 1;
		}
	} /* end of for */
	*idx=i;
	return 0;
} /* end of if */
EXPORT_SYMBOL(isIPv4MagwSvc);

/* ------------------------------------------------------------------------*/
int isIPv4LTE(uint32_t host) {
int  i = 0;
RTB *rtb = &lfRtb.tb[lfRtb.idx%2];
R4L *r = NULL;
uint32_t h = ntohl(host);
    for(i=0; i<rtb->cnt; i++) {
        r = &rtb->r[i];
		if(r->used ==0) continue;
        if(h>=r->s && h<=r->e)
            return 1;
    } /* end of for */

    return 0;
} /* end of if */
EXPORT_SYMBOL(isIPv4LTE);


#define IDX_FLAG		0
#define IDX_IPV4_V6		1
#define IDX_NIC_INTF	2
#define IDX_LTE_WIFI	3
/* ------------------------------------------------------------------------*/
inline 
void mgCheckStat(struct sock *sk, struct sk_buff *skb, u8 *vals, char *name)
{
const struct iphdr  *iph = ip_hdr(skb);
const struct tcphdr *th  = tcp_hdr(skb);
struct inet_sock    *ik  = inet_sk(sk);

	if(tcp_hdr(skb)->dest != mptcp_gw_port) 
		goto DONT_INC_STAT;
	
	if(!isIPv4MagwSvc(ip_hdr(skb)->daddr, &vals[IDX_NIC_INTF/*2*/])) 
		goto DONT_INC_STAT;

	/* Now Valid Service*/
	if (skb->protocol == htons(ETH_P_IP))
		vals[IDX_IPV4_V6/*1*/]= MAGW_FM_IPV4; 
	else
		vals[IDX_IPV4_V6/*1*/]= MAGW_FM_IPV6; 

	 if(isIPv4LTE(iph->saddr))
		vals[IDX_LTE_WIFI/*3*/]= MAGW_SVC_LTE; 
	 else
		vals[IDX_LTE_WIFI/*3*/]= MAGW_SVC_WIFI; 

	vals[IDX_FLAG/*0*/]= 1; 

	magw_st_debug("[%s]->[%s]:HDR(S[%pI4:%d]D[%pI4:%d]),IK(s[%pI4:%d]d[%pI4:%d])SK(d[%pI4:%d][%p])[%d,%d,%d,%d]", 
		name, __func__, 
		&iph->saddr, ntohs(th->source), 
		&iph->daddr, ntohs(th->dest),
		&ik->inet_saddr, ntohs(ik->inet_sport),
		&ik->inet_daddr, ntohs(ik->inet_dport),
		&sk->sk_daddr, ntohs(sk->sk_dport), sk, vals[0],vals[1],vals[2], vals[3]);

	return;
	
DONT_INC_STAT:
	vals[IDX_FLAG/*0*/]= 0; 

	magw_st_debug("[%s]->[%s]:DO_NOT_INC:HDR(S[%pI4:%d]D[%pI4:%d]),IK(s[%pI4:%d]d[%pI4:%d])SK(d[%pI4:%d][%p])[%d,%d,%d,%d]", 
		name, __func__, 
		&iph->saddr, ntohs(th->source), 
		&iph->daddr, ntohs(th->dest),
		&ik->inet_saddr, ntohs(ik->inet_sport),
		&ik->inet_daddr, ntohs(ik->inet_dport),
		&sk->sk_daddr, ntohs(sk->sk_dport), sk, vals[0],vals[1],vals[2], vals[3]);

	return;
} /* end of function */
EXPORT_SYMBOL(mgCheckStat);


/* ------------------------------------------------------------------------*/
inline 
void mgCheckStat2(struct sock *sk, struct sock *child, u8 *vals, char *name)
{
	if(inet_sk(child)->inet_sport != mptcp_gw_port) 
		goto DONT_INC_STAT;
	
	if(!isIPv4MagwSvc(inet_sk(child)->inet_saddr, &vals[IDX_NIC_INTF/*2*/])) 
		goto DONT_INC_STAT;

	/* Now Valid Service*/
	if (child->sk_family == AF_INET)
		vals[IDX_IPV4_V6/*1*/]= MAGW_FM_IPV4; 
	else
		vals[IDX_IPV4_V6/*1*/]= MAGW_FM_IPV6; 

	 if(isIPv4LTE(inet_sk(child)->inet_daddr))
		vals[IDX_LTE_WIFI/*3*/]= MAGW_SVC_LTE; 
	 else
		vals[IDX_LTE_WIFI/*3*/]= MAGW_SVC_WIFI; 

	vals[IDX_FLAG/*0*/]= 1; 

	magw_st_debug("[%s]->[%s]:CHD(S[%pI4:%d]D[%pI4:%d]),SK(s[%pI4:%d]d[%pI4:%d])SK(%p)CHD(%p)[%d,%d,%d,%d]", 
		name, __func__, 
		&inet_sk(child)->inet_saddr, ntohs(inet_sk(child)->inet_sport), 
		&inet_sk(child)->inet_daddr, ntohs(inet_sk(child)->inet_dport), 
		&inet_sk(sk)->inet_saddr, ntohs(inet_sk(sk)->inet_sport), 
		&inet_sk(sk)->inet_daddr, ntohs(inet_sk(sk)->inet_dport), 
		sk, child, vals[0],vals[1],vals[2], vals[3]);

	return;
	
DONT_INC_STAT:
	vals[IDX_FLAG/*0*/]= 0; 

	magw_st_debug("[%s]->[%s]:DO_NOT_INC:CHD(S[%pI4:%d]D[%pI4:%d]),SK(s[%pI4:%d]d[%pI4:%d])SK(%p)CHD(%p)[%d,%d,%d,%d]", 
		name, __func__, 
		&inet_sk(child)->inet_saddr, ntohs(inet_sk(child)->inet_sport), 
		&inet_sk(child)->inet_daddr, ntohs(inet_sk(child)->inet_dport), 
		&inet_sk(sk)->inet_saddr, ntohs(inet_sk(sk)->inet_sport), 
		&inet_sk(sk)->inet_daddr, ntohs(inet_sk(sk)->inet_dport), 
		sk, child, vals[0],vals[1],vals[2], vals[3]);

	return;
} /* end of function */
EXPORT_SYMBOL(mgCheckStat2);

/* ------------------------------------------------------------------------*/
inline 
void mgCheckStat3(struct sk_buff *skb, u8 *vals, char *name)
{
const struct iphdr  *iph = ip_hdr(skb);
const struct tcphdr *th  = tcp_hdr(skb);

	if(tcp_hdr(skb)->dest != mptcp_gw_port) 
		goto DONT_INC_STAT;
	
	if(!isIPv4MagwSvc(ip_hdr(skb)->daddr, &vals[IDX_NIC_INTF/*2*/])) 
		goto DONT_INC_STAT;

	/* Now Valid Service*/
	if (skb->protocol == htons(ETH_P_IP))
		vals[IDX_IPV4_V6/*1*/]= MAGW_FM_IPV4; 
	else
		vals[IDX_IPV4_V6/*1*/]= MAGW_FM_IPV6; 

	 if(isIPv4LTE(iph->saddr))
		vals[IDX_LTE_WIFI/*3*/]= MAGW_SVC_LTE; 
	 else
		vals[IDX_LTE_WIFI/*3*/]= MAGW_SVC_WIFI; 

	vals[IDX_FLAG/*0*/]= 1; 

	magw_st_debug("[%s]->[%s]:HDR(S[%pI4:%d]D[%pI4:%d])[%d,%d,%d,%d]", 
		name, __func__, 
		&iph->saddr, ntohs(th->source), 
		&iph->daddr, ntohs(th->dest),
		 vals[0],vals[1],vals[2], vals[3]);

	return;
	
DONT_INC_STAT:
	vals[IDX_FLAG/*0*/]= 0; 

	magw_st_debug("[%s]->[%s]:DO_NOT_INC:HDR(S[%pI4:%d]D[%pI4:%d]),[%d,%d,%d,%d]", 
		name, __func__, 
		&iph->saddr, ntohs(th->source), 
		&iph->daddr, ntohs(th->dest),
		vals[0],vals[1],vals[2], vals[3]);

	return;
} /* end of function */
EXPORT_SYMBOL(mgCheckStat3);



/* ------------------------------------------------------------------------*/
/* MAGW MPTCP Statistics */
/* ------------------------------------------------------------------------*/

static const struct snmp_mib magw_snmp_list[] = {
    SNMP_MIB_ITEM("MP_CAPABLE_SYN",     MAGW_MIB_MCSYN_RX),/**/
    SNMP_MIB_ITEM("MP_CAPABLE_SYN_ACK", MAGW_MIB_MCSACK_TX),/**/
    SNMP_MIB_ITEM("MP_CAPABLE_ACK", 	MAGW_MIB_MCACK_RX),/**/
    SNMP_MIB_ITEM("MP_JOIN_SYN",        MAGW_MIB_MJSYN_RX),/**/
    SNMP_MIB_ITEM("MP_JOIN_SYN_ACK",    MAGW_MIB_MJSACK_TX),/**/
    SNMP_MIB_ITEM("MP_JOIN_ACK", 	    MAGW_MIB_MJACK_RX),/**/
    SNMP_MIB_ITEM("MP_FAIL_SEND", 	    MAGW_MIB_FAIL_TX),
    SNMP_MIB_ITEM("MP_FAIL_RECV", 	    MAGW_MIB_FAIL_RX),/**/
    SNMP_MIB_ITEM("MP_FASTCLOSE_SEND",  MAGW_MIB_FCLOSE_TX),
    SNMP_MIB_ITEM("MP_FASTCLOSE_RECV",  MAGW_MIB_FCLOSE_RX),/**/
    SNMP_MIB_ITEM("DATA_FIN_SEND",      MAGW_MIB_DTFIN_TX),
    SNMP_MIB_ITEM("DATA_FIN_RECV",      MAGW_MIB_DTFIN_RX),/**/
    SNMP_MIB_ITEM("REMOVE_ADDR_SEND",   MAGW_MIB_RMADDR_TX),/**/
    SNMP_MIB_ITEM("REMOVE_ADDR_RECV",   MAGW_MIB_RMADDR_RX),/**/
    SNMP_MIB_ITEM("ADD_ADDR_SEND",      MAGW_MIB_ADADDR_TX),/**/
    SNMP_MIB_ITEM("ADD_ADDR_RECV",      MAGW_MIB_ADADDR_RX),/**/
 /* MPTCP Fail */
    SNMP_MIB_ITEM("TRY",                 MAGW_MIB_MP_TRY),/**/
    SNMP_MIB_ITEM("SUCCESS",             MAGW_MIB_MP_SUCCESS),/**/
    SNMP_MIB_ITEM("FAILURE",             MAGW_MIB_MP_FAIL),/**/
    SNMP_MIB_ITEM("CAPABLE_SYN_ERR",     MAGW_MIB_MP_CYE),
    SNMP_MIB_ITEM("CAPABLE_TIMEOUT_ERR", MAGW_MIB_MP_CTE),
    SNMP_MIB_ITEM("CAPABLE_ACK_ERR",     MAGW_MIB_MP_CAE),
    SNMP_MIB_ITEM("CAPABLE_CHECKSUM_ERR",MAGW_MIB_MP_CCE),
    SNMP_MIB_ITEM("JOIN_SYN_ERR",        MAGW_MIB_MP_JSE),
    SNMP_MIB_ITEM("JOIN_TIMEOUT_ERR",    MAGW_MIB_MP_JTE),
    SNMP_MIB_ITEM("JOIN_ACK_ERR",        MAGW_MIB_MP_JAE),
    SNMP_MIB_ITEM("JOIN_CHECKSUM_ERR",   MAGW_MIB_MP_JCE),
    SNMP_MIB_SENTINEL
};

/* ------------------------------------------------------------------------*
 *  Output /proc/net/mptcp_net/magw
 */
static int magw_snmp_seq_show(struct seq_file *seq, void *v)
{
int i=0;
struct net *net = seq->private;
GwTB *gtb = &lfGwtb.tb[lfGwtb.idx];

#if 0
	if(gtb->addr4[0] == INADDR_ANY)
		goto NET_INTF_V4_2;
#endif
	seq_printf(seq, "IPv4: %pI4", &gtb->addr4[0]);
	seq_puts(seq, "\nLTE :");
	for (i = 0; magw_snmp_list[i].name != NULL; i++) 
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;

		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i1v4L_stat,
				      magw_snmp_list[i].entry));
	}
	seq_puts(seq, "\nWIFI:");
	for (i = 0; magw_snmp_list[i].name != NULL; i++)
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;

		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i1v4W_stat,
				      magw_snmp_list[i].entry));
	}
	seq_putc(seq, '\n');

#if 0
NET_INTF_V4_2:
	if(gtb->addr4[1] == INADDR_ANY)
		goto NET_INTF_V6_1;
#endif
	seq_printf(seq, "IPv4: %pI4", &gtb->addr4[1]);
	seq_puts(seq, "\nLTE :");
	for (i = 0; magw_snmp_list[i].name != NULL; i++) 
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;

		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i2v4L_stat,
				      magw_snmp_list[i].entry));
	}
	seq_puts(seq, "\nWIFI:");
	for (i = 0; magw_snmp_list[i].name != NULL; i++) 
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;
	
		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i2v4W_stat,
				      magw_snmp_list[i].entry));
	}
	seq_putc(seq, '\n');

#if 0
NET_INTF_V6_1:
	if(!memcmp(&gtb->addr6[0], &in6addr_any, sizeof(struct in6_addr)))
		goto NET_INTF_V6_2;
#endif

	seq_printf(seq, "IPv6: %pI6", &gtb->addr6[0]);
	seq_puts(seq, "\nLTE :");
	for (i = 0; magw_snmp_list[i].name != NULL; i++) 
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;
	
		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i1v6L_stat,
				      magw_snmp_list[i].entry));
	}
	seq_puts(seq, "\nWIFI:");
	for (i = 0; magw_snmp_list[i].name != NULL; i++)
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;
	
		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i1v6W_stat,
				      magw_snmp_list[i].entry));
	}
	seq_putc(seq, '\n');

#if 0
NET_INTF_V6_2:
	if(!memcmp(&gtb->addr6[1], &in6addr_any, sizeof(struct in6_addr)))
		goto DONE;
#endif

	seq_printf(seq, "IPv6: %pI6", &gtb->addr6[1]);
	seq_puts(seq, "\nLTE :");
	for (i = 0; magw_snmp_list[i].name != NULL; i++) 
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;
	
		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i2v6L_stat,
				      magw_snmp_list[i].entry));
	}
	seq_puts(seq, "\nWIFI:");
	for (i = 0; magw_snmp_list[i].name != NULL; i++) 
	{
		if(magw_snmp_list[i].entry >=MAGW_MIB_RMADDR_TX && 
				magw_snmp_list[i].entry <=MAGW_MIB_ADADDR_RX) continue;
		if(magw_snmp_list[i].entry == MAGW_MIB_MP_FAIL) continue;
	
		seq_printf(seq, " %lu", 
			   snmp_fold_field((void __percpu **) net->mptcp.mg_i2v6W_stat,
				      magw_snmp_list[i].entry));
	}
	seq_putc(seq, '\n');
#if 0
DONE:
	seq_putc(seq, '\n');
#endif
	return 0;
} /* end of function */


/* ------------------------------------------------------------------------*/
static int magw_snmp_seq_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, magw_snmp_seq_show);
}

static const struct file_operations magw_snmp_seq_fops = {
    .owner = THIS_MODULE,
    .open  = magw_snmp_seq_open,
    .read  = seq_read,
    .llseek = seq_lseek,
    .release = single_release_net,
};


/* ------------------------------------------------------------------------*/
int magw_mib_init_net(struct net *net)
{
	/* ------------ */
	/* For IPv4     */
	/* ------------ */
	/* interface #1 - LTE */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i1v4L_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_0;

	/* interface #1 - WIFI */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i1v4W_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_1;

	/* interface #2 - LTE */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i2v4L_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_2;

	/* interface #2 - WIFI */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i2v4W_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_3;


	/* ------------ */
	/* For IPv6 */
	/* ------------ */
	/* interface #1 - LTE */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i1v6L_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_4;

	/* interface #1 - WIFI */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i1v6W_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_5;

	/* interface #2 - LTE */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i2v6L_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_6;

	/* interface #2 - WIFI */
	if (snmp_mib_init((void __percpu **)net->mptcp.mg_i2v6W_stat, 
			sizeof(struct magw_mib), __alignof__(struct magw_mib)) < 0)
		goto ERROR_7;

	return 0;

ERROR_7:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v6L_stat);
ERROR_6:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v6W_stat);
ERROR_5:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v6L_stat);
ERROR_4:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v4W_stat);
ERROR_3:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v4L_stat);
ERROR_2:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v4W_stat);
ERROR_1:
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v4L_stat);
ERROR_0:

	return -ENOMEM;
} /* end of function */

/* ------------------------------------------------------------------------*/
void magw_mib_exit_net(struct net *net)
{
	/* For IPv4 */
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v4L_stat);
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v4W_stat);
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v4L_stat);
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v4W_stat);
	/* For IPv6 */
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v6L_stat);
	snmp_mib_free((void __percpu **)net->mptcp.mg_i1v6W_stat);
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v6L_stat);
	snmp_mib_free((void __percpu **)net->mptcp.mg_i2v6W_stat);

} /* end of function */


/* ------------------------------------------------------------------------*/
int magw_proc_init_net(struct net *net)
{
    if(!proc_create("magw", S_IRUGO, net->mptcp.proc_net_mptcp, 
									&magw_snmp_seq_fops))
		return -ENOMEM;
	return 1;
}

/* ------------------------------------------------------------------------*/
void magw_proc_exit_net(struct net *net)
{
	remove_proc_entry("magw", net->mptcp.proc_net_mptcp);
} /* end of function */

/* ------------------------------------------------------------------------*/
/*  END OF FILE                                                            */
/* ------------------------------------------------------------------------*/
