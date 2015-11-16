/*
 *	MPTCP MAGW implementation
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#ifndef _MPTCP_MAGW_H
#define _MPTCP_MAGW_H

#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/netpoll.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/kernel.h>

#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <net/tcp.h>
#include <net/genetlink.h>


/* ------------------------------------------------------------------------- */
/*  For Session Monitor                                                      */
/* ------------------------------------------------------------------------- */
#define MPTCP_SM_NAME_MAX 16
#define MPTCP_SM_ADDR_MAX 64

struct mptcp_sm_ops {
	struct list_head list;
	void (*on_new_master_session)(struct mptcp_cb *mpcb,
			                      struct sock *sk);
	void (*on_new_sub_session)   (struct mptcp_cb *mpcb,
			                      struct sock *sk);
	void (*on_del_session)       (struct mptcp_cb *mpcb,
			                      struct sock *sk);
	void (*on_destory_session)   (struct mptcp_cb *mpcb, 
			                      struct sock *sk);
	char			name[MPTCP_SM_NAME_MAX];
	struct module		*owner;
};

/* ------------------------------------------------------------------------- */
/*  For UE IP Range                                                          */
/* ------------------------------------------------------------------------- */
typedef struct _range_4_lte {
    uint32_t    used;
    uint32_t    s;
    uint32_t    e;
} R4L;

typedef struct _range_tb {
    int         cnt;
#define MAX_RTB_ROWS    200
    R4L         r[MAX_RTB_ROWS];
} RTB;

typedef struct _lf_rtb { /*lock free Range Table*/
    int         idx;
    RTB         tb[2];
} lfRTB;

/* ------------------------------------------------------------------------- */
/*  For GW IP                                                                */
/* ------------------------------------------------------------------------- */
typedef struct _nc_gw_tb {
#define MAX_GWTB_ROWS    2
	__be32   		  addr4[MAX_GWTB_ROWS];
	struct in6_addr   addr6[MAX_GWTB_ROWS];
} GwTB;

typedef struct _lf_gwtb {
    int         idx;
	GwTB		tb[2];
} lfGwTB;


/* ------------------------------------------------------------------------- */
/*  For GW specific MPTCP Statistic                                          */
/* ------------------------------------------------------------------------- */
#define MAGWS_INC(net,_f,_i,_j,_k, field)   do{\
 if(_f) {                                      \
      SNMP_INC_STATS((net)->mptcp.mg_stat[_i][_j][_k], field);\
 }                                             \
}while(0)

#if 0
#define MAGW_INC_STATS_BH(net, field)	SNMP_INC_STATS_BH((net)->mptcp.mptcp_statistics, field)
#define MAGW_DEC_STATS(net, field)	SNMP_DEC_STATS((net)->mptcp.mptcp_statistics, field)
#define MAGW_ADD_STATS_USER(net, field, val) SNMP_ADD_STATS_USER((net)->mptcp.mptcp_statistics, field, val)
#define MAGW_ADD_STATS(net, field, val)	SNMP_ADD_STATS((net)->mptcp.mptcp_statistics, field, val)
#endif

enum {
	MAGW_MIB_NUM = 0,
 	MAGW_MIB_MCSYN_RX,
 	MAGW_MIB_MCSACK_TX,
 	MAGW_MIB_MCACK_RX,
 	MAGW_MIB_MJSYN_RX,
 	MAGW_MIB_MJSACK_TX,
 	MAGW_MIB_MJACK_RX,
 	MAGW_MIB_FAIL_TX,
 	MAGW_MIB_FAIL_RX,
 	MAGW_MIB_FCLOSE_TX,
 	MAGW_MIB_FCLOSE_RX,
 	MAGW_MIB_DTFIN_TX,
 	MAGW_MIB_DTFIN_RX,
 	MAGW_MIB_RMADDR_TX,
 	MAGW_MIB_RMADDR_RX,
 	MAGW_MIB_ADADDR_TX,
 	MAGW_MIB_ADADDR_RX,
 /* MPTCP Fail */
 	MAGW_MIB_MP_TRY,
 	MAGW_MIB_MP_SUCCESS,
 	MAGW_MIB_MP_FAIL,
 	MAGW_MIB_MP_CYE,/* MP_CAPABLE SYN ERROR */
 	MAGW_MIB_MP_CTE,/* MP_CAPABLE TIMEOUT ERROR */
 	MAGW_MIB_MP_CAE,/* MP_CAPABLE ACK ERROR */
 	MAGW_MIB_MP_CCE,/* MP_CAPABLE CHECKSUM ERROR */
 	MAGW_MIB_MP_JSE,/* MP_JOIN SYN ERROR */
 	MAGW_MIB_MP_JTE,/* MP_JOIN TIMEOUT ERROR */
 	MAGW_MIB_MP_JAE,/* MP_JOIN ACK ERROR */
 	MAGW_MIB_MP_JCE,/* MP_JOIN SYN ERROR */
	__MAGW_MIB_MAX
};

#define MAGW_MIB_MAX __MAGW_MIB_MAX
struct magw_mib {
	unsigned long	mibs[MAGW_MIB_MAX];
};


#ifdef CONFIG_NC_KT_MAGW

#define NC_INC_RX(_st, _len)   do {\
  if(_len>0) {/*0907*/            \
    (_st)->rxPkts++;               \
    (_st)->rxOctets += _len;       \
  }                                \
} while(0)
#define NC_INC_TX(_st, _len)   do {\
  if(_len>0) { /*0907*/           \
    (_st)->txPkts++;               \
    (_st)->txOctets += _len;       \
  }                                \
} while(0)

#define mptcp_sm_debug(fmt, args...)  do {\
  if (unlikely(sysctl_mptcp_sm_debug))	  \
    pr_err(__FILE__ ": " fmt, ##args);	  \
} while(0)

#define magw_st_debug(fmt, args...)  do {\
  if (unlikely(sysctl_magw_st_debug))	  \
    pr_err(__FILE__ ": " fmt, ##args);	  \
} while(0)


/* MPTCP-session-monitor registration/initialization functions */
int  mptcp_register_session_monitor(struct mptcp_sm_ops *sm);
void mptcp_unregister_session_monitor(struct mptcp_sm_ops *sm);
void mptcp_init_session_monitor(struct mptcp_cb *mpcb);
void mptcp_cleanup_session_monitor(struct mptcp_cb *mpcb);
void mptcp_sm_fallback_default(struct mptcp_cb *mpcb);
void mptcp_get_default_session_monitor(char *name);
int  mptcp_set_default_session_monitor(const char *name);

/* MAGW CDR  */
void nc_inc_rx_stat(struct tcp_sock *tp, u32 len);
void nc_inc_tx_stat(struct tcp_sock *tp, u32 len);

/* MPTCP Statistics  */
void rSetRow       (int idx, u32 uS, u32 uE);
int  isIPv4LTE     (uint32_t host);
int  isIPv4MagwSvc (uint32_t host, u8 *idx);
void lfRTBUpdate   (void *param);
int  magw_proc_init_net(struct net *net);
void magw_proc_exit_net(struct net *net);
int  magw_mib_init_net (struct net *net);
void magw_mib_exit_net (struct net *net);
inline 
void mgCheckStat(struct sock *sk, struct sk_buff *skb, u8 *vals, char *name);
inline 
void mgCheckStat2(struct sock *sk, struct sock *child, u8 *vals, char *name);
inline 
void mgCheckStat3(struct sk_buff *skb, u8 *vals, char *name);

void gwSetIPv4(u8 idx, const char *addr, int len);
void gwGetIPv4(u8 idx, char *addr, int len);

void gwSetIPv6(u8 idx, const char *addr, int len);
void gwGetIPv6(u8 idx, char *addr, int len);

extern struct mptcp_sm_ops mptcp_sm_default;

extern int sysctl_mptcp_gw_port; //0907
extern u16 mptcp_gw_port; //0907
extern int sysctl_mptcp_sm_debug;
extern int sysctl_magw_st_debug;


#else /* CONFIG_NC_KT_MAGW */


static inline int  mptcp_register_session_monitor(struct mptcp_sm_ops *sm) {return 0;};
static inline void mptcp_unregister_session_monitor(struct mptcp_sm_ops *sm) {};
static inline void mptcp_init_session_monitor(struct mptcp_cb *mpcb) {};
static inline void mptcp_cleanup_session_monitor(struct mptcp_cb *mpcb) {};
static inline void mptcp_sm_fallback_default(struct mptcp_cb *mpcb) {};
static inline void mptcp_get_default_session_monitor(char *name) {};
static inline int  mptcp_set_default_session_monitor(const char *name) {return 0;};
static inline void nc_inc_rx_stat(struct tcp_sock *tp, u32 len) {};
static inline void nc_inc_tx_stat(struct tcp_sock *tp, u32 len) {};
static inline void rSetRow(int idx, u32 uS, u32 uE) {};
static inline int isIPv4LTE(uint32_t host) {return 0;};
static inline int isIPv4MagwSvc(uint32_t host, u8 *idx) {return 0;};
static inline void lfRTBUpdate (void *param) {};
static inline int  magw_proc_init_net(struct net *net){return 0;};
static inline void magw_proc_exit_net(struct net *net);
static inline int  magw_mib_init_net(struct net *net){return 0;};
static inline void magw_mib_exit_net(struct net *net);
static inline void mgCheckStat(struct sock *sk, struct sk_buff *skb, u8 *vals, char *name){};
static inline void mgCheckStat2(struct sock *sk, struct sock *child, u8 *vals, char *name){};
static inline void mgCheckStat3(struct sk_buff *skb, u8 *vals, char *name){};
#define mptcp_sm_debug(fmt, args...)	do {} while(0)
#define magw_st_debug(fmt, args...)	do {} while(0)
#define NC_INC_RX(_st, _len)            do {} while(0)
#define NC_INC_TX(_st, _len)   			do {} while(0)
#define MAGW_INC_STATS_I1_V4(net, field) do {} while(0)
#define MAGW_INC_STATS_I2_V4(net, field) do {} while(0)
#define MAGW_INC_STATS_I1_V6(net, field) do {} while(0)
#define MAGW_INC_STATS_I2_V6(net, field) do {} while(0)

#endif /* CONFIG_NC_KT_MAGW */

#endif /* _MPTCP_MAGW_H */
