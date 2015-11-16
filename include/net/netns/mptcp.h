/*
 *	MPTCP implementation - MPTCP namespace
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef __NETNS_MPTCP_H__
#define __NETNS_MPTCP_H__

#include <linux/compiler.h>

enum {
	MPTCP_PM_FULLMESH = 0,
	MPTCP_PM_MAX
};

struct mptcp_mib;

#ifdef CONFIG_NC_KT_MAGW
struct magw_mib;
enum {
	MAGW_FM_IPV4 =0,
	MAGW_FM_IPV6,
	MAGW_FM_MAX
};
enum {
	MAGW_IF_1 =0,
	MAGW_IF_2,
	MAGW_IF_MAX
};
enum {
	MAGW_SVC_LTE =0,
	MAGW_SVC_WIFI,
	MAGW_SVC_MAX
};
#endif /* CONFIG_NC_KT_MAGW */

struct netns_mptcp {
	DEFINE_SNMP_STAT(struct mptcp_mib, mptcp_statistics);

#ifdef CONFIG_NC_KT_MAGW
#if 0
	DEFINE_SNMP_STAT(struct magw_mib, mg_i1v4L_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i1v4W_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i2v4L_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i2v4W_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i1v6L_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i1v6W_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i2v6L_stat);
	DEFINE_SNMP_STAT(struct magw_mib, mg_i2v6W_stat);
#else
	DEFINE_SNMP_STAT(struct magw_mib, \
			   mg_stat[MAGW_FM_MAX][MAGW_IF_MAX][MAGW_SVC_MAX]);

#define mg_i1v4L_stat mg_stat[MAGW_FM_IPV4][MAGW_IF_1][MAGW_SVC_LTE]
#define mg_i1v4W_stat mg_stat[MAGW_FM_IPV4][MAGW_IF_1][MAGW_SVC_WIFI]
#define mg_i2v4L_stat mg_stat[MAGW_FM_IPV4][MAGW_IF_2][MAGW_SVC_LTE]
#define mg_i2v4W_stat mg_stat[MAGW_FM_IPV4][MAGW_IF_2][MAGW_SVC_WIFI]
#define mg_i1v6L_stat mg_stat[MAGW_FM_IPV6][MAGW_IF_1][MAGW_SVC_LTE]
#define mg_i1v6W_stat mg_stat[MAGW_FM_IPV6][MAGW_IF_1][MAGW_SVC_WIFI]
#define mg_i2v6L_stat mg_stat[MAGW_FM_IPV6][MAGW_IF_2][MAGW_SVC_LTE]
#define mg_i2v6W_stat mg_stat[MAGW_FM_IPV6][MAGW_IF_2][MAGW_SVC_WIFI]

#endif
#endif /* CONFIG_NC_KT_MAGW */

#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_net_mptcp;
#endif

	void *path_managers[MPTCP_PM_MAX];
};

#endif /* __NETNS_MPTCP_H__ */
