/******************************************************************************

            版权所有 (C), 2017-2018, xxx Co.xxx, Ltd.

 ******************************************************************************
    文 件 名 : ss_parser_pkt.c
    版 本 号 : V1.0
    作    者 : zc
    生成日期 : 2018年8月21日
    功能描述 : 数据包解析
    修改历史 :
******************************************************************************/
#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_gre.h>
#include <rte_sctp.h>

#include "ss_parser_pkt.h"

#define IPPORT_VXLAN            4789
#define DEFAULT_VXLAN_PORT      4789
#define DEFAULT_DNS_PORT        53

#define SS_VXLAN_HF_VNI_BE   rte_cpu_to_be_32(0x08000000)
#define SS_TCP_HLEN(_hdr)    (((_hdr)->data_off & 0xF0) >> 2)
#define SS_IPV4_HLEN(_hdr)   (((_hdr)->version_ihl & 0x0F) << 2)

#define SS_RETURN_RES(_cond, _res) do { \
    if ((_cond)) return (_res); } while (0)

/*****************************************************************************
    函 数 名 : ss_ptype_l4
    功能描述 : 获取L4包类型
    输入参数 : uint8_t proto
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月23日
*****************************************************************************/
static uint32_t
ss_ptype_l4(uint8_t proto)
{
    static const uint32_t ptype_l4_proto[256] = {
        [IPPROTO_ICMP]    = RTE_PTYPE_L4_ICMP,
        [IPPROTO_IGMP]    = RTE_PTYPE_L4_IGMP,
        [IPPROTO_TCP]     = RTE_PTYPE_L4_TCP,
        [IPPROTO_UDP]     = RTE_PTYPE_L4_UDP,
        [IPPROTO_ICMPV6]  = RTE_PTYPE_L4_ICMP6,
        [IPPROTO_SCTP]    = RTE_PTYPE_L4_SCTP,
        [IPPROTO_UDPLITE] = RTE_PTYPE_L4_UDPLITE,
    };

    return ptype_l4_proto[proto];
}

/*****************************************************************************
    函 数 名 : ss_ptype_l3_ipv4
    功能描述 : 获取L3的IPv4类型
    输入参数 : uint8_t ipv_ihl
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月23日
*****************************************************************************/
static uint32_t
ss_ptype_l3_ipv4(uint8_t ipv_ihl)
{
    static const uint32_t ptype_l3_ip_proto_map[256] = {
        [0x45] = RTE_PTYPE_L3_IPV4,
        [0x46] = RTE_PTYPE_L3_IPV4_EXT,
        [0x47] = RTE_PTYPE_L3_IPV4_EXT,
        [0x48] = RTE_PTYPE_L3_IPV4_EXT,
        [0x49] = RTE_PTYPE_L3_IPV4_EXT,
        [0x4A] = RTE_PTYPE_L3_IPV4_EXT,
        [0x4B] = RTE_PTYPE_L3_IPV4_EXT,
        [0x4C] = RTE_PTYPE_L3_IPV4_EXT,
        [0x4D] = RTE_PTYPE_L3_IPV4_EXT,
        [0x4E] = RTE_PTYPE_L3_IPV4_EXT,
        [0x4F] = RTE_PTYPE_L3_IPV4_EXT,
    };

    return ptype_l3_ip_proto_map[ipv_ihl];
}

/*****************************************************************************
    函 数 名 : ss_ptype_l3_ipv6
    功能描述 : 获取L3的IPv6类型
    输入参数 : uint8_t ip6_proto
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月23日
*****************************************************************************/
static uint32_t
ss_ptype_l3_ipv6(uint8_t ip6_proto)
{
    static const uint32_t ip6_ext_proto_map[256] = {
        [IPPROTO_HOPOPTS]  = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
        [IPPROTO_ROUTING]  = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
        [IPPROTO_FRAGMENT] = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
        [IPPROTO_Ess]      = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
        [IPPROTO_AH]       = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
        [IPPROTO_DSTOPTS]  = RTE_PTYPE_L3_IPV6_EXT - RTE_PTYPE_L3_IPV6,
    };

    return RTE_PTYPE_L3_IPV6 + ip6_ext_proto_map[ip6_proto];
}

/*****************************************************************************
    函 数 名 : ss_ptype_inner_l4
    功能描述 : 获取内L4包类型
    输入参数 : uint8_t proto
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static uint32_t
ss_ptype_inner_l4(uint8_t proto)
{
    static const uint32_t ptype_inner_l4_proto[256] = {
        [IPPROTO_ICMP]    = RTE_PTYPE_INNER_L4_ICMP,
        [IPPROTO_IGMP]    = RTE_PTYPE_INNER_L4_IGMP,
        [IPPROTO_TCP]     = RTE_PTYPE_INNER_L4_TCP,
        [IPPROTO_UDP]     = RTE_PTYPE_INNER_L4_UDP,
        [IPPROTO_ICMPV6]  = RTE_PTYPE_INNER_L4_ICMP6,
        [IPPROTO_SCTP]    = RTE_PTYPE_INNER_L4_SCTP,
        [IPPROTO_UDPLITE] = RTE_PTYPE_INNER_L4_UDPLITE,
    };

    return ptype_inner_l4_proto[proto];
}

/*****************************************************************************
    函 数 名 : ss_ptype_inner_l3_ipv4
    功能描述 : 获取内L3的IPv4类型
    输入参数 : uint8_t ipv_ihl
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static uint32_t
ss_ptype_inner_l3_ipv4(uint8_t ipv_ihl)
{
    static const uint32_t ptype_inner_l3_ip_proto_map[256] = {
        [0x45] = RTE_PTYPE_INNER_L3_IPV4,
        [0x46] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x47] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x48] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x49] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4A] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4B] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4C] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4D] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4E] = RTE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4F] = RTE_PTYPE_INNER_L3_IPV4_EXT,
    };

    return ptype_inner_l3_ip_proto_map[ipv_ihl];
}

/*****************************************************************************
    函 数 名 : ss_ptype_inner_l3_ipv6
    功能描述 : 获取内L3的IPv6类型
    输入参数 : uint8_t ip6_proto
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static uint32_t
ss_ptype_inner_l3_ipv6(uint8_t ip6_proto)
{
    static const uint32_t ptype_inner_ip6_ext_proto_map[256] = {
        [IPPROTO_HOPOPTS]  = RTE_PTYPE_INNER_L3_IPV6_EXT -
            RTE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_ROUTING]  = RTE_PTYPE_INNER_L3_IPV6_EXT -
            RTE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_FRAGMENT] = RTE_PTYPE_INNER_L3_IPV6_EXT -
            RTE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_Ess]      = RTE_PTYPE_INNER_L3_IPV6_EXT -
            RTE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_AH]       = RTE_PTYPE_INNER_L3_IPV6_EXT -
            RTE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_DSTOPTS]  = RTE_PTYPE_INNER_L3_IPV6_EXT -
            RTE_PTYPE_INNER_L3_IPV6,
    };

    return RTE_PTYPE_INNER_L3_IPV6 +
        ptype_inner_ip6_ext_proto_map[ip6_proto];
}

/*****************************************************************************
    函 数 名 : ss_ptype_tunnel
    功能描述 : 获取tunnel数据类型
    输入参数 : const struct rte_mbuf *m
               uint16_t *proto
               uint32_t *off
    输出参数 : 无
    返 回 值 : uint32_t
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static uint32_t
ss_ptype_tunnel(const struct rte_mbuf *m, uint16_t *proto, 
    uint32_t *off)
{
    switch (*proto) {
    case IPPROTO_GRE:
    {
        static const uint8_t opt_len[16] = {
            [0x0] = 4,
            [0x1] = 8,
            [0x2] = 8,
            [0x8] = 8,
            [0x3] = 12,
            [0x9] = 12,
            [0xa] = 12,
            [0xb] = 16,
        };
        uint16_t flags;
        struct gre_hdr gh_copy;
        const struct gre_hdr *gh;

        gh = rte_pktmbuf_read(m, *off, sizeof(*gh), &gh_copy);
        SS_RETURN_RES(unlikely(gh == NULL), 0);

        flags = rte_be_to_cpu_16(*(const uint16_t *)gh);
        flags >>= 12;
        SS_RETURN_RES(opt_len[flags] == 0, 0);

        *off += opt_len[flags];
        *proto = gh->proto;
        if (*proto == rte_cpu_to_be_16(ETHER_TYPE_TEB)) {
            return RTE_PTYPE_TUNNEL_NVGRE;
        } else {
            return RTE_PTYPE_TUNNEL_GRE;
        }
    }
    case IPPROTO_IPIP:
    {
        *proto = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
        return RTE_PTYPE_TUNNEL_IP;
    }
    case IPPROTO_IPV6:
    {
        *proto = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
        return RTE_PTYPE_TUNNEL_IP; /* IP is also valid for IPv6 */
    }
    case IPPORT_VXLAN:
    {
        struct vxlan_hdr *vxh_copy;
        const struct vxlan_hdr *vxh;
        uint32_t off_len = *off + sizeof(struct udp_hdr);

        vxh = rte_pktmbuf_read(m, off_len, sizeof(*vxh), &vxh_copy);
        SS_RETURN_RES(unlikely(vxh == NULL), 0);
        SS_RETURN_RES(unlikely(vxh->vx_flags != SS_VXLAN_HF_VNI_BE), 0);

        *off += ETHER_VXLAN_HLEN;
        *proto = rte_cpu_to_be_16(ETHER_TYPE_TEB);
        return RTE_PTYPE_TUNNEL_VXLAN;
    }
    default:
        return 0;
    }
}

/*****************************************************************************
    函 数 名 : ss_skip_ip6_ext
    功能描述 : 解析IPv6扩展头
    输入参数 : const struct rte_mbuf *m
               uint16_t proto
               uint32_t *off
               int *frag
    输出参数 : 无
    返 回 值 : uint16_t
    作    者 : zc
    日    期 : 2018年8月23日
*****************************************************************************/
static uint16_t
ss_skip_ip6_ext(const struct rte_mbuf *m, uint16_t proto, 
    uint32_t *off, int *frag)
{
    struct ext_hdr {
        uint8_t next_hdr;
        uint8_t len;
    };
    unsigned int i;
    struct ext_hdr exh_copy;
    const struct ext_hdr *exh;

    *frag = 0;

#define ss_MAX_EXT_HDRS 5
    for (i = 0; i < ss_MAX_EXT_HDRS; i++) {
        switch (proto) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        {
            exh = rte_pktmbuf_read(m, *off, sizeof(*exh), &exh_copy);
            SS_RETURN_RES(exh == NULL, 0);
            *off += (exh->len + 1) * 8;
            proto = exh->next_hdr;
            break;
        }
        case IPPROTO_FRAGMENT:
        {
            exh = rte_pktmbuf_read(m, *off, sizeof(*exh), &exh_copy);
            SS_RETURN_RES(exh == NULL, 0);
            *off += 8;
            proto = exh->next_hdr;
            *frag = 1;
            return proto; /* this is always the last ext hdr */
        }
        case IPPROTO_NONE:
            return 0;
        default:
            return proto;
        }
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_inner_tcp
    功能描述 : 解析内TCP数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_inner_tcp(struct rte_mbuf *m, uint32_t off_len)
{
    struct tcp_hdr th_copy;
    const struct tcp_hdr *th;

    th = rte_pktmbuf_read(m, off_len, sizeof(*th), &th_copy);
    SS_RETURN_RES(unlikely(th == NULL), 0);

    m->ss.ssort = th->src_port;
    m->ss.dport = th->dst_port;
    m->ss.inner_l4_len = SS_TCP_HLEN(th);

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_inner_sctp
    功能描述 : 解析内SCTP数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_inner_sctp(struct rte_mbuf *m, uint32_t off_len)
{
    struct sctp_hdr sh_copy;
    const struct sctp_hdr *sh;

    sh = rte_pktmbuf_read(m, off_len, sizeof(*sh), &sh_copy);
    SS_RETURN_RES(unlikely(sh == NULL), 0);

    m->ss.ssort = sh->src_port;
    m->ss.dport = sh->dst_port;
    m->ss.inner_l4_len = sizeof(*sh);

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_inner_l4_proto
    功能描述 : 解析内L4协议
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_inner_l4_proto(struct rte_mbuf *m, uint32_t off_len)
{
    int ret = 0;
    uint32_t type = m->ss.packet_type & RTE_PTYPE_INNER_L4_MASK;

    switch (type) {
    case RTE_PTYPE_INNER_L4_UDP:
    case RTE_PTYPE_INNER_L4_ICMP:
    case RTE_PTYPE_INNER_L4_IGMP:
    case RTE_PTYPE_INNER_L4_ICMP6:
    case RTE_PTYPE_INNER_L4_UDPLITE:
    {
        break;
    }
    case RTE_PTYPE_INNER_L4_TCP:
    {
        ret = ss_parser_pkt_inner_tcp(m, off_len);
        break;
    }
    case RTE_PTYPE_INNER_L4_SCTP:
    {
        ret = ss_parser_pkt_inner_sctp(m, off_len);
        break;
    }
    default:
        break;
    }

    return ret;    
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_inner_ipv4
    功能描述 : 解析内IPv4数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_inner_ipv4(struct rte_mbuf *m, uint32_t off_len)
{
    int ret = 0;
    uint16_t proto;
    uint32_t off = off_len;
    struct ipv4_hdr ip4h_copy;
    const struct ipv4_hdr *ip4h;

    ip4h = rte_pktmbuf_read(m, off, sizeof(*ip4h), &ip4h_copy);
    SS_RETURN_RES(unlikely(ip4h == NULL), 0);
    SS_RETURN_RES(ip4h->fragment_offset & rte_cpu_to_be_16(
        IPV4_HDR_OFFSET_MASK | IPV4_HDR_MF_FLAG), 0);

    m->ss.packet_type |= ss_ptype_inner_l3_ipv4(ip4h->version_ihl);
    m->ss.inner_l3_len = SS_IPV4_HLEN(ip4h);
    m->ss.inner_sip[0] = ip4h->src_addr;
    m->ss.inner_dip[0] = ip4h->dst_addr;
    off += m->ss.inner_l3_len;
    proto = ip4h->next_proto_id;
    m->ss.packet_type |= ss_ptype_inner_l4(proto);

    return ss_parser_pkt_inner_l4_proto(m, off);
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_inner_ipv6
    功能描述 : 解析内IPv6数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_inner_ipv6(struct rte_mbuf *m, uint32_t off_len)
{
    int frag = 0;
    uint16_t proto;
    uint32_t off = off_len;
    struct ipv6_hdr ip6h_copy;
    const struct ipv6_hdr *ip6h;
    
    ip6h = rte_pktmbuf_read(m, off, sizeof(*ip6h), &ip6h_copy);
    SS_RETURN_RES(unlikely(ip6h == NULL), 0);

    rte_memcpy(m->ss.inner_sip, ip6h->src_addr, 16);
    rte_memcpy(m->ss.inner_dip, ip6h->dst_addr, 16);
    m->ss.inner_l3_len = sizeof(*ip6h);
    off += m->ss.inner_l3_len;
    proto = ip6h->proto;
    m->ss.packet_type |= ss_ptype_inner_l3_ipv6(proto);

    /* 解析IPv6扩展头 */
    if ((m->ss.packet_type & RTE_PTYPE_L3_MASK)
        == RTE_PTYPE_L3_IPV6_EXT) {
        uint32_t prev_off = off;

        proto = ss_skip_ip6_ext(m, proto, &off, &frag);
        m->ss.inner_l3_len += off - prev_off;
    }
    SS_RETURN_RES(!proto, 0);
    SS_RETURN_RES(frag, 0);
    m->ss.packet_type |= ss_ptype_inner_l4(proto);

    return ss_parser_pkt_inner_l4_proto(m, off);
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_tunnel
    功能描述 : 解析tunnel数据
    输入参数 : struct rte_mbuf *m
               uint16_t proto
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_tunnel(struct rte_mbuf *m, uint16_t proto,
    uint32_t off_len)
{
    int ret = 0;
    uint32_t packet_type;
    uint32_t off = off_len;
    uint32_t prev_off = off_len;

    m->ss.l4_len = 0;
    packet_type = ss_ptype_tunnel(m, &proto, &off);
    SS_RETURN_RES(unlikely(packet_type == 0), 0);
    m->ss.tunnel_len = off - prev_off;
    m->ss.packet_type |= packet_type;

    if (proto == rte_cpu_to_be_16(ETHER_TYPE_TEB)) {
        struct ether_hdr eh_copy;
        const struct ether_hdr *eh;

        eh = rte_pktmbuf_read(m, off, sizeof(*eh), &eh_copy);
        SS_RETURN_RES(unlikely(eh == NULL), 0);
        rte_memcpy(m->ss.inner_smac, eh->s_addr.addr_bytes,
            ETHER_ADDR_LEN);
        rte_memcpy(m->ss.inner_dmac, eh->d_addr.addr_bytes,
            ETHER_ADDR_LEN);
        m->ss.packet_type |= RTE_PTYPE_INNER_L2_ETHER;
        m->ss.inner_l2_len = sizeof(*eh);
        proto = eh->ether_type;
        off += sizeof(*eh);
    }

    if (proto == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
        struct vlan_hdr vh_copy;
        const struct vlan_hdr *vh;

        m->ss.packet_type &= ~RTE_PTYPE_INNER_L2_MASK;
        m->ss.packet_type |= RTE_PTYPE_INNER_L2_ETHER_VLAN;
        vh = rte_pktmbuf_read(m, off, sizeof(*vh), &vh_copy);
        SS_RETURN_RES(unlikely(vh == NULL), 0);
        off += sizeof(*vh);
        m->ss.inner_l2_len += sizeof(*vh);
        proto = vh->eth_proto;
    } else if (proto == rte_cpu_to_be_16(ETHER_TYPE_QINQ)) {
        struct vlan_hdr vh_copy;
        const struct vlan_hdr *vh;

        m->ss.packet_type &= ~RTE_PTYPE_INNER_L2_MASK;
        m->ss.packet_type |= RTE_PTYPE_INNER_L2_ETHER_QINQ;
        vh = rte_pktmbuf_read(m, off + sizeof(*vh), sizeof(*vh),
            &vh_copy);
        SS_RETURN_RES(unlikely(vh == NULL), 0);
        off += 2 * sizeof(*vh);
        m->ss.inner_l2_len += 2 * sizeof(*vh);
        proto = vh->eth_proto;
    }

    switch (rte_be_to_cpu_16(proto)) {
    case ETHER_TYPE_IPv4:
    {
        ret = ss_parser_pkt_inner_ipv4(m, off);
        break;
    }
    case ETHER_TYPE_IPv6:
    {
        ret = ss_parser_pkt_inner_ipv6(m, off);
        break;
    }
    default:
        break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_udp_port
    功能描述 : 根据UDP端口进行处理
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
               const struct udp_hdr *uh
               uint16_t port
               uint8_t *find
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年9月15日
*****************************************************************************/
static int
ss_parser_pkt_udp_port(struct rte_mbuf *m, uint32_t off_len,
    const struct udp_hdr *uh, uint16_t port, uint8_t *find)
{
    int ret = 0;

    switch (rte_be_to_cpu_16(port)) {
    case DEFAULT_DNS_PORT:
    {
        *find = 1;
        m->ss.ssort = uh->src_port;
        m->ss.dport = uh->dst_port;
        m->ss.l4_len = sizeof(*uh);
        return 1;
    }
    case DEFAULT_VXLAN_PORT:
    {
        *find = 1;
        ret = ss_parser_pkt_tunnel(m, IPPORT_VXLAN, off_len);
        break;
    }
    default:
        break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_udp
    功能描述 : 解析UDP数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年9月13日
*****************************************************************************/
static int
ss_parser_pkt_udp(struct rte_mbuf *m, uint32_t off_len)
{
    int ret = 0;
    uint8_t find = 0;
    struct udp_hdr *uh_copy;
    const struct udp_hdr *uh;

    uh = rte_pktmbuf_read(m, off_len, sizeof(*uh), &uh_copy);
    SS_RETURN_RES(unlikely(uh == NULL), 0);

    ret = ss_parser_pkt_udp_port(m, off_len, uh, uh->dst_port, &find);
    SS_RETURN_RES(find, ret);
    ret = ss_parser_pkt_udp_port(m, off_len, uh, uh->src_port, &find);

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_tcp
    功能描述 : 解析TCP数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月22日
*****************************************************************************/
static int
ss_parser_pkt_tcp(struct rte_mbuf *m, uint32_t off_len)
{
    struct tcp_hdr th_copy;
    const struct tcp_hdr *th;

    th = rte_pktmbuf_read(m, off_len, sizeof(*th), &th_copy);
    SS_RETURN_RES(unlikely(th == NULL), 0);

    m->ss.ssort = th->src_port;
    m->ss.dport = th->dst_port;
    m->ss.l4_len = SS_TCP_HLEN(th);

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_sctp
    功能描述 : 解析SCTP数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_sctp(struct rte_mbuf *m, uint32_t off_len)
{
    struct sctp_hdr sh_copy;
    const struct sctp_hdr *sh;

    sh = rte_pktmbuf_read(m, off_len, sizeof(*sh), &sh_copy);
    SS_RETURN_RES(unlikely(sh == NULL), 0);

    m->ss.ssort = sh->src_port;
    m->ss.dport = sh->dst_port;
    m->ss.l4_len = sizeof(*sh);

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_l4_proto
    功能描述 : 解析L4协议
    输入参数 : struct rte_mbuf *m
               uint16_t proto
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月24日
*****************************************************************************/
static int
ss_parser_pkt_l4_proto(struct rte_mbuf *m, uint16_t proto,
    uint32_t off_len)
{
    int ret = 0;
    uint32_t type = m->ss.packet_type & RTE_PTYPE_L4_MASK;

    switch (type) {
    case RTE_PTYPE_L4_UDP:
    {
        ret = ss_parser_pkt_udp(m, off_len);
        break;
    }
    case RTE_PTYPE_L4_ICMP:
    case RTE_PTYPE_L4_IGMP:
    case RTE_PTYPE_L4_ICMP6:
    case RTE_PTYPE_L4_UDPLITE:
    {
        break;
    }
    case RTE_PTYPE_L4_TCP:
    {
        ret = ss_parser_pkt_tcp(m, off_len);
        break;
    }
    case RTE_PTYPE_L4_SCTP:
    {
        ret = ss_parser_pkt_sctp(m, off_len);
        break;
    }
    default:
        ret = ss_parser_pkt_tunnel(m, proto, off_len);
        break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_ipv4
    功能描述 : 解析IPv4数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月22日
*****************************************************************************/
static int
ss_parser_pkt_ipv4(struct rte_mbuf *m, uint32_t off_len)
{
    uint16_t proto;
    uint32_t off = off_len;
    struct ipv4_hdr ip4h_copy;
    const struct ipv4_hdr *ip4h;

    ip4h = rte_pktmbuf_read(m, off, sizeof(*ip4h), &ip4h_copy);
    SS_RETURN_RES(unlikely(ip4h == NULL), 0);
    SS_RETURN_RES(ip4h->fragment_offset & rte_cpu_to_be_16(
        IPV4_HDR_OFFSET_MASK | IPV4_HDR_MF_FLAG), 0);

    m->ss.packet_type |= ss_ptype_l3_ipv4(ip4h->version_ihl);
    m->ss.sip[0] = ip4h->src_addr;
    m->ss.dip[0] = ip4h->dst_addr;
    m->ss.l3_len = SS_IPV4_HLEN(ip4h);
    off += m->ss.l3_len;
    proto = ip4h->next_proto_id;
    m->ss.packet_type |= ss_ptype_l4(proto);

    return ss_parser_pkt_l4_proto(m, proto, off);
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_ipv6
    功能描述 : 解析IPv6数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月22日
*****************************************************************************/
static int
ss_parser_pkt_ipv6(struct rte_mbuf *m, uint32_t off_len)
{
    int frag = 0;
    uint16_t proto;
    uint32_t off = off_len;
    struct ipv6_hdr ip6h_copy;
    const struct ipv6_hdr *ip6h;

    ip6h = rte_pktmbuf_read(m, off, sizeof(*ip6h), &ip6h_copy);
    SS_RETURN_RES(unlikely(ip6h == NULL), 0);

    rte_memcpy(m->ss.sip, ip6h->src_addr, 16);
    rte_memcpy(m->ss.dip, ip6h->dst_addr, 16);
    m->ss.l3_len = sizeof(*ip6h);
    off += m->ss.l3_len;
    proto = ip6h->proto;
    m->ss.packet_type |= ss_ptype_l3_ipv6(proto);

    /* 解析IPv6扩展头 */
    if ((m->ss.packet_type & RTE_PTYPE_L3_MASK)
        == RTE_PTYPE_L3_IPV6_EXT) {
        proto = ss_skip_ip6_ext(m, proto, &off, &frag);
        m->ss.l3_len = off - m->ss.l2_len;
    }
    SS_RETURN_RES(proto == 0, 0);
    SS_RETURN_RES(frag, 0);
    m->ss.packet_type |= ss_ptype_l4(proto);

    return ss_parser_pkt_l4_proto(m, proto, off);
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_vlan
    功能描述 : 解析VLAN数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月23日
*****************************************************************************/
static int
ss_parser_pkt_vlan(struct rte_mbuf *m, uint32_t off_len)
{
    int ret = 0;
    uint16_t proto;
    uint32_t off = off_len;
    struct vlan_hdr vh_copy;
    const struct vlan_hdr *vh;

    vh = rte_pktmbuf_read(m, off, sizeof(*vh), &vh_copy);
    SS_RETURN_RES(unlikely(vh == NULL), 0);
    proto = vh->eth_proto;

    m->ss.packet_type = RTE_PTYPE_L2_ETHER_VLAN;
    m->ss.l2_len += sizeof(*vh);
    off += sizeof(*vh);

    switch (rte_be_to_cpu_16(proto)) {
    case ETHER_TYPE_IPv4:
    {
        ret = ss_parser_pkt_ipv4(m, off);
        break;
    }
    case ETHER_TYPE_IPv6:
    {
        ret = ss_parser_pkt_ipv6(m, off);
        break;
    }
    default:
        break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_qinq
    功能描述 : 解析QINQ数据
    输入参数 : struct rte_mbuf *m
               uint32_t off_len
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月23日
*****************************************************************************/
static int
ss_parser_pkt_qinq(struct rte_mbuf *m, uint32_t off_len)
{
    int ret = 0;
    uint32_t off = off_len;
    struct vlan_hdr vh_copy;
    const struct vlan_hdr *vh;

    vh = rte_pktmbuf_read(m, off + sizeof(*vh), sizeof(*vh), &vh_copy);
    SS_RETURN_RES(unlikely(vh == NULL), 0);

    m->ss.packet_type = RTE_PTYPE_L2_ETHER_QINQ;
    m->ss.l2_len += 2 * sizeof(*vh);
    off += 2 * sizeof(*vh);

    switch (rte_be_to_cpu_16(vh->eth_proto)) {
    case ETHER_TYPE_IPv4:
    {
        ret = ss_parser_pkt_ipv4(m, off);
        break;
    }
    case ETHER_TYPE_IPv6:
    {
        ret = ss_parser_pkt_ipv6(m, off);
        break;
    }
    default:
        break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt_ether
    功能描述 : 解析二层数据
    输入参数 : struct rte_mbuf *m
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月22日
*****************************************************************************/
static int
ss_parser_pkt_ether(struct rte_mbuf *m)
{
    int ret = 0;
    uint32_t off = 0;
    struct ether_hdr eh_copy;
    const struct ether_hdr *eh;

    eh = rte_pktmbuf_read(m, off, sizeof(*eh), &eh_copy);
    SS_RETURN_RES(unlikely(eh == NULL), 0);

    rte_memcpy(m->ss.smac, eh->s_addr.addr_bytes, ETHER_ADDR_LEN);
    rte_memcpy(m->ss.dmac, eh->d_addr.addr_bytes, ETHER_ADDR_LEN);
    m->ss.packet_type = RTE_PTYPE_L2_ETHER;
    m->ss.l2_len = sizeof(*eh);
    off = m->ss.l2_len;

    switch (rte_be_to_cpu_16(eh->ether_type)) {
    case ETHER_TYPE_IPv4: //IPv4
    {
        ret = ss_parser_pkt_ipv4(m, off);
        break;
    }
    case ETHER_TYPE_IPv6: //IPv6
    {
        ret = ss_parser_pkt_ipv6(m, off);
        break;
    }
    case ETHER_TYPE_VLAN: //VLAN
    {
        ret = ss_parser_pkt_vlan(m, off);
        break;
    }
    case ETHER_TYPE_QINQ: //QINQ
    {
        ret = ss_parser_pkt_qinq(m, off);
        break;
    }
    default:
        break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_parser_pkt
    功能描述 : 解析数据包
    输入参数 : struct rte_mbuf *m
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年8月22日
*****************************************************************************/
int
ss_parser_pkt(struct rte_mbuf *m)
{
    SS_RETURN_RES(unlikely(m == NULL), 0);
    memset(&m->ss, 0, sizeof(struct ss_mbuf));

    return ss_parser_pkt_ether(m);
}

