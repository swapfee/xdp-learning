// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>        // XDP definitions, struct xdp_md
#include <linux/if_ether.h>   // struct ethhdr, ETH_P_IP
#include <linux/ip.h>         // struct iphdr
#include <linux/udp.h>        // struct udphdr
#include <linux/tcp.h>        // struct tcphdr

#include <bpf/bpf_helpers.h>  // SEC(), bpf_printk()
#include <bpf/bpf_endian.h>   // bpf_ntohs(), bpf_htons()


SEC("xdp")
int xdp_parse(struct xdp_md *ctx)
{
    /*
     * ctx->data is where the packet starts in memory.
     *
     * ctx->data_end is where the packet ends.
     *
     * We use these two pointers to make sure we never
     * read outside the packet.
     */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;


    /*
     * eth points to the start of the packet.
     *
     * Ethernet is normally the first header we see.
     */
    struct ethhdr *eth = data;


    /*
     * eth + 1 means:
     *
     * move forward by sizeof(struct ethhdr).
     *
     * If that goes past data_end, the packet is too
     * small to even contain an Ethernet header.
     */
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }


    /*
     * h_proto tells us what protocol comes AFTER
     * the Ethernet header.
     *
     * Examples:
     *
     * ETH_P_IP   = IPv4
     * ETH_P_IPV6 = IPv6
     * ETH_P_ARP  = ARP
     *
     * For now we only want IPv4.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }


    /*
     * We now know Ethernet says the next header is IPv4.
     *
     * eth + 1 points immediately after the Ethernet
     * header, which is where the IPv4 header starts.
     */
    struct iphdr *ip = (void *)(eth + 1);


    /*
     * Before reading fields from the IPv4 header,
     * make sure the minimum IPv4 header exists.
     */
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }


    /*
     * ip->ihl means:
     *
     * Internet Header Length
     *
     * It is measured in 32-bit words.
     *
     * 1 word = 4 bytes
     *
     * Example:
     *
     * ihl = 5
     *
     * 5 * 4 = 20-byte IPv4 header
     */
    __u32 ip_header_length = ip->ihl * 4;


    /*
     * The minimum valid IPv4 header length is 20 bytes.
     *
     * If ihl says something smaller than that,
     * something is wrong with the packet.
     */
    if (ip_header_length < sizeof(struct iphdr)) {
        return XDP_PASS;
    }


    /*
     * Make sure the FULL IPv4 header fits inside
     * the packet.
     */
    if ((void *)ip + ip_header_length > data_end) {
        return XDP_PASS;
    }


    /*
     * ip->protocol tells us which transport protocol
     * comes after IPv4.
     *
     * Examples:
     *
     * IPPROTO_UDP
     * IPPROTO_TCP
     * IPPROTO_ICMP
     */


    /*
     * ==========================
     * UDP
     * ==========================
     */
    if (ip->protocol == IPPROTO_UDP) {

        /*
         * UDP begins after the IPv4 header.
         *
         * We use ip_header_length instead of ip + 1
         * because IPv4 headers can have different lengths.
         */
        struct udphdr *udp =
            (void *)ip + ip_header_length;


        /*
         * Before reading the UDP fields,
         * make sure the UDP header exists.
         */
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }


        /*
         * UDP ports are 16-bit values stored in
         * network byte order.
         *
         * bpf_ntohs() converts them into the CPU's
         * normal host byte order.
         */
        __u16 source_port =
            bpf_ntohs(udp->source);

        __u16 dest_port =
            bpf_ntohs(udp->dest);


        /*
         * Print what we found.
         *
         * Example:
         *
         * UDP: Source Port: 53421, Dest Port: 1194
         */
        bpf_printk(
            "UDP: Source Port: %u, Dest Port: %u",
            source_port,
            dest_port
        );
    }


    /*
     * ==========================
     * TCP
     * ==========================
     *
     * Notice this is OUTSIDE the UDP if statement.
     *
     * TCP and UDP are separate possibilities.
     */
    if (ip->protocol == IPPROTO_TCP) {

        /*
         * TCP also begins after the IPv4 header.
         */
        struct tcphdr *tcp =
            (void *)ip + ip_header_length;


        /*
         * Make sure the TCP header exists before
         * reading anything from it.
         */
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }


        /*
         * Convert the TCP ports from network byte
         * order to host byte order.
         */
        __u16 source_port =
            bpf_ntohs(tcp->source);

        __u16 dest_port =
            bpf_ntohs(tcp->dest);


        /*
         * Print the TCP ports.
         */
        bpf_printk(
            "TCP: Source Port: %u, Dest Port: %u",
            source_port,
            dest_port
        );
    }


    /*
     * We are only observing packets right now.
     *
     * Nothing is being blocked.
     */
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";
