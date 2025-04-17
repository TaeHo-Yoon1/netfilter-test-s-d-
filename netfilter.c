#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

// Target host to block
char *target_host = NULL;

void dump(unsigned char* buf, int size) {
        int i;
        for (i = 0; i < size; i++) {
                if (i != 0 && i % 16 == 0)
                        printf("\n");
                printf("%02X ", buf[i]);
        }
        printf("\n");
}

// Function to check if a packet contains HTTP request with target host
int check_http_host(unsigned char *data, int len) {
    if (len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
        return 0;
    }

    struct iphdr *iph = (struct iphdr*)data;
    int ip_header_len = iph->ihl * 4;
    
    if (iph->protocol != IPPROTO_TCP) {
        return 0;
    }

    struct tcphdr *tcph = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcph->doff * 4;
    
    // Start of HTTP payload
    unsigned char *http_payload = data + ip_header_len + tcp_header_len;
    int payload_len = len - ip_header_len - tcp_header_len;
    
    if (payload_len <= 0) {
        return 0;
    }
    
    // Check if this is an HTTP request (starts with method like "GET", "POST", etc.)
    if (payload_len > 3 && 
        ((http_payload[0] == 'G' && http_payload[1] == 'E' && http_payload[2] == 'T') ||
         (http_payload[0] == 'P' && http_payload[1] == 'O' && http_payload[2] == 'S' && http_payload[3] == 'T') ||
         (http_payload[0] == 'H' && http_payload[1] == 'E' && http_payload[2] == 'A' && http_payload[3] == 'D'))) {
        
        // Search for "Host: " in the HTTP header
        unsigned char *host_field = memmem(http_payload, payload_len, "Host: ", 6);
        if (host_field) {
            host_field += 6; // Skip "Host: "
            
            // Find end of the line (CR or LF)
            unsigned char *end_of_line = memchr(host_field, '\r', payload_len - (size_t)(host_field - http_payload));
            if (!end_of_line) {
                end_of_line = memchr(host_field, '\n', payload_len - (size_t)(host_field - http_payload));
            }
            
            if (end_of_line) {
                int host_len = (int)(end_of_line - host_field);
                char host[256] = {0};
                
                if (host_len < (int)sizeof(host)) {
                    memcpy(host, host_field, host_len);
                    host[host_len] = '\0';
                    
                    // Remove port number if present
                    char *port = strchr(host, ':');
                    if (port) {
                        *port = '\0';
                    }
                    
                    printf("HTTP Host: %s\n", host);
                    
                    // Check if this is the target host
                    if (strcmp(host, target_host) == 0) {
                        printf("Found target host: %s\n", host);
                        return 1;
                    }
                }
            }
        }
    }
    
    return 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi;
        int ret;
        unsigned char *data;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(ph->hw_protocol), ph->hook, id);
        }

        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);

                printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                        printf("%02x:", hwph->hw_addr[i]);
                printf("%02x ", hwph->hw_addr[hlen-1]);
        }

        mark = nfq_get_nfmark(tb);
        if (mark)
                printf("mark=%u ", mark);

        ifi = nfq_get_indev(tb);
        if (ifi)
                printf("indev=%u ", ifi);

        ifi = nfq_get_outdev(tb);
        if (ifi)
                printf("outdev=%u ", ifi);
        ifi = nfq_get_physindev(tb);
        if (ifi)
                printf("physindev=%u ", ifi);

        ifi = nfq_get_physoutdev(tb);
        if (ifi)
                printf("physoutdev=%u ", ifi);

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0) {
                printf("payload_len=%d\n", ret);
                // dump(data, ret);
        }
        fputc('\n', stdout);

        return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg __attribute__((unused)),
              struct nfq_data *nfa, void *data __attribute__((unused)))
{
        u_int32_t id = print_pkt(nfa);
        printf("entering callback\n");
        
        unsigned char *packet_data;
        int packet_len = nfq_get_payload(nfa, &packet_data);
        
        if (packet_len >= 0) {
            // Check if this packet contains HTTP traffic with the target host
            if (check_http_host(packet_data, packet_len)) {
                printf("Dropping packet to harmful website\n");
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
        
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        if (argc != 2) {
            printf("syntax : netfilter-test <host>\n");
            printf("sample : netfilter-test test.gilgil.net\n");
            return 1;
        }
        
        target_host = argv[1];
        printf("Target host to block: %s\n", target_host);

        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        printf("Ready to filter. Run the following command to redirect packets to the queue:\n");
        printf("sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0\n");
        printf("sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0\n");

        for (;;) {
                if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
                        printf("pkt received\n");
                        nfq_handle_packet(h, buf, rv);
                        continue;
                }

                if (rv < 0 && errno == ENOBUFS) {
                        printf("losing packets!\n");
                        continue;
                }
                perror("recv failed");
                break;
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);

        printf("closing library handle\n");
        nfq_close(h);

        exit(0);
}
