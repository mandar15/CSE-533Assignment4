#include "globals.h"

int 
main(
        int argc,
        char *argv[]
    )
{
    int raw_sockfd;
    int stream_sockfd;
    int stream_connfd = -1;
    int clilen;
    fd_set rset;
    int maxfd;
    int err;
    void* buffer = (void*)malloc(ETH_FRAME_LEN);
    arp_header* arp_hdr = (arp_header*) malloc(sizeof(arp_header));
    char sender_ip_addr_buf[16] = "";
    char dest_ip_addr_buf[16] = "";
    char ip_addr_buf[16] = "";
    unsigned char mac_addr_buf[6];
    int i;
    ar_cache* arp_cache = (ar_cache*) malloc(sizeof(ar_cache));

    struct sockaddr_ll * addr = (struct sockaddr_ll*) malloc(sizeof(struct sockaddr_ll));

    struct sockaddr_un servaddr;
    struct sockaddr_un cliaddr;

    struct sockaddr_in recvd_ip;
    struct hwaddr* hw_addr = (struct hwaddr *) malloc (sizeof(struct hwaddr));
    cache_entry* found_ce = NULL;

    unsigned char inv_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    clilen = sizeof(struct sockaddr_un);

    bzero(arp_hdr, sizeof(arp_header));

    print_eth0_info();

    raw_sockfd = Socket(PF_PACKET, SOCK_RAW, htons(IPPROTO_ID));

    stream_sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    unlink(SERVER_PATH);
    bzero(&servaddr, sizeof(struct sockaddr_un));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, SERVER_PATH);

    Bind(stream_sockfd, (SA*) &servaddr, sizeof(struct sockaddr_un));

    Listen(stream_sockfd, LISTENQ);

    arp_cache->ar_next = NULL;

    while (1)
    {
        FD_ZERO(&rset);
        FD_SET (raw_sockfd, &rset);
        FD_SET (stream_sockfd, &rset);

        maxfd = max(raw_sockfd, stream_sockfd);

        if (stream_connfd != -1)
        {
            FD_SET (stream_connfd, &rset);
        }

        maxfd = max(maxfd, stream_connfd);

        err = select (maxfd + 1, &rset, NULL, NULL, NULL);

        if (err < 0 && errno == EINTR)
        {
            trace;
            continue;
        }
        else if (err < 0)
        {
            perror("Select error.");
            exit(1);
        }

        if (FD_ISSET (raw_sockfd, &rset))
        {
            //
            // Data in RAW socket.
            //

            recvfrom (raw_sockfd, buffer, ETH_FRAME_LEN, 0, addr, sizeof(*addr));

            memcpy(arp_hdr, buffer + 14, sizeof(arp_header));

            print_arp_packet(arp_hdr);

            if (ntohs(arp_hdr->ah_id) != ARP_ID)
            {
                printf("ID of the received message != ARP_ID. Ignoring the message.\n");

                continue;
            }
            
            if (ntohs(arp_hdr->ah_op) == ARP_OP_ARP_REQ)
            {
                //
                // ARP req received.
                //

                printf("ARP Request broadcast received.\n");

                //
                // Copy sender's ethernet addr.
                //

                memcpy(mac_addr_buf, buffer + 6, 6);

                printf("Sender's ethernet addr: ");

                print_mac_addr(mac_addr_buf);

                //
                // Retrieve destination IP address.
                //

                Inet_ntop(AF_INET, &arp_hdr->ah_target_ip_addr.s_addr,
                        dest_ip_addr_buf, 16);

                //
                // Retrieve sender's ip address.
                //

                Inet_ntop(AF_INET, &arp_hdr->ah_sender_ip_addr.s_addr,
                        sender_ip_addr_buf, 16);

                check_and_update_arp_cache(sender_ip_addr_buf, mac_addr_buf,
                        arp_cache);

                //
                // Check if my ethernet address is being queried upon.
                //

                if (strcmp(get_my_ip(), dest_ip_addr_buf) == 0)
                {
                    //
                    // My IP = Queried IP. Respond with AREQ Reply.
                    //

                    printf("Sending reply.\n");

                    arp_hdr = prep_arp_rep_hdr(&arp_hdr->ah_target_ip_addr, mac_addr_buf);

                    print_arp_packet(arp_hdr);

                    send_unicast(raw_sockfd, get_my_hw_addr(), mac_addr_buf, 2, 
                            arp_hdr, sizeof(arp_header), IPPROTO_ID);
                }
                else
                {
                    printf("No need to send a reply since I was not the intended recipient.\n");
                } 
            }
            else
            {
                Inet_ntop(AF_INET, &arp_hdr->ah_sender_ip_addr.s_addr, ip_addr_buf, 16);

                printf("ARP reply received for %s.\n", ip_addr_buf);
                    
                print_arp_packet(arp_hdr);

                set_hwaddr(hw_addr, arp_hdr->ah_sender_eth_addr);

                found_ce = find_ip_addr_in_cache(ip_addr_buf, arp_cache);
                found_ce->ce_incomplete = 0;
                memcpy(found_ce->ce_hw_addr, arp_hdr->ah_sender_eth_addr, 6);

                print_arp_cache(arp_cache);

                printf("Responding to areq. Writing data on stream socket.\n");

                Write(found_ce->ce_sockfd, hw_addr, sizeof(struct hwaddr));

                //
                // Delete sockfd from cache.
                // 

                printf("Invalidated sockfd entry from cache.\n");

                found_ce->ce_sockfd = -1;

                print_arp_cache(arp_cache);

                Close(stream_connfd);

                stream_connfd = -1;
            }
        }
        else if (FD_ISSET(stream_sockfd, &rset))
        {
            //
            // Data in STREAM socket. ARP request received.
            //

            stream_connfd = Accept(stream_sockfd, (SA*) &cliaddr, &clilen);

            Read(stream_connfd, &recvd_ip, sizeof(recvd_ip));

            Inet_ntop(AF_INET, &recvd_ip.sin_addr.s_addr, ip_addr_buf, 16);

            printf("Stream socket received ARP request for %s.\n", ip_addr_buf);

            found_ce = find_ip_addr_in_cache(ip_addr_buf, arp_cache);

            if (found_ce == NULL)
            {
                printf("No entry in cache for %s. Creating an incomplete entry.\n", ip_addr_buf);

                append_cache(create_cache_entry(ip_addr_buf, inv_mac, stream_connfd), arp_cache);

                arp_hdr = prep_arp_req_hdr(&recvd_ip.sin_addr);

                print_arp_cache(arp_cache);

                printf("Sending ARP REQ for IP %s.\n", ip_addr_buf);

                print_arp_packet(arp_hdr);

                flood_interface(raw_sockfd, 2, get_my_hw_addr(), arp_hdr,
                        sizeof(arp_header));
            }
            else
            {
                printf("Cache has entry for %s. Sending the reply\n",
                        ip_addr_buf);

                found_ce->ce_sockfd = stream_connfd;
                set_hwaddr(hw_addr, found_ce->ce_hw_addr);

                print_arp_cache(arp_cache);

                Write(stream_connfd, hw_addr, sizeof(struct hwaddr));

                Close(stream_connfd);

                stream_connfd = -1;
            }
        }
        else if (stream_connfd > -1 && FD_ISSET (stream_connfd, &rset))
        {
            //
            // Time out.
            //

            printf("Activity in stream_connfd.\n");

            int read_bytes = Read(stream_connfd, &buffer, 1024);

            if (read_bytes == 0)
            {
                printf("Client has closed the connection. Detected timeout.\n");
                delete_from_cache(stream_connfd, arp_cache);
                Close(stream_connfd);
                stream_connfd = -1; 

                print_arp_cache(arp_cache);
            }
            else
            {
                printf("Error!\n");
                exit(1);
            }
        }
    }

    return 0;
}

