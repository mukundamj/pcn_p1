/***************************************************************** 
 * file: sr_router.c
 * date: Mon Feb 18 12:50:42 PST 2002
 * contact: casado@stanford.edu
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

/**********************Code added by Mukunda************************/
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
/**********************************************************************/

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    sr->ac = 0;
    struct queue* ipq;
    ipq = (struct queue*)create_queue(IP_QUEUE_SIZE);
    assert(ipq);
    sr->iq = ipq;    

    struct queue* arp_req_queue;
    arp_req_queue = (struct queue*)create_queue(ARP_QUEUE_SIZE);
    assert(arp_req_queue);
    sr->arp_req_queue = arp_req_queue;
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
/**********************Code added by Mukunda-begin************************/
    int i;
    struct sr_ethernet_hdr* eth_hdr;
    struct sr_arphdr* arp_hdr;
    struct arp_cache* ac;
    struct ip* ip_hdr;
    struct sr_icmp_hdr* icmp_hdr;
    uint8_t* reply_packet;
    struct sr_ethernet_hdr* icmp_reply_packet;
        eth_hdr = (struct sr_ethernet_hdr*)packet;    
    printf("\n*** -> Received packet of length %d from mac addr %x\n",eth_hdr->ether_shost[0]);

    if(eth_hdr->ether_type == 0x0608){ 

    	arp_hdr = (struct sr_arphdr*)&eth_hdr->payload;

    	if(arp_hdr->ar_op == 0x100){	
       	     printf("\nARP Req Packet received\n");
	     reply_packet = (uint8_t*) malloc(len*sizeof(uint8_t));
    	     assert(reply_packet);
	     form_arp_reply_packet(eth_hdr,arp_hdr,reply_packet,interface,sr);
	     sr_send_packet(sr,reply_packet, len, interface);
	     free(reply_packet);
    	}
	
	else if(arp_hdr->ar_op == 0x200){
	     printf("ARP reply packet received\n");
	     update_arp_table(sr, packet);
        }

        else{
	     printf("Invalid ARP packet");
	}
    }

    else if(eth_hdr->ether_type == 0x0008){
	printf("\nIPv4 Packet received\n");
	ip_hdr = (struct ip*)&eth_hdr->payload;
		if(ip_hdr->ip_dst.s_addr == (sr_get_interface(sr,interface))->ip){
			if(ip_hdr->ip_p == 1){
				printf("ICMP echo req message received for router\n");
				icmp_hdr = (struct sr_icmp_hdr*)&ip_hdr->payload;
				printf("ip packet length is %x\n", (ntohs(ip_hdr->ip_len)-20));
				if(find_icmp_checksum(icmp_hdr,(ntohs(ip_hdr->ip_len)-20))!=0){
					 printf("Checksum error in icmp header");
					 return;
				}
				icmp_reply_packet = (struct sr_ethernet_hdr*)malloc((14+(ntohs(ip_hdr->ip_len)))*sizeof(uint8_t));
				memcpy(icmp_reply_packet,packet,(14+(ntohs(ip_hdr->ip_len))));
				
				memcpy(icmp_reply_packet->ether_shost,eth_hdr->ether_dhost,6);
				memcpy(icmp_reply_packet->ether_dhost,eth_hdr->ether_shost,6);
				icmp_reply_packet->ether_type = eth_hdr->ether_type;
				ip_hdr = (struct ip*)&icmp_reply_packet->payload;
				printf("ip packet length is in reply packet is%x\n", (ntohs(ip_hdr->ip_len)-20));
				ip_hdr->ip_dst.s_addr = ip_hdr->ip_src.s_addr;
				ip_hdr->ip_src.s_addr = sr_get_interface(sr,interface)->ip;
				icmp_hdr = (struct sr_icmp_hdr*)&ip_hdr->payload;
				icmp_hdr->type = 0;
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ntohs(find_icmp_checksum(icmp_hdr,(ntohs(ip_hdr->ip_len)-20)));		
	     			sr_send_packet(sr,icmp_reply_packet,(14+(ntohs(ip_hdr->ip_len))), interface);
				free(icmp_reply_packet);
				return;
                        }
			else{
				return;
			}				
		}
	enqueue(sr->iq,eth_hdr);
//	printf("ip packet is enqued\n");
	process_ip_packet(sr);
    }
    else{
	printf("unknown packet type received\n");
    }
}/* end sr_ForwardPacket */

void form_arp_reply_packet(const struct sr_ethernet_hdr* eth_hdr, const struct sr_arphdr* arp_hdr, uint8_t* buf, char* interface, struct sr_instance* sr)
{
  	int i=0;
        struct sr_ethernet_hdr* reply_packet;
	reply_packet = (struct sr_ethernet_hdr*)buf; 
 	struct sr_if* iface;     	
	struct sr_arphdr* rep_arp_hdr;
	rep_arp_hdr = (struct sr_arphdr*)&(reply_packet->payload);
        strncpy(reply_packet->ether_dhost,eth_hdr->ether_shost,ETHER_ADDR_LEN);
	reply_packet->ether_type = eth_hdr->ether_type;
	rep_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
	rep_arp_hdr->ar_pro = arp_hdr->ar_pro;
	rep_arp_hdr->ar_hln = arp_hdr->ar_hln;
	rep_arp_hdr->ar_pln = arp_hdr->ar_pln;
        rep_arp_hdr->ar_op = 0x200;//set the opcode as arp reply packet
        rep_arp_hdr->ar_sip = arp_hdr->ar_tip;
	strncpy(rep_arp_hdr->ar_tha,arp_hdr->ar_sha,ETHER_ADDR_LEN);
	rep_arp_hdr->ar_tip = arp_hdr->ar_sip;

	iface = sr_get_interface(sr,interface);
	assert(iface);
	strncpy(reply_packet->ether_shost,iface->addr,ETHER_ADDR_LEN);
	strncpy(rep_arp_hdr->ar_sha,iface->addr,ETHER_ADDR_LEN);
        printf("formed arp reply packet\n");	
}/*form_arp_reply_packet*/

void update_arp_table(struct sr_instance* sr, uint8_t* packet)
{
    /* -- REQUIRES -- */
    assert(packet);
    assert(sr);
    struct arp_cache* arp_walker = 0;
    struct sr_ethernet_hdr* eth_hdr;
    struct sr_arphdr* arp_hdr;
    eth_hdr = (struct sr_ethernet_hdr*)packet;
    arp_hdr = (struct sr_arphdr*)(&(eth_hdr->payload));
    printf("arp_sha is %x %x %x %x %x %x\n",arp_hdr->ar_sha[0],arp_hdr->ar_sha[1],arp_hdr->ar_sha[2],arp_hdr->ar_sha[3],arp_hdr->ar_sha[4],arp_hdr->ar_sha[5]);
    if(sr->ac == 0)
    {
    	sr->ac = (struct arp_cache*)malloc(sizeof(struct arp_cache));
	assert(sr->ac);
        sr->ac->next = 0;
       	strcpy(&(sr->ac->ip_addr),&(arp_hdr->ar_sip));
        memcpy(sr->ac->mac_addr,arp_hdr->ar_sha,ETHER_ADDR_LEN);
	sr->ac->time_sec = 0;
        return;
    }
    arp_walker = sr->ac;
    while(arp_walker->next)
    {arp_walker = arp_walker->next; }
    arp_walker->next = (struct arp_cache*)malloc(sizeof(struct arp_cache));
    assert(arp_walker->next);
    arp_walker = arp_walker->next;
    strcpy(&arp_walker->ip_addr,&arp_hdr->ar_sip);
    strncpy(arp_walker->mac_addr,arp_hdr->ar_sha,ETHER_ADDR_LEN);
    arp_walker->time_sec = 0;
    arp_walker->next = 0;
}/*update_arp_table*/

void update_arp_cache_timer(struct sr_instance* sr)
{
	struct arp_cache** ptr_to_arp_ptr = &(sr->ac);
	check_arp_node(ptr_to_arp_ptr);
}/* update_arp_cache_timer*/


void check_arp_node(struct arp_cache** ptr_to_arp_ptr)
{
	if ( *ptr_to_arp_ptr == NULL){
  //    	printf("Returning bcoz arp cache is empty\n");		
	 	return;
	}
	else{
//        	printf("doing arp timer update\n");		
		if((*ptr_to_arp_ptr)->time_sec > 14){
			*ptr_to_arp_ptr = (*ptr_to_arp_ptr)->next;
			check_arp_node(ptr_to_arp_ptr);
		}
		else{
			(*ptr_to_arp_ptr)->time_sec++;
			ptr_to_arp_ptr = &((*ptr_to_arp_ptr)->next);
			check_arp_node(ptr_to_arp_ptr);
		}
	}
}/*check_arp_node*/
  
void check_arp_req_queue(struct sr_instance* sr)
{
	struct queue* arp_req_queue;
	struct sr_ethernet_hdr* arp_req_packet;
	struct sr_arphdr* arp_hdr; 
	struct arp_cache* ac_walker;
	int arp_found_flag = 0;
	int  arp_pkt_len = 42;
	ac_walker = sr->ac;
	arp_req_queue = sr->arp_req_queue;
	assert(arp_req_queue);
	if(arp_req_queue->size == 0){
//		printf("arp req queue is empty \n");
		return;
	}
	arp_req_packet = (struct sr_ethernet_hdr*)get_q_front(sr->arp_req_queue);
  	arp_hdr = &arp_req_packet->payload;
	if(arp_hdr->arp_req_count > 4 ){ /**here 4 is used bcoz the arp req packet is already sent once after forming arp_req_pkt*/
		printf("Destination host %d is not reachable\n", arp_hdr->ar_tip);
		check_arp_req_queue(sr);
	}
	if(ac_walker == 0){
//		printf("arp cache is empty\n");
	}
 	
        while (ac_walker){
		if(ac_walker->ip_addr ^ arp_hdr->ar_tip == 0){
			printf("The arp req packet for dst ip %d has got a reply\n",arp_hdr->ar_tip); 
			arp_found_flag = 1;
			break;
		}	
		ac_walker = ac_walker->next;
	}
	if( arp_found_flag == 0){
	     	sr_send_packet(sr,arp_req_packet, arp_pkt_len, arp_hdr->dst_iface);
		arp_hdr->arp_req_count++;
		enqueue(arp_req_queue,arp_req_packet);
	}
	check_arp_req_queue(sr);	
}
void  process_ip_packet(struct sr_instance* sr)
{
	struct ip* ip_hdr;
	struct ip* fwd_ip_hdr;
	struct sr_ethernet_hdr* eth_hdr; 
	struct sr_rt* rt_entry;
	struct sr_ethernet_hdr* ip_fwd_pkt; 
	uint16_t checksum;
	uint8_t* arp_req_pkt;
        unsigned char* dst_mac;
	long dst_ip;
	unsigned short arp_pkt_len = 42;
	uint8_t* dummy;
        
	while( sr->iq->size){	
	eth_hdr = (struct sr_ethernet_hdr*)get_q_front(sr->iq);
	assert(eth_hdr);
	ip_hdr = &eth_hdr->payload;

		if (find_checksum(ip_hdr) != 0){
		//	printf("Checksum error in IP packet\n");
			process_ip_packet(sr);
		}
		else{
						
			/*************get interface and next hop***********/
		         
		//	printf("packet is free of checksum error\n");
			rt_entry = get_rt_entry_from_rtable(ip_hdr->ip_dst.s_addr,sr->routing_table);
//			printf("rt entry dst ip is %x\n",rt_entry->gw.s_addr);
		//	printf("the dest iface is %C%C%C%C\n",rt_entry->interface[0],rt_entry->interface[1],rt_entry->interface[2],rt_entry->interface[3]);
						
			if((rt_entry->gw.s_addr) == 0x00000000){
				dst_ip = ip_hdr->ip_dst.s_addr;
			}
			else{
				dst_ip = rt_entry->gw.s_addr;
			}

			print_arp_cache(sr);
//			printf("the dest ip is %x\n",dst_ip);
			dst_mac = get_dst_mac_from_arp_cache(dst_ip,sr->ac); 
			/****************If mac addr is not in arp cache send arp request***********/
			if(dst_mac == NULL){
//				printf("arp cache doesn't contain the dst IP\n");
				arp_req_pkt = form_arp_req_pkt(dst_ip,rt_entry->interface,sr);
	     			sr_send_packet(sr,arp_req_pkt, arp_pkt_len, rt_entry->interface);
				printf("arp request message sent\n");
				enqueue(sr->arp_req_queue,arp_req_pkt);
			/*	if(enqueue(sr->iq,eth_hdr)==1){
					printf("ip q is full");
					return;
				}*/
			}
			/***********If mac addr is in arp cache, do ip forwarding***********/
			else{
			
			//	printf("the dst mac is %x %x %x %x %x %x\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
				ip_fwd_pkt = (struct sr_ethernet_hdr*)malloc((14+ip_hdr->ip_len)*sizeof(uint8_t));
				assert(ip_fwd_pkt);
				memcpy(ip_fwd_pkt, eth_hdr, (14+ntohs(ip_hdr->ip_len)));
				memcpy(ip_fwd_pkt->ether_dhost,dst_mac,6);
				
				memcpy(ip_fwd_pkt->ether_shost,sr_get_interface(sr,rt_entry->interface)->addr,6);
				dummy = (uint8_t*)ip_fwd_pkt;
				//for(int i=0;i<98;i++) printf("%x\t",dummy[i]);
				fwd_ip_hdr = (struct ip*)&(ip_fwd_pkt->payload);
			//	printf("total length of ip packet to be forwarded is %x, ttl is %x\n",ntohs(fwd_ip_hdr->ip_len),fwd_ip_hdr->ip_ttl);
				/*decrement ttl and update checksum*/
				fwd_ip_hdr->ip_ttl--;
				fwd_ip_hdr->ip_sum = 0x0000;
				checksum = find_checksum(fwd_ip_hdr);
				fwd_ip_hdr->ip_sum = ntohs(checksum);
				sr_send_packet(sr,ip_fwd_pkt,(14+ntohs(fwd_ip_hdr->ip_len)), rt_entry->interface);
//				printf("ip packet forwarded\n");
			        free(ip_fwd_pkt);
			}	
		}
	
	}	
}/*process_ip_packet*/

uint16_t find_checksum(uint16_t* ip_hdr)
{
	int i=0;
	struct ip* ih;
	ih = (struct ip*)ip_hdr;
//	printf("header length is %d\n", ih->ip_hl);
	int hdr_len;
	hdr_len = ih->ip_hl*2; /*No of 16 bit words*/
	uint32_t sum = 0;
	uint16_t s=0,c=0, checksum=0;
	uint16_t dummy = 0;
//	printf("the header values used for checksum\n");
        for(i=0; i<hdr_len;i++){
//		printf("header is %x\n", ip_hdr[i]);
 	        dummy = ((ip_hdr[i] & 0xff) << 8) | ((ip_hdr[i] >> 8) & 0xff);	
		sum = sum + dummy;
//		printf("partial sum is %x\n", sum);
	}
//        printf("sum is %x\n",sum);
	c = (sum & 0xffff0000)>>16;	
	s = sum;
        checksum = ~(s+c);
//	printf("checksum is %d\n",checksum);
	return checksum;

}/*find_checksum*/



struct queue* create_queue(int no_of_elements)
{
	struct queue* q;
	q = (struct queue* ) malloc(sizeof(struct queue));
	q->elements = (uint32_t *)malloc(no_of_elements*sizeof(uint32_t*));
	printf("q created, the element start addr is %x\n",q->elements);
	q->size = 0;
	q->capacity = no_of_elements;
	q->front = 0;
	q->rear = -1;
	return q;
}

uint8_t* get_q_front(struct queue* q)
/*This function will return the front of the queue and also dequeue 
that element*/
{
	if(q->size == 0){
		printf("Queue is empty\n");
		return NULL;
	}
	int front_of_q;
	front_of_q = q->front;
	q->size--;
	q->front++;
	if(q->front == q->capacity){
		q->front = 0;
	}
//	printf("q item dequed\n");
	return q->elements[front_of_q];	
}

int enqueue(struct queue* q,uint8_t* element)
{
	if(q->size == q->capacity){
//		printf("queue is full\n");
		return 1;
	}
	else{
		q->size++;
		q->rear = q->rear +1 ;
		if(q->rear == q->capacity){
			q->rear = 0;
		}
		(q->elements)[q->rear] = element;		
		return 0;
	}
} 

struct sr_rt*  get_rt_entry_from_rtable(long dst_ip,struct sr_rt* rt)
{
	struct sr_rt* rt_walker = rt;
	char* dst_iface;
	long ip_and_mask=0xffffffff;
        while(rt_walker){
                if(rt_walker->mask.s_addr !=0){
			ip_and_mask = dst_ip & rt_walker->mask.s_addr;
			if((ip_and_mask ^  rt_walker->dest.s_addr)==0){ 
				dst_iface = rt_walker->interface; 
		        	return rt_walker; 
			}
		}	
		rt_walker = rt_walker->next;	
	}
	return rt;
}

char* get_dst_mac_from_arp_cache(long dst_ip,struct arp_cache* ac)
{
	struct arp_cache* ac_walker = ac;
	unsigned char* dst_mac;
        while(ac_walker){
//		printf("checking arp cache, xor value is %x\n", ((dst_ip)^(ac_walker->ip_addr)));
		if(((dst_ip)^(ac_walker->ip_addr))==0){ 
			dst_mac = ac_walker->mac_addr;
			return dst_mac;
		}	
		ac_walker = ac_walker->next;	
	}
	return NULL;
}

uint8_t* form_arp_req_pkt(uint32_t ip_dst,char dst_iface[sr_IFACE_NAMELEN], struct sr_instance* sr)
{
	struct sr_ethernet_hdr* eth_hdr;
	struct sr_arphdr* arp_hdr;
	struct sr_if* srif; 
	eth_hdr = (struct sr_ethernet_hdr*)malloc(100*sizeof(uint8_t));
	assert(eth_hdr);
	srif = sr_get_interface(sr,dst_iface);
	strncpy(eth_hdr->ether_shost,srif->addr,6);
	eth_hdr->ether_dhost[0]=0xff;
	eth_hdr->ether_dhost[1]=0xff;
	eth_hdr->ether_dhost[2]=0xff;
	eth_hdr->ether_dhost[3]=0xff;
	eth_hdr->ether_dhost[4]=0xff;
	eth_hdr->ether_dhost[5]=0xff;
	eth_hdr->ether_type = 0x0608;
	arp_hdr = &(eth_hdr->payload);
        arp_hdr->ar_hrd = 0x0100;
	arp_hdr->ar_pro = 0x0008;
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
        arp_hdr->ar_op = 0x0100;//set the opcode as arp req packet
	strncpy(arp_hdr->ar_sha,srif->addr,6);
        arp_hdr->ar_tha[0] = 0;
        arp_hdr->ar_tha[1] = 0;
        arp_hdr->ar_tha[2] = 0;
        arp_hdr->ar_tha[3] = 0;
        arp_hdr->ar_tha[4] = 0;
        arp_hdr->ar_tha[5] = 0;
        arp_hdr->ar_sip = (srif->ip);
	arp_hdr->arp_req_count = 0  ; /*this info is not for sending, its used to count no of arp req sent, max is 5 */
	arp_hdr->ar_tip = (ip_dst); 
	strcpy(arp_hdr->dst_iface,dst_iface); /* this info is not for sending, it is used as an argument in send packet function*/
	return (uint8_t*)eth_hdr;
}

void print_arp_cache(struct sr_instance* sr)
{
   struct arp_cache* ac_walker;
   ac_walker = sr->ac;
   printf("ip_addr     mac_addr         time_sec\n");
   while(ac_walker){
	printf("%x     %x %x %x %x %x %x   %d\n",ac_walker->ip_addr,ac_walker->mac_addr[0],ac_walker->mac_addr[1],ac_walker->mac_addr[2],ac_walker->mac_addr[3],ac_walker->mac_addr[4],ac_walker->mac_addr[5],ac_walker->time_sec);
	ac_walker = ac_walker->next;
   }
}

uint16_t find_icmp_checksum(uint16_t* icmp_hdr,int len)
{
	int i=0;
	uint32_t sum = 0;
	uint16_t s=0,c=0, checksum=0;
	uint16_t dummy = 0;
//	printf("the icmp header and datagram length is %d\n",len); 
//	printf("the header values used for checksum\n");
        for(i=0; i<(len/2);i++){
//		printf("header is %x\n", icmp_hdr[i]);
 	        dummy = ((icmp_hdr[i] & 0xff) << 8) | ((icmp_hdr[i] >> 8) & 0xff);	
		sum = sum + dummy;
//		printf("partial sum is %x\n", sum);
	}
  //    printf("sum is %x\n",sum);
	c = (sum & 0xffff0000)>>16;	
	s = sum;
        checksum = ~(s+c);
//	printf("checksum is %x\n",checksum);
	return checksum;
}

/*--------------------------------------------------------------------- 
 * Method:
 *
**/
