
/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
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
    uint8_t* reply_packet;
    reply_packet = (uint8_t*) malloc(PACKET_SIZE);
    assert(reply_packet);
    eth_hdr = (struct sr_ethernet_hdr*)packet;    
    printf("\n*** -> Received packet of length %d \n",len);

    if(eth_hdr->ether_type == 0x0608){ /*Arp packet received*/
    	arp_hdr = (struct sr_arphdr*)&eth_hdr->payload_ptr;
    	if(arp_hdr->ar_op == 0x100){	
           printf("\nARP Req Packet received\n");
	     form_arp_reply_packet(eth_hdr,arp_hdr,reply_packet,interface,sr);
	     sr_send_packet(sr,reply_packet, len, interface);
    	}
	
	else if(arp_hdr->ar_op == 0x200){
	     update_arp_table(sr, packet);
        }
        else{
	     printf("Invalid ARP packet");
	}
    }
    else if(eth_hdr->ether_type == 0x0008){
	printf("\nIPv4 Packet received\n");
	process_ip_packet(&eth_hdr->payload_ptr);
    }
}/* end sr_ForwardPacket */

void form_arp_reply_packet(const struct sr_ethernet_hdr* eth_hdr, const struct sr_arphdr* arp_hdr, uint8_t* buf, char* interface, struct sr_instance* sr)
{
  	int i=0;
        struct sr_ethernet_hdr* reply_packet;
	reply_packet = (struct sr_ethernet_hdr*)buf; 
 	struct sr_if* iface;     	
	struct sr_arphdr* rep_arp_hdr;
	rep_arp_hdr = (struct sr_arphdr*)&(reply_packet->payload_ptr);
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
    arp_hdr = (struct sr_arphdr*)(&(eth_hdr->payload_ptr));
    if(sr->ac == 0)
    {
    	sr->ac = (struct arp_cache*)malloc(sizeof(struct arp_cache));
	assert(sr->ac);
        sr->ac->next = 0;
       	strcpy(&(sr->ac->ip_addr),&(arp_hdr->ar_sip));
        strncpy(sr->ac->mac_addr,arp_hdr->ar_sha,ETHER_ADDR_LEN);
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
        	printf("doing arp timer update\n");		
		if((*ptr_to_arp_ptr)->time_sec > 15){
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
   
void  process_ip_packet(struct ip* ip_hdr)
{
	unsigned int hdr_len;
	hdr_len = ip_hdr->ip_hl;
	if (find_checksum(ip_hdr, hdr_len) != 0){
		printf("Checksum error in IP packet\n");
		return;
	}
}/*process_ip_packet*/

uint16_t find_checksum(uint16_t* ip_hdr, int hdr_len)
{
	int i=0;
	hdr_len = hdr_len*2; /*No of 16 bit words*/
	uint32_t sum = 0;
	uint16_t s,c, checksum;
	uint16_t dummy = 0;
        for(i=0; i<hdr_len;i++){
 	        dummy = ((ip_hdr[i] & 0xff) << 8) | ((ip_hdr[i] >> 8) & 0xff);	
		sum = sum + dummy;
	}

	c = (sum & 0xffff0000)>>16;	
	s = sum;
        checksum = ~(s+c);
	return checksum;
}/*find_checksum*/


	



/*--------------------------------------------------------------------- 
 * Method:
 *
**/
