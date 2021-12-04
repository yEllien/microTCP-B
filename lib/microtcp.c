/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//TODO: add timeout option for receive

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  microtcp_socket_t s;
  if ((s.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    perror("opening socket");
    return NULL;
  }
  s.packets_send = 0;
  s.packets_received = 0;
  s.packets_lost = 0;
  s.bytes_send = 0;
  s.bytes_received = 0;
  s.bytes_lost = 0;
  
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

  s.state = UNKNOWN;
  return s;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{ 
  int rv;
  if((rv = bind(socket->sd, address, address_len)) == -1){
    perror("TCP bind");
  }
  
  return rv;
}

static uint16_t set_bit (uint16_t data, uint16_t pos)
{
  return (data|(1 << pos));
}

//returns 0 if bit not set, else !=0
static uint16_t get_bit (uint16_t data, uint16_t pos)
{
  return ((data >> pos) & 1);
}

static microtcp_header_t * make_header (uint32_t seq_number,uint32_t ack_number, 
                                 uint16_t window, uint32_t data_len,
                                 uint8_t ACK, uint8_t RST, uint8_t SYN, uint8_t FIN)
{
  microtcp_header_t *header = malloc (sizeof(microtcp_header_t));

  header->seq_number = htonl(seq_number);
  header->ack_number = htonl(ack_number);
  header->window = htnos(window);
  header->data_len = htonl(data_len);
  header->future_use0 = 0;
  header->future_use1 = 0;
  header->future_use2 = 0;
  header->checksum = 0;
  uint16_t tmp_control = 0;
  if(ACK) set_bit(tmp_control, ACK_F);
  if(RST) set_bit(tmp_control, RST_F);
  if(SYN) set_bit(tmp_control, SYN_F);
  if(FIN) set_bit(tmp_control, FIN_F);
  header->control = htons(tmp_control);

  return header;
}


/* Calculates checksum of header recv_header
   Returns 1 if checksum calculated is equal to 
   checksum field of header else returns 0 */

static int is_checksum_valid(const uint8_t *recv_buf){

  microtcp_header_t *tmp_header, *recv_header = recv_buf;
  uint32_t received_checksum, calculated_checksum;
  int i = 0, size = 0;

  size = sizeof(recv_header); //TODO: check size
  tmp_header = malloc(size);

  for(i=0 ; i<size ; i++){ 
    tmp_header[i] = recv_header[i];
  }

  /* check sum in received header */
  received_checksum = ntohl(recv_header->checksum);

  /* calculate checksum of header for comparison */
  calculated_checksum = ntohl(crc32(recv_buf, sizeof(recv_buf)));

  return (received_checksum == calculated_checksum);
}


int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  microtcp_header_t *syn, *synack, *ack;
  struct sockaddr src_addr, src_addr_length;
  ssize_t bytes_sent, ret;
  char tmp_buf[MICROTCP_RECVBUF_LEN];

  srand(time(NULL));
  socket->seq_number = rand();  // create random sequence number

  //create the header for the 1st step of the 3-way handshake (SYN segment)
  syn = make_header(socket->seq_number, 0, 0, 0, 0, 0, 1, 0);
  syn->checksum = crc32(&synack, sizeof(synack));                             //add checksum
  bytes_sent = sendto(socket->sd, syn, sizeof((*syn)), address, address_len); //send segment
  
  if(bytes_sent != sizeof(syn))
  {
    perror("none or not all bytes of syn were sent\n"); 
    socket->state = INVALID;
    return socket->sd;
  } 
  socket->seq_number += 1;
  socket->packets_send += 1;
  socket->bytes_send += bytes_sent;

  //wait to receive the SYNACK from the specific address
  do{
    ret = recvfrom(socket->sd, tmp_buf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
  }while(*address != src_addr);
  synack = tmp_buf;

  // received segment
  if(ret<0 || ret != MICROTCP_RECVBUF_LEN){
    socket->state = UNKNOWN; //TODO: ckeck state
    return socket->sd;
  }

  // check if checksum in received header is valid
  if(!is_checksum_valid(socket->recvbuf)){
    socket->state = UNKNOWN; //TODO: ckeck state
    return socket->sd;
  }

  // check that SYN and ACK bits are set to 1
  // check if ACK_received = SYN_sent + 1
  if( (get_bit(synack->control, 12) == 0) || (get_bit(synack->control, 14) == 0) || (synack->ack_number != socket->seq_number) )
  {
    socket->state = INVALID;
    return socket->sd;
  }
  //received valid SYNACK
  socket->address = address;
  socket->address_len = address_len;
  socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(char));
  socket->state = ESTABLISHED;    //TODO: maybe put this at the end of function
  socket->ack_number = synack->seq_number + 1;

  // O client λαμβάνει το SYN+ACK πακέτο, αποθηκεύει το sequence number M του server και 
  // στέλνει ένα ACK με ACK number Μ+1 (από εκφώνηση)

  //make header of last ack
  ack = make_header(socket->seq_number, socket->ack_number, MICROTCP_WIN_SIZE, 0, 1, 0, 0, 0);
  ack->checksum = crc32(&synack, sizeof(synack)); //add checksum

  //send last ack
  bytes_sent = sendto(socket->sd, &ack, sizeof(ack), address, address_len);
  if(bytes_sent != sizeof(ack)){
    socket->state = INVALID;
    perror("none or not all ack bytes were sent");
    return socket->sd;
  } 
  socket->seq_number += 1; 

  return socket->sd;
}


int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(char));
  socket->buf_fill_level = 0;
  socket->init_win_size = MICROTCP_WIN_SIZE;
  socket->curr_win_size = MICROTCP_WIN_SIZE;
  
  microtcp_header_t *syn, *synack, *ack;
  struct sockaddr src_addr;
  struct socklen_t src_addr_length;
  ssize_t bytes_sent, rcv; 

  //receive SYN segment from any address
  do
  {
    if (!receivefrom(socket->sd, &(socket->recvbuf), MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length));
      syn = socket->recvbuf;
  } while (get_bit(syn->control, 14) == 0);
  
  //received SYN segment

  // checksum validation
  if(!is_valid_checksum(syn)){
    perror("checksum is invalid");
    socket->state = INVALID;
    return socket->sd;
  }

  //received valid SYN segment
  srand(time(NULL));
  socket->seq_number = rand(); //create random sequence number
  socket->ack_number = syn->ack_number+1;
  socket->init_win_size = syn->window;
  socket->curr_win_size = syn->window;
  socket->address = src_addr;
  socket->address_len = src_addr_length;

  //create header of SYNACK
  synack = make_header(socket->seq_number, socket->ack_number, MICROTCP_WIN_SIZE, 0, 1, 0, 1, 0);
  synack.checksum = htonl(crc32(&synack, sizeof(synack)));

  //send SYNACK
  bytes_sent = sendto(socket->sd, &synack, sizeof(synack), &socket->address, &socket->address_length);
  //check that SYNACK was successfully sent
  if (bytes_sent != sizeof(synack))
  {
    socket->state = INVALID;
    perror("none or not all bytes of synack were sent\n");
    return socket->sd;
  }
  socket->seq_number += 1;
  socket->bytes_send += bytes_sent;
  socket->packets_send += 1;

  do
  {
    rcv = receivefrom(socket->sd, &(socket->recvbuf), MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length));
    if (!rcv) 
      ack = socket->recvbuf;
  } while (socket->address != src_addr);
  
  //recvfrom failed
  if (rcv)
  {
    socket->state = INVALID;
    perror("none or not all bytes of ACK were received\n");
    return socket->sd;
  }

  //check ACK bit
  if(get_bit(ack->control, 12)==0)
  {
    socket->state = INVALID;
    perror("failed to accept connection\n");
    return socket->sd;
  }
  socket->state = ESTABLISHED;
  socket->ack_number = ack->ack_number;
  
  return socket->sd;
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  microtcp_header_t client_fin, server_ack, *server_header, *client_ack, *client_finack, client_send_ack;
  ssize_t ret;
  uint32_t checksum_received, checksum_calculated;

if(how == SHUT_RDWR){

  if(socket->state == CLOSING_BY_PEER){

    /* server creates ACK segment */

    server_ack.control = 0;
    server_ack.control = set_bit(server_ack.control, 12); // set ACK bit to 1
    server_ack.control = set_bit(server_ack.control, 15); // set FIN bit to 1
    server_ack.ack_number = htonl(socket->seq_number + 1);
    server_ack.seq_number = htonl(socket->seq_number);
    server_ack.checksum =  0;
    server_ack.window = MICROTCP_WIN_SIZE;
    server_ack.data_len = 0;
    server_ack.future_use0 = 0;
    server_ack.future_use1 = 0;
    server_ack.future_use2 = 0;
    server_ack.checksum = htonl(crc32(&server_ack, sizeof(server_ack)));

    /* server sends ACK to client */
    ret = sendto(socket->sd, &server_ack, sizeof(server_ack), 0, socket->address, socket->address_len);

    /* if sendto returned error value or not all header bytes were sent return invalid socket */
    if(ret < 0 || ret != sizeof(server_ack)){
        socket->state = INVALID;
        return socket->sd;
    }

    /* server waits to receive ACK from client */
    ret = recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->address, socket->address_len);
    
    /* if recvfrom returned error value or not all header bytes were received return invalid socket */
    if(ret < 0 || ret != sizeof(server_ack)){
        socket->state = INVALID;
        return socket->sd;
    }

    /* client ACK header received in server's recv buffer */
    server_header = socket->recvbuf;
  //  checksum_received = ntohl(server_header->checksum);
    
    /* check if checksum is valid */
    if(!is_checksum_valid(socket->recvbuf)){
      socket->state = INVALID;
      return socket->sd;
    }
   
    socket->seq_number += 1;

    /* check that seq number and ack number are valid */
    if(server_header->seq_number != socket->ack_number && server_header->ack_number != socket->seq_number){
      perror("error");
      return socket->sd;
    }

    socket->state = CLOSED;

  }else{

    /* client creates FIN ACK segment */

    client_fin.control = 0;
    client_fin.control = set_bit(client_fin.control, 12); // set ACK bit to 1
    client_fin.control = set_bit(client_fin.control, 15); // set FIN bit to 1
    client_fin.ack_number = socket->ack_number;
    client_fin.seq_number = socket->seq_number;
    client_fin.window = MICROTCP_WIN_SIZE;
    client_fin.data_len = 0;
    client_fin.future_use0 = 0;
    client_fin.future_use1 = 0;
    client_fin.future_use2 = 0;
    client_fin.checksum =  crc32(&client_fin, sizeof(client_fin));

    /* send FIN ACK to server */
    ret = sendto(socket->sd, &client_fin, sizeof(client_fin), 0, socket->address, socket->address_len);
    
    /* if sendto returned error value or not all header bytes were sent return invalid socket */
    if(ret < 0 || ret != sizeof(client_fin)){
        socket->state = INVALID;
        return socket->sd;
    }

    socket->seq_number += 1;

    /* client waits to receive ACK from server */
    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->address, socket->address_len);
    client_ack = socket->recvbuf;
    
    /* check if checksum is valid */
    if(!is_checksum_valid(socket->recvbuf)){
      socket->state = INVALID;
      return socket->sd;
    }

    /* check if ACK is valid and ACK bit is set to 1 */
    if((client_ack->ack_number != client_fin.seq_number) || (get_bit(client_finack->control, 12) == 0)){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
    }

    socket->state = CLOSING_BY_HOST;

    /* client waits to receive FIN ACK from server */

    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->address, socket->address_len);
    client_finack = socket->recvbuf;

    /* check if checksum is valid */
    if(!is_checksum_valid(socket->recvbuf)){
      socket->state = INVALID;
      return socket->sd;
    }

    /* check that FIN and ACK bits are set to 1 */
    if((get_bit(client_finack->control, 12) == 0) && (get_bit(client_finack->control, 15) == 0)){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
    }

    /* check if ack number and seq number */
    if(client_finack->ack_number != socket->seq_number){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
    }

    /* client creates ACK segment to send to server */

    client_send_ack.control = 0;
    client_send_ack.control = set_bit(client_fin.control, 12); // set ACK bit to 1
    client_send_ack.ack_number = client_finack->seq_number+1;
    client_send_ack.seq_number = socket->seq_number;
    client_send_ack.window = MICROTCP_WIN_SIZE;
    client_send_ack.data_len = 0;
    client_send_ack.future_use0 = 0;
    client_send_ack.future_use1 = 0;
    client_send_ack.future_use2 = 0;
    client_send_ack.checksum =  crc32(&client_fin, sizeof(client_fin));

    /* send FIN ACK to server */
    ret = sendto(socket->sd, &client_send_ack, sizeof(client_send_ack), 0, socket->address, socket->address_len);
    
    /* if sendto returned error value or not all header bytes were sent return invalid socket */
    if(ret < 0 || ret != sizeof(client_send_ack)){
        socket->state = INVALID;
        return socket->sd;
    }

    socket->state = CLOSED;

  }
}

return socket->sd;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Your code here */
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here */
}

//returns the current window
uint16_t get_unacked (microtcp_socket_t *sock)
{
  // unacked bytes = last byte sent - last byte acked
  return  sock->seq_number - sock->ack_number;
}

//returns the current window
uint16_t get_my_rwnd (microtcp_socket_t *sock)
{
  // unread bytes = last byte received - last byte read
  //return MICROTCP_WIN_SIZE - (?? - sock->bytes_received)
}
