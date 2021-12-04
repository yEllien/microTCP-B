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
  
  int timeout_value = MICROTCP_ACK_TIMEOUT_US;
  if (setsockopt(s.sd, SOL_SOCKET, SO_RCVTIMEO, &timeout_value, sizeof(int)) == -1)
  {
    perror("setting receive timeout interval");
    s.state = INVALID;
    return s;
  }

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

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  microtcp_header_t syn, *synack, ack;
  struct sockaddr src_addr, src_addr_length;
  ssize_t bytes_sent;

  srand(time(NULL));
  socket->seq_number = rand();  // create random sequence number

  /*create the header for the 1st step of the 3-way handshake (SYN segment)*/
  syn.seq_number = socket->seq_number;
  syn.control = 0;
  syn.control = set_bit(syn.control, 14);        // set SYN bit to 1
  syn.window = 0;                                //no window yet
  syn.data_len = 0;   
  syn.future_use0 = 0;
  syn.future_use1 = 0;
  syn.future_use2 = 0;
  syn.checksum = 0;
  syn.checksum = crc32(&synack, sizeof(synack)); //add checksum

  //send SYN segment
  bytes_sent = sendto(socket->sd, &syn, sizeof(syn), address, address_len);
  if(bytes_sent != sizeof(syn)){
    socket->state = INVALID;
    perror("none or not all bytes of syn were sent\n");
    //TODO: add packets/bytes lost??
    return socket->sd;
  } 
  socket->seq_number += 1;
  socket->packets_send += 1;
  socket->bytes_send += bytes_sent;

  //wait to receive the SYNACK from the specific address

  do{
    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
    synack = socket->recvbuf;
  }while(*address != src_addr);
  
  // received synack from server

 // TODO: perform checksum check on synack



  // check that SYN and ACK bits are set to 1
  // check if ACK_received = SYN_sent + 1
  if( (get_bit(synack->control, 12) != 0) && (get_bit(synack->control, 14) != 0) && (synack->ack_number == socket->seq_number) ){
    socket->address = address;
    socket->address_length = address_len;
    socket->state = ESTABLISHED;
  }else{
    socket->state = INVALID;
    return socket->sd;
  }

  //make header of last ack
  ack.seq_number = socket->seq_number;
  ack.seq_number = socket->ack_number;
  ack.control = 0;
  ack.control = set_bit(syn.control, 12); // set ACK bit to 1
  ack.window = MICROTCP_WIN_SIZE; //now send the window size
  ack.data_len = 0;               //no data yet
  ack.future_use0 = 0;
  ack.future_use1 = 0;
  ack.future_use2 = 0;
  ack.checksum = crc32(&synack, sizeof(synack)); //add checksum

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
  s.init_win_size = MICROTCP_WIN_SIZE;
  s.curr_win_size = MICROTCP_WIN_SIZE;
  
  microtcp_header_t *syn, synack, *ack;
  struct sockaddr src_addr;
  struct socklen_t src_addr_length;
  ssize_t bytes_sent, rcv; 

  //receive syn segment
  do
  {
    if (!receivefrom(socket->sd, &(socket->recvbuf), MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length));
      syn = socket->recvbuf;
  } while (get_bit(syn->control, 14) == 0);
  
  //received syn segment
  //TODO: perform checksum 

  srand(time(NULL));
  socket->seq_number = rand(); //create random sequence number
  socket->init_win_size = syn->window;
  socket->curr_win_size = syn->window;
  socket->ack_number = syn->ack_number; //last byte acked
  socket->address = src_addr;
  socket->address_length = src_addr_length;

  //socket->ack_number = syn->seq_number+1;

  //create header of synack
  synack.seq_number = socket->seq_number;
  synack.ack_number = syn->seq_number + 1;
  synack.control = 0;
  synack.control = set_bit(synack.control, 12);
  synack.control = set_bit(synack.control, 14);
  synack.window = MICROTCP_WIN_SIZE;
  synack.data_len = 0;
  synack.future_use0 = 0;
  synack.future_use1 = 0;
  synack.future_use2 = 0;
  synack.checksum = 0;
  synack.checksum = crc32(&synack, sizeof(synack));

  bytes_sent = sendto(socket->sd, &synack, sizeof(synack), &socket->address, &socket->address_length);
  if (bytes_sent != sizeof(synack))
  {
    socket->state = INVALID;
    perror("none or not all bytes of synack were sent\n");
    return socket->sd;
  }
  socket->seq_number += 1;

  do
  {
    rcv = receivefrom(socket->sd, &(socket->recvbuf), MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length));
    ack = socket->recvbuf;
  } while (socket->address != src_addr);
  
  if (rcv)
  {
    socket->state = INVALID;
    perror("none or not all bytes of ACK were received\n");
    return socket->sd;
  }

  //checl ACK bit
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
//TODO: check return value of checksum and sendto
int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  microtcp_header_t client_fin, server_ack, *server_header, *client_ack, *client_finack, client_send_ack;
  ssize_t ret;
  uint32_t checksum_received, checksum_calculated;

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
    ret = sendto(socket->sd, &server_ack, sizeof(server_ack), 0, socket->address, socket->address_length);

    /* if sendto returned error value or not all header bytes were sent return invalid socket */
    if(ret < 0 || ret != sizeof(server_ack)){
        socket->state = INVALID;
        return socket->sd;
    }

    /* server waits to receive ACK from client */
    ret = recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->address, socket->address_length);
    
    /* if recvfrom returned error value or not all header bytes were received return invalid socket */
    if(ret < 0 || ret != sizeof(server_ack)){
        socket->state = INVALID;
        return socket->sd;
    }

    /* client ACK header received in server's recv buffer */
    server_header = socket->recvbuf;
    socket->seq_number += 1;
    checksum_received = ntohl(server_header->checksum);

    if(server_header->seq_number != socket->ack_number && server_header->ack_number != socket->seq_number){
      perror("error");
      return socket->sd;
    }

  }else{

    /* client creates FIN ACK segment */

    client_fin.control = 0;
    client_fin.control = set_bit(client_fin.control, 12); // set ACK bit to 1
    client_fin.control = set_bit(client_fin.control, 15); // set FIN bit to 1
    client_fin.ack_number = socket->ack_number;
    client_fin.seq_number = socket->seq_number;
    client_fin.checksum =  crc32(&client_fin, sizeof(client_fin));
    client_fin.window = MICROTCP_WIN_SIZE;
    client_fin.data_len = 0;
    client_fin.future_use0 = 0;
    client_fin.future_use1 = 0;
    client_fin.future_use2 = 0;

    /* send FIN ACK to server */
    ret = sendto(socket->sd, &client_fin, sizeof(client_fin), 0, socket->address, socket->address_length);
    
    /* if sendto returned error value or not all header bytes were sent return invalid socket */
    if(ret < 0 || ret != sizeof(server_ack)){
        socket->state = INVALID;
        return socket->sd;
    }

    socket->seq_number += 1;

    /* client waits to receive ACK from server */
    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->address, socket->address_length);
    client_ack = socket->recvbuf;
    
    if((client_ack->ack_number != client_fin.seq_number) || (get_bit(client_finack->control, 12) == 0)){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
    }

    socket->state = CLOSING_BY_HOST;

    /* client waits to receive FIN ACK from server */

    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->address, socket->address_len);
    client_finack = socket->recvbuf;

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

    socket->state = CLOSED;

    client_send_ack.control = 0;
    client_send_ack.control = set_bit(client_fin.control, 12); // set ACK bit to 1
    client_send_ack.ack_number = client_finack->seq_number+1;
    client_send_ack.seq_number = socket->seq_number;
    client_send_ack.checksum =  crc32(&client_fin, sizeof(client_fin));
    client_send_ack.window = MICROTCP_WIN_SIZE;
    client_send_ack.data_len = 0;
    client_send_ack.future_use0 = 0;
    client_send_ack.future_use1 = 0;
    client_send_ack.future_use2 = 0;

  }

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