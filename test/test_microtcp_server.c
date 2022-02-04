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

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#include "../utils/crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "../lib/microtcp.h"

int
main(int argc, char **argv)
{
    microtcp_sock_t sock;
    socklen_t client_addr_len;
    struct sockaddr_in sin;
  struct sockaddr client_addr;

    sock = microtcp_socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock.sd == -1) {
        printf("Error opening microTCP socket");
        return -EXIT_FAILURE;
    }

    memset (&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (4444);
    /* Bind to all available network interfaces */
    sin.sin_addr.s_addr = INADDR_ANY;

    if (microtcp_bind (&sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) == -1) {
         printf("Error binding microTCP socket");
        return -EXIT_FAILURE;
    }

    client_addr_len = sizeof(struct sockaddr);
    microtcp_accept (&sock, &client_addr, client_addr_len);
    if (sock.state == INVALID) {
        printf("Error in TCP accept");
    return -EXIT_FAILURE;
  }

  printf("cnnected to : %s", client_addr.sa_data);

}
