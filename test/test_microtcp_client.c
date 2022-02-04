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
 * You can use this file to write a test microTCP client.
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
    uint16_t server_port = 4444;
    const char *serverip = "";
    struct sockaddr_in sin;

    if ((sock->sd = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        printf ("Failed to open microTCP socket");
        free (buffer);
        fclose (fp);
        return -EXIT_FAILURE;
    }

    struct sockaddr_in sin;
    memset (&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;

    /*Port that server listens at */
    sin.sin_port = htons (server_port);

    /* The server's IP*/
    sin.sin_addr.s_addr = inet_addr (serverip);

    // microtcp_connect returns the socket so we have to check for error based on the socket's state
    microtcp_connect(sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));

    if(sock->state == INVALID){
        printf ("failed TCP connect");
        exit (EXIT_FAILURE);
    }
}
