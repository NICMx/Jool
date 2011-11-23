/*
	ClienteUDP.c
	Se conecta a un servidor y manda mensajes que va leyendo del teclado.
	Hasta que el mensaje sea 'q'.
	En la línea de comandos se tiene que especificar la dirección IP o el nombre
	del servidor.
	La comunicación es por medio de datagramas (UDP) y es por el puerto 5000
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PUERTO_ENVIO 60007
#define PUERTO 60000

int main(int argc, char *argv[]){
	int sockfd;
	struct sockaddr_in servidor, si_me;
	struct hostent *he;
	int numbytes;
	char buffer[80];
	int addr_len = sizeof(struct sockaddr);

	if (argc != 2) {
		fprintf(stderr,"uso: clienteUDP dirIPServidor\n");
		exit(1);
	}

	if ((he=gethostbyname(argv[1])) == NULL) {
		perror("gethostbyname");
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	servidor.sin_family = AF_INET;     
	servidor.sin_port = htons(PUERTO); 
	servidor.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(servidor.sin_zero), '\0', 8); 

//	do{
// Leer string del teclado
		printf("Teclea un mensaje: ");
		fgets(buffer, 80, stdin);
		buffer[strlen(buffer)-1] = '\0';
// Mandar string al servidor
		if ((numbytes=sendto(sockfd, buffer, strlen(buffer), 0,
				(struct sockaddr *)&servidor, sizeof(struct sockaddr))) == -1){
			perror("sendto");
			exit(1);
		}
		printf("Envia %d bytes a %s\n", numbytes, inet_ntoa(servidor.sin_addr));
// Recibir string modificado (en mayasculas) del servidor
		//if ((numbytes=recvfrom(sockfd, buffer, 80-1 , 0, (struct sockaddr *) &servidor, &addr_len)) == -1) {
		//	perror("Error en el recvfrom");
		//	exit(1);
		//}
		//buffer[numbytes] = '\0';
		//printf("Recibe de %s/%d: %s\n",inet_ntoa(servidor.sin_addr), ntohs(servidor.sin_port), buffer);

//	} while (strcmp(buffer,"Q") != 0);

	close(sockfd);
	return 0;
} 
