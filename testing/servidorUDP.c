/*
	servidorUDP.c
	Servidor que escucha por paquetes en el puerto 5000.
	Imprime en la línea de comandos los datos recibidos
	así como la dirección y puerto del emisor.
	Contesta con el string recibido en mayúsculas
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

#define MIPUERTO 4950
#define PUERTO_OTRO_SERV 4950

void aMayusculas(char str[]);

int main(void){
	int sockfd;
	struct sockaddr_in yo;    
	struct sockaddr_in cliente; 
	int addr_len, numbytes;
	char buffer[80];


	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	yo.sin_family = AF_INET6;         
	yo.sin_port = htons(MIPUERTO);     
	yo.sin_addr.s_addr = INADDR_ANY; 
	memset(&(yo.sin_zero), '\0', 8); 

	if (bind(sockfd, (struct sockaddr *)&yo, sizeof(struct sockaddr)) == -1) {
		perror("Error en el bind");
		exit(1);
	}

	addr_len = sizeof(struct sockaddr);
	printf("Servidor escuchando en el puerto 5000\n");

	do{
// Recibir string del cliente
		printf("HAA");
		if ((numbytes=recvfrom(sockfd, buffer, 80-1 , 0,
				(struct sockaddr *) &cliente, &addr_len)) == -1) {
			perror("Error en el recvfrom");
			exit(1);
		}
		buffer[numbytes] = '\0';
		printf("Recibo de %s/%d: %s\n",inet_ntoa(cliente.sin_addr),
						ntohs(cliente.sin_port), buffer);
// Procesar string recibido, pasarlo a mayusculas
//		aMayusculas(buffer);
//		cliente.sin_port = htons(PUERTO_OTRO_SERV); 
// Enviar al cliente el string modificado
/*		if ((numbytes=sendto(sockfd, buffer, strlen(buffer), 0,
			(struct sockaddr *)&cliente, sizeof(struct sockaddr))) == -1){
			perror("sendto");
			exit(1);
		}
*/
	}while(1);
	close(sockfd);
	return 0;
}

void aMayusculas(char str[]){
	int i;
	for(i=0; i<strlen(str); i++)
		if (str[i] >= 'a' && str[i] <= 'z')
			str[i] = str[i] - 'a' + 'A';
}
