#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>	 //Provides declarations for ipv4 header
#include <netinet/udp.h> //Provides declarations for udp header

#define BUFFER_SIZE 65536
#define DNS_PORT 53
#define DNS_HEADER_LEN 12
#define TYPE_A 1
#define TYPE_AAAA 28
#define TYPE_CNAME 5

void handle_packet(int, unsigned int(unsigned char *));
void parse_dns(unsigned char *, unsigned short);
int print_domain(unsigned char *, int);
unsigned int ipv4_offset(unsigned char *);
unsigned int ipv6_offset(unsigned char *);

int main()
{
	int sock_raw4, sock_raw6, max_sock, fd;
	fd_set all_socks, ready_socks;

	sock_raw4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	sock_raw6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	if (sock_raw4 < 0 || sock_raw6 < 0)
	{
		perror("Socket Error\n");
		return EXIT_FAILURE;
	}

	FD_ZERO(&all_socks);
	FD_SET(sock_raw4, &all_socks);
	FD_SET(sock_raw6, &all_socks);

	// max_sock should be sock_raw6 but just in case...
	max_sock = (sock_raw6 > sock_raw4 ? sock_raw6 : sock_raw4) + 1;

	while (1)
	{
		// Getting fds that are ready to be read
		ready_socks = all_socks;
		if (select(max_sock, &ready_socks, NULL, NULL, NULL) < 0)
		{
			perror("Selcet Error\n");
			return EXIT_FAILURE;
		}
		for (fd = 0; fd < max_sock; fd++)
		{
			if (FD_ISSET(fd, &ready_socks))
			{
				if (fd == sock_raw4)
				{
					handle_packet(fd, &ipv4_offset);
				}
				else if (fd == sock_raw6)
				{
					handle_packet(fd, &ipv6_offset);
				}
			}
		}
	}
	return EXIT_SUCCESS;
}

void handle_packet(int fd, unsigned int (*offset_func)(unsigned char *))
{
	unsigned char *buffer = NULL, *dns_packet = NULL;
	struct udphdr *udph = NULL;
	unsigned short a_count;
	unsigned int offset;

	buffer = (unsigned char *)malloc(BUFFER_SIZE);
	if (buffer == NULL)
	{
		perror("Memory could not be allocated\n");
		exit(EXIT_FAILURE);
	}

	if (recv(fd, buffer, BUFFER_SIZE, 0) < 0)
	{
		perror("Recv error, failed to get packet\n");
		exit(EXIT_FAILURE);
	}

	offset = offset_func(buffer);

	udph = (struct udphdr *)(buffer + offset);
	if (ntohs(udph->source) == DNS_PORT)
	{	
		// Assuming only one question in a single query since the scenario of multiple questions in a single query is not well defined

		dns_packet = buffer + offset + sizeof(udph);
		a_count = (dns_packet[6] << 8) | dns_packet[7];

		// Not reading responses with no answers
		if (a_count > 0)
		{
			parse_dns(dns_packet, a_count);
		}
	}
	free(buffer);
}

void parse_dns(unsigned char *dns_packet, unsigned short a_count)
{
	unsigned short type;
	int pos = print_domain(dns_packet, DNS_HEADER_LEN) + 4;
	printf(": \n");
	for (int i = 0; i < a_count; i++)
	{
		printf("Name: ");
		pos = print_domain(dns_packet, pos);
		printf("\n");
		type = (dns_packet[pos] << 8) | dns_packet[pos + 1];
		pos += 10;
		switch (type)
		{
		case TYPE_A:
			printf("IPv4: ");
			for (int j = 0; j < 3; j++)
			{
				printf("%u.", dns_packet[pos + j]);
			}
			printf("%u\n", dns_packet[pos + 3]);
			pos += 4;
			break;

		case TYPE_AAAA:
			printf("IPv6: ");
			for (int j = 0; j < 15; j++)
			{
				((j % 2) && printf("%02x:", dns_packet[pos + j])) || printf("%02x", dns_packet[pos + j]);
			}
			printf("%02x\n", dns_packet[pos + 15]);
			pos += 16;
			break;

		case TYPE_CNAME:
			printf("CNAME: ");
			pos = print_domain(dns_packet, pos);
			printf("\n");
			break;
		}
	}
	printf("\n");
}

int print_domain(unsigned char *dns_packet, int offset)
{
	char domain_name[256];
	int dns_pos = offset, domain_name_pos = 0, label_pos;
	uint8_t label_len = dns_packet[dns_pos];
	uint16_t domain_name_ptr;

	if (label_len >> 6 == 3)
	{
		domain_name_ptr = (dns_packet[dns_pos] << 8 & 0x3F) | dns_packet[dns_pos + 1];
		print_domain(dns_packet, domain_name_ptr);
		return dns_pos + 2;
	}

	while (1)
	{
		dns_pos++;

		for (label_pos = 0; label_pos < label_len; label_pos++)
		{
			domain_name[domain_name_pos] = dns_packet[dns_pos + label_pos];
			domain_name_pos++;
		}

		dns_pos = dns_pos + label_len;
		label_len = dns_packet[dns_pos];

		if (label_len >> 6 == 3)
		{
			domain_name_ptr = (dns_packet[dns_pos] << 8 & 0x3F) | dns_packet[dns_pos + 1];
			domain_name[domain_name_pos] = '\0';
			printf("%s.", domain_name);
			print_domain(dns_packet, domain_name_ptr);
			return dns_pos + 2;
		}
		else if (label_len > 0)
		{
			domain_name[domain_name_pos] = '.';
			domain_name_pos++;
		}
		else
		{
			domain_name[domain_name_pos] = '\0';
			printf("%s", domain_name);
			return dns_pos + 1;
		}
	}
}

unsigned int ipv4_offset(unsigned char *buffer)
{
	return ((struct iphdr *)buffer)->ihl * 4;
}

unsigned int ipv6_offset(unsigned char *buffer)
{
	return 0;
}
