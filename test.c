#include <stdio.h>
#include "../include/base.h"

struct ethhdr {
	u_char dst[6];
	u_char src[6];
	u_short type;
};

void macprint(u_char *addr)
{
	for (int n = 0; addr && n < 6; n++)
		printf("%02x%s", addr[n],
			 (n==5) ? "\n" : ":");
}

bool callback(void *frame, size_t frmlen, void *arg)
{
	struct ethhdr *eth = (struct ethhdr *)frame;
	macprint(eth->dst);
	macprint(eth->src);

	(void)frmlen;
	(void)arg;
	return 0;
}

void print_ifdata(const if_data_t *d) {
    char ip4[INET_ADDRSTRLEN];
    char gate[INET_ADDRSTRLEN];
    char ip6[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET,  d->srcip4,  ip4,   sizeof(ip4));
    inet_ntop(AF_INET,  d->gate4, gate, sizeof(gate));
    inet_ntop(AF_INET6, d->srcip6,  ip6,   sizeof(ip6));

    printf("Name:   %s\n", d->name);
    printf("Index:  %d\n", d->index);
    printf("Flags:  %d\n", d->flags);
    printf("MTU:    %d\n", d->mtu);

    printf("MAC src: %02x:%02x:%02x:%02x:%02x:%02x\n",
        d->src[0], d->src[1], d->src[2], d->src[3], d->src[4], d->src[5]);

    printf("MAC dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
        d->dst[0], d->dst[1], d->dst[2], d->dst[3], d->dst[4], d->dst[5]);

    printf("IPv4 src:  %s\n", ip4);
    printf("IPv6 src:  %s\n", ip6);
    printf("IPv4 gate: %s\n", gate);

    printf("Support IPv4: %s\n", d->support4 ? "yes" : "no");
    printf("Support IPv6: %s\n", d->support6 ? "yes" : "no");
}


int main(int c, char **av)
{
	if_data_t data = {0};

	if_get(NULL, &data);
	if_output(stdout, &data);

	putchar(10);
	memset(&data, 0, sizeof(if_data_t));
	if_get("lo0", &data);
	if_output(stdout, &data);
	
	
	struct timeval s, e;
	u_char buf[65535];
	dlt_t *dlt;
	ssize_t n;

	dlt = dlt_open("re0");
	
	n = dlt_recv_cb(dlt, buf, sizeof(buf), callback,
		NULL, 500000000, &s, &e);
	printf("n: %zd\n", n);

	dlt_close(dlt);
	return 0;

/*
	if (av[1])
		printf("is %lld\n", strtons(av[1]));
	if (av[2]) {
		u_char a;

		strtoull_rng(av[2], 0, UINT_MAX, &a, sizeof(a));
		printf("is %hhu\n", a);
	}

	random_init(romuduojr, romuduojr_seed);
	random_srand(time(NULL));
	printf("%lu\n", random_rand());
*/
}
