#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define CHAINS_MAX_CNT 32
#define PROXIES_MAX_CNT 64
#define HOSTNAME_SIZE 128
#define MAX_CHAIN_SIZE 16

enum Action {
    ACTION_ADD_PROXY = 1,
    ACTION_DELETE_PROXY,
    ACTION_ADD_CHAIN,
    ACTION_VIEW_CHAIN,
    ACTION_DELETE_CHAIN,
    ACTION_EXIT,
};

typedef struct _proxy {
    char* hostname;
    int16_t port;
} proxy_t;

typedef struct _chain {
    proxy_t* proxy;
    struct _chain* next;
} chain_t;

chain_t* chains[CHAINS_MAX_CNT];
proxy_t* proxies[PROXIES_MAX_CNT];

void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void read_into_buffer(char* buf, int size) {
    char* result = fgets(buf, size, stdin);

    if (result == NULL) {
        perror("[-] Failed to read into buffer");
        exit(1);
    }

    size_t length = strlen(buf);

    if (length > 0 && buf[length - 1] == '\n') {
        buf[length - 1] = '\0';
    }
}

uint64_t read_integer(void) {
    const size_t buflen = 16;

    char buf[buflen];
    read_into_buffer(buf, buflen);

    return strtoull(buf, NULL, 10);
}

proxy_t* proxy_cstr(void) {
    proxy_t* new_proxy = (proxy_t*)malloc(sizeof(proxy_t));

    if (new_proxy == NULL) {
        perror("[-] Failed to create new proxy");
        exit(1);
    }

    new_proxy->hostname = (char*)malloc(HOSTNAME_SIZE);

    if (new_proxy->hostname == NULL) {
        perror("[-] Failed to create chunk for hostname");
        exit(1);
    }

    return new_proxy;
};

void proxy_dstr(proxy_t* proxy) {
    free(proxy->hostname);
    proxy->hostname = NULL;

    free(proxy);
};

chain_t* chain_cstr(void) {
    chain_t* new_chain = (chain_t*)malloc(sizeof(chain_t));
    return new_chain;
}

void chain_dstr(chain_t* chain) {
    chain_t* head = chain;

    while (head != NULL) {
        proxy_dstr(head->proxy);
        head->proxy = NULL;

        chain_t* next = head->next;
        head->next = NULL;
        free(head);

        head = next;
    }
}

void add_proxy(void) {
    size_t proxy_id = 0;

    for (proxy_id; proxy_id < PROXIES_MAX_CNT; ++proxy_id) {
        if (proxies[proxy_id] == NULL) {
            break;
        }
    }

    if (proxy_id == PROXIES_MAX_CNT) {
        puts("[-] Proxies limit exceeded");
        return;
    }

    proxy_t* new_proxy = proxy_cstr();

    printf("[?] Enter proxy hostname: ");
    read_into_buffer(new_proxy->hostname, HOSTNAME_SIZE);

    printf("[?] Enter proxy port: ");
    new_proxy->port = (uint16_t)read_integer();

    printf("[+] Proxy with id #%d created!\n", proxy_id);

    proxies[proxy_id] = new_proxy;
};

void delete_proxy(void) {
    printf("[?] Enter proxy id: ");
    size_t proxy_id = (size_t)read_integer();

    if (proxy_id >= PROXIES_MAX_CNT) {
        puts("[-] Invalid proxy index!");
        return;
    }

    proxy_t* proxy = proxies[proxy_id];

    if (proxy == NULL) {
        puts("[-] No such proxy!");
        return;
    }

    proxy_dstr(proxy);
    proxies[proxy_id] = NULL;
};

void add_chain(void) {
    size_t chain_id = 0;
    
    for (chain_id; chain_id < CHAINS_MAX_CNT; ++chain_id) {
        if (chains[chain_id] == NULL) {
            break;
        }
    }

    if (chain_id == CHAINS_MAX_CNT) {
        puts("[-] Chains limit exceeded!");
        return;
    }

    printf("[?] Enter chain size: ");
    size_t chain_size = (size_t)read_integer();

    if (chain_size == 0 || chain_size > MAX_CHAIN_SIZE) {
        puts("[-] Invalid chain size!");
        return;
    }

    int has_proxy[PROXIES_MAX_CNT] = {0};

    chain_t* head = chain_cstr();
    chain_t* current = head;

    for (size_t i = 0; i < chain_size; ++i) {
        printf("[?] Enter #%d proxy id: ", i);
        size_t proxy_id = (size_t)read_integer();

        if (proxy_id >= PROXIES_MAX_CNT) {
            puts("[-] Invalid proxy index!");
            return;
        }

        if (proxies[proxy_id] == NULL) {
            puts("[-] No such proxy!");
            return;
        }

        if (has_proxy[proxy_id] != 0) {
            puts("[-] This proxy already in chain!");
            return;
        }

        has_proxy[proxy_id] = 1;

        current->proxy = proxies[proxy_id];
        current->next = NULL;

        if (i < chain_size - 1) {
            current->next = chain_cstr();
            current = current->next;
        }
    }
    
    printf("[+] Chain with id #%d created!\n", chain_id);
    chains[chain_id] = head;
};

void view_chain(void) {
    printf("[?] Enter chain id: ");
    size_t chain_id = (size_t)read_integer();

    if (chain_id >= CHAINS_MAX_CNT) {
        puts("[-] Invalid chain index!");
        return;
    }

    if (chains[chain_id] == NULL) {
        puts("[-] No such chain!");
        return;
    }

    chain_t* chain = chains[chain_id];
    size_t proxy_id = 0;

    while (chain != NULL) {
        proxy_t* proxy = chain->proxy;

        printf("[*] proxy #%d is %s:%d\n", proxy_id, proxy->hostname, proxy->port);

        chain = chain->next;
        ++proxy_id;
    }
}

void delete_chain(void) {
    printf("[?] Enter chain id: ");
    size_t chain_id = (size_t)read_integer();

    if (chain_id >= CHAINS_MAX_CNT) {
        puts("[-] Invalid chain index!");
        return;
    }

    chain_t* chain = chains[chain_id];

    if (chain == NULL) {
        puts("[-] No such chain!");
        return;
    }

    chain_dstr(chain);
    chains[chain_id] = NULL;
}

int main() {
    setup();

    while (true) {
        printf(
            "%d. Add Proxy\n"
            "%d. Delete Proxy\n"
            "%d. Add Chain\n"
            "%d. View Chain\n"
            "%d. Delete Chain\n"
            "%d. Exit\n"
            "> ",
            ACTION_ADD_PROXY, ACTION_DELETE_PROXY, ACTION_ADD_CHAIN,
            ACTION_VIEW_CHAIN, ACTION_DELETE_CHAIN, ACTION_EXIT
        );

        switch (read_integer()) 
        { 
            case ACTION_ADD_PROXY:
                add_proxy();
                break;
            case ACTION_DELETE_PROXY:
                delete_proxy();
                break;
            case ACTION_ADD_CHAIN:
                add_chain();
                break;
            case ACTION_VIEW_CHAIN:
                view_chain();
                break;
            case ACTION_DELETE_CHAIN:
                delete_chain();
                break;
            case ACTION_EXIT:
                return 0;
            default:
                puts("[-] Invalid option");
                continue;
        }
    }

    return 0;
}
