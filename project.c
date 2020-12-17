#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define BUFSIZE 8192
#define CACHESIZE 100
#define URLLEN 500
#define MAXAGEDEFAULT 3600
#define AGESIZE 64
#define DEFAULT_PORTNO_SERV 80
#define ERROR_BUILD_CONNECTION -1
#define ERROR_CREATE_MY_SOCK -2

// Connect and read timeouts in seconds
#define CONNECT_TIMEOUT 4
#define READ_TIMEOUT    1

// SSL read timeout in seconds and usec
#define SSL_TIMEOUT   0
#define SSL_TIMEOUT_U 100000

// Window length in microseconds
#define WINDOWLEN 1000
// Max bytes in a window
#define WINDOWMAX 40000

// For spoof translating a phrase to be something else for HTTPS
#define SPOOF_PHRASES 1 // set to 0 to turn this off
#define PHRASE_SEARCH "Computer Science"
#define PHRASE_SEARCH2 "Computer science"
#define PHRASE_SEARCH3 "computer science"
#define PHRASE_REPLACE "NANANANANANANANA"
#define PHRASE_LEN 16
/* Cache function and data structures */

typedef struct {
    char url[URLLEN + 2];
    char host[URLLEN + 2];
    int  portno;
} cacheKey;

typedef struct {
    cacheKey key;
    size_t   data_size;
    char     *value;
    time_t   maxAge;
    time_t   insertionTime;
    time_t   lastAccessTime;
} cacheEntry;

typedef struct connect_sock {
    int sock;
    int host_sock;
    SSL *ssl;
    SSL *ssl_host;
    SSL_CTX *ctx;
    EVP_PKEY *pkey;
    X509 *x509;
    X509 *x509_host;
    struct connect_sock *next;
    struct timeval windowStart;
    size_t bytesTransmitted;
} connect_sock;

connect_sock* connect_sock_root;
fd_set read_fd_set, active_fd_set;
int sockfd_listen;
char PROXY_SUCCESS[] = "HTTP/1.0 200 Connection established\r\n\r\n";
const char* pcszPassphrase = "PWD"; // CHANGE FOR YOUR OWN pwd

int passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}

void freeCacheEntry(cacheEntry *pEntry)
{
    if (pEntry->value != NULL) free(pEntry->value);
    free(pEntry);
}

void freeCache(cacheEntry **cache, int cacheSize)
{
    int i;
    cacheEntry *pEntry = NULL;
    for (i = 0; i < cacheSize; ++i) {
        if ((pEntry = cache[i]) != NULL)
            freeCacheEntry(pEntry);
    }
    free(cache);
}

int keysEqual(cacheKey key1, cacheKey key2)
{
    return ((strcmp(key1.url, key2.url) == 0) &&
            (strcmp(key1.host, key2.host) == 0) &&
            (key1.portno == key2.portno));
}

int search_key(cacheEntry **cache, int cacheSize, cacheKey key)
{
    int i;
    cacheEntry *pEntry = NULL;
    for (i = 0; i < cacheSize; ++i) {
        pEntry = cache[i];
        if (pEntry == NULL)
            continue;
        if (keysEqual(pEntry->key, key))
            return i;
    }
    return -1; // no match
}

int search_null(cacheEntry **cache, int cacheSize)
{
    int i;
    cacheEntry *pEntry = NULL;
    for (i = 0; i < cacheSize; ++i) {
        pEntry = cache[i];
        if (pEntry == NULL)
            return i;
    }
    return -1; // no match
}

int search_expired(cacheEntry **cache, int cacheSize)
{
    int i;
    time_t timeDiff;
    cacheEntry *pEntry = NULL;

    for (i = 0; i < cacheSize; ++i) {
        pEntry = cache[i];
        if (pEntry == NULL)
            continue;
        timeDiff = time(NULL) - pEntry->insertionTime;
        if (timeDiff >= pEntry->maxAge)
            return i;
    }
    return -1; // no match
}

int search_oldest(cacheEntry **cache, int cacheSize)
{
    int i, oldestPos = 0;
    time_t oldestAccess = time(NULL) + 10;
    cacheEntry *pEntry = NULL;

    for (i = 0; i < cacheSize; ++i) {
        pEntry = cache[i];
        if (pEntry == NULL)
            continue;
        if (pEntry->lastAccessTime < oldestAccess) {
            oldestPos = i;
            oldestAccess = pEntry->lastAccessTime;
        }
    }

    return oldestPos;
}

int allocate_index(cacheEntry **cache, int cacheSize, cacheKey key)
{
    int pos;
    // case one: key is already there, return its index
    if ((pos = search_key(cache, cacheSize, key)) != -1)
        return pos;
    // case two: find a null spot, return its index
    if ((pos = search_null(cache, cacheSize)) != -1)
        return pos;
    // case three: find an expired spot, free it and return its index
    // case four: find the oldest spot, free it and return its index
    pos = search_expired(cache, cacheSize);
    if (pos == -1)
        pos = search_oldest(cache, cacheSize);
    freeCacheEntry(cache[pos]);
    cache[pos] = NULL;
    return pos;
}

connect_sock* create_connect_sock(int sock, int host_sock, SSL *ssl, SSL *ssl_host,
                                  SSL_CTX *ctx, EVP_PKEY *pkey, X509 *x509, X509 *x509_host) {
    connect_sock * node = (connect_sock*) malloc(sizeof(connect_sock));
    node->sock = sock;
    node->host_sock = host_sock;
    node->ssl = ssl;
    node->ssl_host = ssl_host;
    node->ctx = ctx;
    node->pkey = pkey;
    node->x509 = x509;
    node->x509_host = x509_host;
    node->next = NULL;
    gettimeofday(&(node->windowStart), NULL);
    node->bytesTransmitted = 0;
    return node;
}

connect_sock *get_connect_sock_ptr(int sock) {
    connect_sock*  curr = connect_sock_root;
    while (curr != NULL)
        {
            if(curr->sock == sock)
                return curr;
            if(curr->host_sock == sock)
                return curr;
            curr = curr -> next;
        }
    return NULL;
}

int get_connect_sock(int sock){
    connect_sock*  curr = connect_sock_root;
    while (curr != NULL)
        {
            if(curr->sock == sock)
                return curr->host_sock;
            if(curr->host_sock == sock)
                return curr->sock;
            curr = curr -> next;
        }
    return -1;
}

int add_connect_sock(connect_sock* sb){
    //TODO 1 sock can have multi-tunnel?
    if(get_connect_sock(sb->sock) >= 0) return -1;
    if(connect_sock_root == NULL){
        connect_sock_root = sb;
        return 0;
    }
    connect_sock* curr = connect_sock_root;
    while (curr->next != NULL)
        {
            curr = curr -> next;
        }
    curr->next = sb;
    return 0;
}

int remove_connect_sock(int sock){
    int debug = 0;
    if (debug) printf("Removing sock %d\n", sock);
    if (connect_sock_root == NULL ) {
        if (debug) printf("Error because of no root\n");
        return -1;
    }
    connect_sock *curr = connect_sock_root->next;
    connect_sock *pre = connect_sock_root;
    
    if ((connect_sock_root->sock == sock) ||
        (connect_sock_root->host_sock == sock)) {
        curr = connect_sock_root; // for freeing it below
        connect_sock_root = connect_sock_root->next;
    } else {
        while (curr != NULL)
            {
                if (curr->sock == sock || curr->host_sock == sock) {
                    pre->next = curr->next;
                    break;
                }
                pre = curr;
                curr = curr->next;
            }
    }
    if (curr == NULL) return -1;
    if (curr->ssl != NULL)
        SSL_free(curr->ssl);
    if (curr->ssl_host != NULL)
        SSL_free(curr->ssl_host);
    if (curr->sock >= 0) {
        close(curr->sock);
        FD_CLR(curr->sock, &active_fd_set);
    }
    if (curr->host_sock >= 0) {
        close(curr->host_sock);
        FD_CLR(curr->host_sock, &active_fd_set);
    }
    if (curr->ctx != NULL)
        SSL_CTX_free(curr->ctx);
    if (curr->x509 != NULL)
        X509_free(curr->x509);
    if (curr->x509_host != NULL)
        X509_free(curr->x509_host);
    if (curr->pkey != NULL)
        EVP_PKEY_free(curr->pkey);

    free(curr);

    return 0;
}


void insert_data(cacheEntry **cache, int cacheSize, cacheKey key, char *value,
                 size_t data_size)
{
    int maxAge, pos;
    cacheEntry *pEntry;
    char *pheader_end, *pcachecontrol, *pcachecontrolEnd;
    time_t now;

    now = time(NULL);
    maxAge = MAXAGEDEFAULT;

    pheader_end = strstr(value, "\r\n\r\n");
    *pheader_end = '\0'; // temporarily end here before searching
    pcachecontrol = strstr(value, "\r\nCache-Control:");
    if (pcachecontrol != NULL) {
        pcachecontrol += 16;
        pcachecontrolEnd = strstr(value, "\r\n");
        if (pcachecontrolEnd != NULL) *pcachecontrolEnd = '\0';
        pcachecontrol = strstr(pcachecontrol, "max-age=");
        if (pcachecontrol != NULL)
            sscanf(pcachecontrol, "max-age=%d", &maxAge);
        if (pcachecontrolEnd != NULL) *pcachecontrolEnd = '\r';

    }
    *pheader_end = '\r'; // restore previous value

    pos = allocate_index(cache, cacheSize, key);
    if (pos == -1)
        return;

    pEntry = cache[pos];
    if (pEntry == NULL) { // not updating existing record
        pEntry = malloc(sizeof(*pEntry));
        pEntry->key = key;
    } else if (pEntry->value != NULL) { // updating existing record
        free(pEntry->value);
    }
    pEntry->value = value;
    pEntry->data_size = data_size;
    pEntry->maxAge = maxAge;
    pEntry->lastAccessTime = now;
    pEntry->insertionTime = now;
    cache[pos] = pEntry;
}

char *retrieve_data(cacheEntry **cache, int cacheSize, cacheKey key,
                    size_t *pdata_size, time_t *age)
{
    int pos;

    pos = search_key(cache, cacheSize, key);
    if (pos != -1) {
        cacheEntry *pEntry = cache[pos];
        *age = time(NULL) - pEntry->insertionTime;
        if (*age < pEntry->maxAge) {
            pEntry->lastAccessTime = time(NULL);
            *pdata_size = pEntry->data_size;
            return pEntry->value;
        }
    }
    return NULL;
}

// read all data from given file descriptor into dynamically allocated string
char *read_data(int fd, int is_response, int testing, size_t *pdata_size, SSL *sender_ssl)
{
    char buffer[BUFSIZE];
    ssize_t n, last_pos;
    char *data_received, *pcontent_length, *pheader_end;
    size_t data_size, content_read, content_length, header_length;
    int read_header, has_content_length;
    fd_set masterDataReadSet, dataReadSet;
    struct timeval tv;

    tv.tv_sec = READ_TIMEOUT;
    tv.tv_usec = 0;

    FD_ZERO(&masterDataReadSet);
    FD_SET(fd, &masterDataReadSet);
    data_received = NULL;
    pcontent_length = NULL;
    pheader_end = NULL;
    data_size = 0;
    last_pos = 0;
    read_header = 0;
    content_length = 0;
    content_read = 0;
    has_content_length = 0;
    do {
        dataReadSet = masterDataReadSet;
        memset(buffer, 0, BUFSIZE);
        if (testing) printf("read_data is reading...\n");
        if (sender_ssl == NULL) {
            if (select(fd + 1, &dataReadSet, NULL, NULL, &tv) < 0) {
                perror("select error");
                *pdata_size = data_size;
                return data_received;
            }
            if (!FD_ISSET(fd, &dataReadSet)) {
                if (testing) printf("select timeout in read_data\n");
                *pdata_size = data_size;
                return data_received;
            }
            if (testing) printf("Going to use read() function..\n");
            n = read(fd, buffer, BUFSIZE - 1);
        } else {
            if (testing) printf("Going to use SSL_read() function...\n");
            n = SSL_read(sender_ssl, buffer, BUFSIZE - 1);
        }

        if (n < 0) {
            if (testing) printf("read() returned negative value for socket %d\n", fd);
            break;
        }
        if (n == 0) {
            if (testing) printf("read() returned 0 for socket %d\n", fd);
            break;
        }

        buffer[BUFSIZE - 1] = '\0'; // to be safe

        if (testing) printf("read_data read %zd bytes inside read_data out of %zu bytes\n", n, content_length);

        if (is_response && !read_header) {
            read_header = 1;
            pheader_end = strstr(buffer, "\r\n\r\n");
            header_length = 4 + pheader_end - buffer;
            content_read += (n - header_length);
            // Check if have Content-Length
            pcontent_length = strstr(buffer, "Content-Length:");
            if (pcontent_length != NULL) {
                has_content_length = 1;
                sscanf(pcontent_length, "Content-Length: %zu",
                       &content_length);
                if (testing) printf("Read content length of %zu\n", content_length);
            } else if (testing) printf("Read no content length\n");
        } else {
            content_read += n;
        }

        data_size += n;
        data_received = realloc(data_received, data_size);
        memcpy(data_received + last_pos, buffer, n);

        last_pos += n;
    } while ((is_response && !has_content_length)
             || (content_read < content_length));
    // ^^^ Need to do rate-limiting here as well that doesn't break HTTP..?

    //if (testing) data_received[data_size - 1] = '\0';
    *pdata_size = data_size;
    return data_received;
}

int get_host(char* token, int testing, char* host){
    char hoststr[110];
    while ((token != NULL) && (strncmp(token, "Host:", 5) != 0))
        token = strtok(NULL, "\r\n");
    if (testing) printf("token:%s\n", token);
    sscanf(token, "Host: %s", hoststr);
    if (testing) printf("hoststr:%s\n", hoststr);
    token = strtok(hoststr, ":");
    strcpy(host, token);
    token = strtok(NULL, ":");

    int portno_serv = DEFAULT_PORTNO_SERV;
    if (token != NULL)
        sscanf(token, "%d", &portno_serv);
    if (testing) printf("host:%s\nport:%d\n", host, portno_serv);
    return portno_serv;
}

int built_connection(char* host, int portno_serv, int testing) {
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int sockfd_serv = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_serv < 0) {
        perror("ERROR opening socket");
        return ERROR_BUILD_CONNECTION;
    }
    if (testing) printf("In built_connection() getting host by name for %s\n", host);
    server = gethostbyname(host);
    if (server == NULL) {
        perror("No such host");
        return ERROR_BUILD_CONNECTION;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr,
          (char *) &serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno_serv);
    if (testing) printf("In built_connection() running connect() call\n");

    int arg;
    // Set non-blocking 
    if ((arg = fcntl(sockfd_serv, F_GETFL, NULL)) < 0) { 
        perror("fcntl");
        exit(0); 
    } 
    arg |= O_NONBLOCK; 
    if (fcntl(sockfd_serv, F_SETFL, arg) < 0) { 
        perror("fcntl");
        exit(0); 
    } 

    // Try to connect with timeout
    if (connect(sockfd_serv, (struct sockaddr *) &serv_addr,
                sizeof(serv_addr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("ERROR connecting");
            return ERROR_BUILD_CONNECTION;
        }
        // Set timeout
        struct timeval tv;
        tv.tv_sec = CONNECT_TIMEOUT;
        tv.tv_usec = 0;
        fd_set connectSet;
        FD_ZERO(&connectSet);
        FD_SET(sockfd_serv, &connectSet);
        // Check if socket becomes writeable within timeout interval
        int ret = select(sockfd_serv + 1, NULL, &connectSet, NULL, &tv);
        if (ret < 0) {
            perror("ERROR connecting");
            return ERROR_BUILD_CONNECTION;
        } else if (ret == 0) {
            if (testing) printf("TIMEOUT while connecting\n");
            close(sockfd_serv);
            return ERROR_BUILD_CONNECTION;
        }        
    }

    // Set to blocking again
    if ((arg = fcntl(sockfd_serv, F_GETFL, NULL)) < 0) { 
        perror("fcntl");
        exit(0);
    } 
    arg &= (~O_NONBLOCK); 
    if (fcntl(sockfd_serv, F_SETFL, arg) < 0) {
        perror("fcntl");
        exit(0);
    }

    if (testing) printf("In built_connection() finished connect() call\n");
    return sockfd_serv;
}

int forward_data(int receiver_sk, char *server_input, size_t data_size, SSL *receiver_ssl) {
    ssize_t n;
    if (receiver_ssl == NULL)
        n = write(receiver_sk, server_input, data_size);
    else
        n = SSL_write(receiver_ssl, server_input, data_size);
    if (n < 0) {
        perror("ERROR writing to socket");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int create_my_socket(int portno_listen) {
    struct sockaddr_in my_addr;
    if ((sockfd_listen = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("ERROR, new socket\n");
        return ERROR_CREATE_MY_SOCK;
    }

    int optval = 1;
    setsockopt(sockfd_listen, SOL_SOCKET, SO_REUSEADDR,(const void *)&optval , sizeof(int));

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(portno_listen);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd_listen, (struct sockaddr*)&my_addr, sizeof(my_addr)) != 0) {
        perror("ERROR, bind socket\n");
        return ERROR_CREATE_MY_SOCK;
    }

    if (listen(sockfd_listen, 5) < 0) {
        perror("ERROR, listen socket\n");
        return ERROR_CREATE_MY_SOCK;
    }

    return EXIT_SUCCESS;
}

void ssl_init(void) {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

SSL_CTX *ssl_init_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)pcszPassphrase);
    SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to get certificate");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        perror("Unable to get private key");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void server_loop(int use_openssl, int testing, int testingnum, cacheEntry **cache) {
    int portno_serv, sockfd_accept, sockfd_serv, fdmax;
    int testing_index = 0;
    char *data_received, *server_input, *server_output, *client_input,
        *token, url[URLLEN], host[URLLEN];
    size_t data_size;
    struct timeval tv, ssl_tv;
    SSL_CTX *ctx = NULL;
    EVP_PKEY *pPrivKey = NULL;
    X509 *cert = NULL;
    X509_NAME *subname = NULL;

    if (use_openssl) {
        ssl_init();
        ctx = ssl_init_context();
        if (testing) printf("Initiated SSL context\n");
        
        // Get private key
        FILE *fp = fopen("key.pem", "r");
        if (!fp) {
            perror("Unable to open private key file");
            return;
        }
        pPrivKey = PEM_read_PrivateKey(fp, NULL, passwd_callback, (void*)pcszPassphrase);
        if (!pPrivKey) {
            perror("Unable to read private key");
            return;
        }
        fclose(fp);

        // Get certificate
        fp = fopen("cert.pem", "r");
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!cert) {
            perror("Unable to parse certificate");
            return;
        }
        fclose(fp);
        subname = X509_get_subject_name(cert);
    }

    tv.tv_sec = 1; // timeout select every second
    tv.tv_usec = 0;

    ssl_tv.tv_sec = SSL_TIMEOUT;
    ssl_tv.tv_usec = SSL_TIMEOUT_U;
    
    /* Initialize the set of active sockets. */
    FD_ZERO(&active_fd_set);
    FD_SET(sockfd_listen, &active_fd_set);
    fdmax = sockfd_listen;

    int j = 0;

    while ((testingnum == 0) || (testing_index < testingnum)) {
        read_fd_set = active_fd_set;
        
        if (select(fdmax + 1, &read_fd_set, NULL, NULL, &tv) < 0) {
            perror("select");
            close(sockfd_listen);
            return;
        }

        if (j > fdmax) j = 0;
        for (int i = j; i <= fdmax; ++i, ++j) {
            if (FD_ISSET (i, &read_fd_set)) {
                if (testing) printf("FD SET triggered socket %d\n", i);
                if (i == sockfd_listen) {
                    struct sockaddr_in client_addr;
                    socklen_t addrlen = sizeof(client_addr);
                    int client_sock = accept(sockfd_listen, (struct sockaddr *) &client_addr, &addrlen);
                    if (client_sock < 0) {
                        close(sockfd_listen);
                        perror("ERROR on accept");
                        return;
                    }
                    FD_SET(client_sock, &active_fd_set);
                    if (client_sock > fdmax) fdmax = client_sock;
                    if (testing) printf("Connected to client %d\n", client_sock);
                } else {
                    int receiver_sk;
                    SSL *receiver_ssl, *sender_ssl;
                    connect_sock *pconnect_sock;
                    
                    sockfd_accept = i;
                    sockfd_serv = -1;
                    data_received = NULL;
                    data_size = 0;
                    pconnect_sock = get_connect_sock_ptr(sockfd_accept);
                    receiver_ssl = NULL;
                    sender_ssl = NULL;

                    // If this connection needs to be throttled then continue
                    if (pconnect_sock != NULL) {
                        struct timeval now;
                        gettimeofday(&now, NULL);
                        if ((now.tv_sec * (uint64_t)1000000 + now.tv_usec) - 
                            (pconnect_sock->windowStart.tv_sec * (uint64_t)1000000 + pconnect_sock->windowStart.tv_usec)
                            >= WINDOWLEN) { // cleared window
                            pconnect_sock->bytesTransmitted = 0;
                            gettimeofday(&(pconnect_sock->windowStart), NULL);
                        } else if (pconnect_sock->bytesTransmitted > WINDOWMAX) { // we've reached max in this window
                            if (testing) printf("Skipping socket %d because reached bandwidth\n", sockfd_accept);
                            continue;
                        }

                        if (pconnect_sock->sock == sockfd_accept) {
                            receiver_sk = pconnect_sock->host_sock;
                            receiver_ssl = pconnect_sock->ssl_host;
                            sender_ssl = pconnect_sock->ssl;
                        } else {
                            receiver_sk = pconnect_sock->sock;
                            receiver_ssl = pconnect_sock->ssl;
                            sender_ssl = pconnect_sock->ssl_host;
                        }
                    }

                    data_received = read_data(sockfd_accept, 0, testing, &data_size, sender_ssl); // need to change this to only get header initially then get the rest (for HTTPS in case they send the data immediately)
                    
                    //if (testing) printf("Data read:\n%s\n", data_received);
                    if (testing) printf("read_data read %zu bytes\n", data_size);
                    //if (testing) sleep(1);

                    if ((data_received == NULL) || (data_size == 0)) { // connection closed
                        if (testing) printf ("Removed disconnected client %d\n", sockfd_accept);
                        if (pconnect_sock != NULL) {
                            if (remove_connect_sock(sockfd_accept) < 0) {
                                perror("ERROR removing tunnel");
                                return;
                            }
                            //break; // because the call to remove_connect_sock will have closed the other end of the tunnel as well
                        } else {
                            close(sockfd_accept);
                            FD_CLR(sockfd_accept, &active_fd_set);
                        }
                        break;
                    }


                    server_input = malloc(data_size);
                    memcpy(server_input, data_received, data_size);

                    //TODO case 1
                    //already established HTTPS tunnel
                    //sock may be client_socks or server_socks
                    if (pconnect_sock != NULL) {
                        pconnect_sock->bytesTransmitted += data_size; // Update bucket

                        if (testing) printf("In case 1\n");
                        if (testing) printf("Forwarding data\n");
                        if (SPOOF_PHRASES && use_openssl) { // use find and replace
                            if (data_size > PHRASE_LEN + 1) {
                                if (testing) printf ("Looking for phrase matches...\n");
                                for (int start = 0; start < (data_size - PHRASE_LEN - 1); start++) {
                                    if ((memcmp(server_input + start, PHRASE_SEARCH, PHRASE_LEN) == 0) ||
                                        (memcmp(server_input + start, PHRASE_SEARCH2, PHRASE_LEN) == 0) ||
                                        (memcmp(server_input + start, PHRASE_SEARCH3, PHRASE_LEN) == 0)) {
                                        memcpy(server_input + start, PHRASE_REPLACE, PHRASE_LEN);
                                        if (testing) printf("Got a phrase match!");
                                    }
                                }
                                if (testing) printf("Done looking for phrase matches\n");
                            }
                        }
                        if (forward_data(receiver_sk, server_input, data_size, receiver_ssl) == EXIT_FAILURE) {
                            perror("ERROR forward data");
                            // remove tunnel
                            if (remove_connect_sock(receiver_sk) < 0) {
                                perror("ERROR removing tunnel");
                                return;
                            }
                        }
                        free(data_received);
                        free(server_input);
                        if (testingnum != 0) testing_index++;
                        break;

                    }

                    token = strtok(data_received, "\r\n");

                    //TODO case2
                    // handle CONNECT method
                    if (data_size >= 7 && strncmp(data_received, "CONNECT", 7) == 0) {
                        if (testing) printf("In case 2\n");
                        int success_connecting = 1;
                        SSL *ssl = NULL;
                        SSL *ssl_host = NULL;
                        SSL_CTX *ctx_accept = NULL;
                        EVP_PKEY *pkey = NULL;
                        X509 *x509 = NULL;
                        X509 *x509_host = NULL;
                        portno_serv = get_host(token, testing, host);
                        // !!!!!!!!!!!!!!!! THE BELOW CALL SOMETIMES TAKES TOO LONG
                        if ((sockfd_serv = built_connection(host, portno_serv, testing)) == ERROR_BUILD_CONNECTION)
                            success_connecting = 0;

                        if (success_connecting) // Tell client connection was successful
                            write(sockfd_accept, PROXY_SUCCESS, strlen(PROXY_SUCCESS));

                        if (success_connecting && use_openssl) { // connect to server
                            ssl_host = SSL_new(ctx);
                            SSL_set_tlsext_host_name(ssl_host, host); // In case of SNI
                            SSL_set_fd(ssl_host, sockfd_serv);
                            if (SSL_connect(ssl_host) == -1) {
                                success_connecting = 0;
                                if (testing) printf("Error connecting to to server via SSL\n");
                            } else { // get host certificate
                                x509_host = SSL_get_peer_certificate(ssl_host);
                                if (testing) printf("Connected to server via SSL\n");
                                setsockopt(sockfd_serv, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ssl_tv, sizeof ssl_tv); // set receive timeout on SSL
                            }
                        }

                        if (success_connecting && use_openssl) { // connect to client
                            if (testing) printf("Creating new key and certificate for client connection\n");
                            // Create key
                            pkey = EVP_PKEY_new();
                            RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
                            if (rsa == NULL) {
                                perror("Unable to generate RSA key");
                                exit(EXIT_FAILURE);
                            }
                            EVP_PKEY_assign_RSA(pkey, rsa);

                            // Create certificate
                            x509 = X509_new();
                            ASN1_INTEGER_set(X509_get_serialNumber(x509), (unsigned)rand());
                            X509_gmtime_adj(X509_get_notBefore(x509), 0);
                            X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
                            X509_set_pubkey(x509, pkey);
                            X509_set_subject_name(x509, X509_get_subject_name(x509_host)); // use host's subject name
                            if (testing) printf("Certificate subject name: %s\n", X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0));
                            X509_set_issuer_name(x509, subname); // set to be issued by saved cert
                            if (testing) printf("Certificate issuer name: %s\n", X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0));
                            X509_add1_ext_i2d(x509, NID_subject_alt_name, X509_get_ext_d2i(x509_host, NID_subject_alt_name, 0, 0), 0, 0);

                            if (X509_sign(x509, pPrivKey, EVP_sha1()) == 0) { // sign with already saved cert's private key
                                perror("Unable to sign new certificate");
                                exit(EXIT_FAILURE);
                            }

                            // Need to make a new context with the desired properties
                            const SSL_METHOD *method;
                            method = TLS_server_method();
                            ctx_accept = SSL_CTX_new(method);
                            if (!ctx_accept) {
                                perror("Unable to create SSL context");
                                exit(EXIT_FAILURE);
                            }
                            
                            if (SSL_CTX_use_certificate(ctx_accept, x509) != 1) {
                                perror("Unable to set SSL context to use new certificate");
                                exit(EXIT_FAILURE);
                            }
                            if (SSL_CTX_use_PrivateKey(ctx_accept, pkey) != 1) {
                                perror("Unable to set SSL context to use private key");
                                exit(EXIT_FAILURE);
                            }
                            if (!SSL_CTX_check_private_key(ctx)) {
                                perror("Private key does not match public certificate");
                                exit(EXIT_FAILURE);
                            }

                            // Finally accept the client using a new SSL with this certificate
                            ssl = SSL_new(ctx_accept);
                            SSL_set_fd(ssl, sockfd_accept);
                            if (SSL_accept(ssl) < 0) {
                                success_connecting = 0;
                                if (testing) printf("Eror connecting to to client via SSL\n");
                            }
                            else if (testing) printf("Connected to client via SSL\n");
                        }

                        if (!success_connecting) {
                            free(data_received);
                            free(server_input);
                            if (ctx_accept != NULL) SSL_CTX_free(ctx_accept);
                            if (x509 != NULL) X509_free(x509);
                            if (x509_host != NULL) X509_free(x509_host);
                            if (pkey != NULL) EVP_PKEY_free(pkey);
                            close(sockfd_accept);
                            if (sockfd_serv != ERROR_BUILD_CONNECTION) close(sockfd_serv);
                            FD_CLR(sockfd_accept, &active_fd_set);
                            if (use_openssl) close(sockfd_serv); // must've failed at SSL after initial connection
                            break;
                        }
                        
                        if (testing) printf("Added other end of connection: %d\n", sockfd_serv);

                        if (add_connect_sock(create_connect_sock(sockfd_accept, sockfd_serv, ssl, ssl_host,
                                                                 ctx_accept, pkey, x509, x509_host)) < 0) {
                            perror("ERROR adding dup tunnel");
                            return;
                        }
                        FD_SET(sockfd_serv, &active_fd_set);
                        if (sockfd_serv > fdmax) fdmax = sockfd_serv;
                        
                        free(data_received);
                        free(server_input);
                        if (testingnum != 0) testing_index++;
                        break;
                    }

                    //TODO case3
                    // handle GET method
                    if (testing) printf("In case 3\n");
                    cacheKey key;
                    time_t age;
                    memset(url, 0, URLLEN);
                    sscanf(token, "GET %s", url);
                    if (testing) printf("URL:%s\n", url);

                    portno_serv = get_host(token, testing, host);

                    free(data_received);

                    // Populate key struct
                    strcpy(key.url, url);
                    strcpy(key.host, host);
                    key.portno = portno_serv;

                    // Check if the data is in the cache (includes age);
                    server_output = retrieve_data(cache, CACHESIZE, key, &data_size, &age);
                    if (server_output == NULL) {
                        if ((sockfd_serv = built_connection(host, portno_serv, testing)) == ERROR_BUILD_CONNECTION) {
                            free(server_input);
                            close(sockfd_accept);
                            FD_CLR(sockfd_accept, &active_fd_set);
                            continue;
                        }

                        if (testing) printf("Built connection, writing HTTP data...\n");
                        size_t n = write(sockfd_serv, server_input, data_size);
                        if (n < 0) {
                            perror("ERROR writing to socket");
                            free(server_input);
                            close(sockfd_serv);
                            close(sockfd_accept);
                            FD_CLR(sockfd_accept, &active_fd_set);
                            continue;
                        }
                        if (testing) printf("Wrote data, now will read HTTP data from server...\n");
                        server_output = read_data(sockfd_serv, 1, testing, &data_size, NULL);
                        if (testing) printf("Done reading HTTP data from server...\n");
                        if ((server_output == NULL) || (data_size == 0)) { // Timed out
                            if (server_input != NULL) free(server_input);
                            close(sockfd_accept);
                            FD_CLR(sockfd_accept, &active_fd_set);
                            continue;
                        }
                        insert_data(cache, CACHESIZE, key, server_output, data_size);
                        client_input = malloc(data_size);
                        memcpy(client_input, server_output, data_size);
                        if (testing) printf("Now will close server HTTP socket...\n");
                        close(sockfd_serv);
                    } else { /* Splice in the age */
                        char ageEntity[AGESIZE], *pheaderEnd, *cursor, lastChar;
                        unsigned newagelen, headerlen;

                        // Find end of header (if there is one)
                        lastChar = server_output[data_size - 1];
                        server_output[data_size - 1] = '\0';
                        pheaderEnd = strstr(server_output, "\r\n\r\n");
                        server_output[data_size - 1] = lastChar;
                        if (pheaderEnd == NULL) {
                            client_input = malloc(data_size);
                            memcpy(client_input, server_output, data_size);
                        } else {
                            sprintf(ageEntity, "\r\nAge: %lu", (unsigned long) age);
                            newagelen = strlen(ageEntity);
                            if (testing) printf("Data size from cache: %zu\n", data_size);
                            data_size += newagelen;
                            client_input = malloc(data_size);

                            headerlen = pheaderEnd - server_output;
                            if (testing) printf("Detected headerlen in cache: %u\n", headerlen);

                            cursor = client_input;
                            memcpy(cursor, server_output, headerlen);
                            cursor += headerlen;

                            strcpy(cursor, ageEntity);
                            cursor += newagelen;

                            memcpy(cursor, pheaderEnd,
                                   data_size - headerlen - newagelen); // +1?
                        }
                    }

                    // forward the data
                    /* BUT WHAT IF THEY KEEP COMMUNICATING */
                    free(server_input);
                    if (testing) printf("Now forwarding HTTP data to the client...\n");
                    size_t n = write(sockfd_accept, client_input, data_size);
                    if (testing) printf("Done forwarding HTTP data\n");
                    if (n < 0) {
                        perror("ERROR writing to socket");
                    }
                    free(client_input);

                    close(sockfd_accept);
                    FD_CLR(sockfd_accept, &active_fd_set);
                    if (testingnum != 0) testing_index++;
                    break;
                }
            }
        }
    }
}

void freeConnectSocks(void)
{
    connect_sock*  curr = connect_sock_root;
    connect_sock*  next;
    while (curr != NULL)
        {
            next = curr->next;
            if (curr->sock >= 0) {
                close(curr->sock);
                FD_CLR(curr->sock, &active_fd_set);
            }
            if (curr->host_sock >= 0) {
                close(curr->host_sock);
                FD_CLR(curr->host_sock, &active_fd_set);
            }
            free(curr);
            curr = next;
        }
    connect_sock_root = NULL;
}

void start_proxy(int use_openssl, int testing, int testingnum, int portno_listen, cacheEntry **cache)
{
    if ((create_my_socket(portno_listen)) == ERROR_CREATE_MY_SOCK)
        {
            close(sockfd_listen);
            perror ("Error: create_server");
            exit (EXIT_FAILURE);
        }
    server_loop(use_openssl, testing, testingnum, cache);
    // free the cache (only necessary for testing with finite loops
    close(sockfd_listen);
    freeCache(cache, CACHESIZE);
    freeConnectSocks();
}

/* main function */
int main(int argc, char **argv) {
    int portno_listen, use_openssl, testing, testingnum;
    cacheEntry **cache;

    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL); // Don't error on broken pipes
    if (argc < 2) {
        perror("ERROR, no port provided\n");
        return EXIT_FAILURE;
    }
    testing = 0;
    testingnum = 0;
    if (argc >= 3)
        use_openssl = atoi(argv[2]);
    if (argc >= 4)
        testing = atoi(argv[3]);
    if (argc >= 5)
        testingnum = atoi(argv[4]);

    portno_listen = atoi(argv[1]);

    // Initialize cache
    cache = malloc(CACHESIZE * sizeof(*cache));
    for (int i = 0; i < CACHESIZE; ++i)
        cache[i] = NULL;
    srand(time(NULL));
    start_proxy(use_openssl, testing, testingnum, portno_listen, cache);
    return 0;
}
