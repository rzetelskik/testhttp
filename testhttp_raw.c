#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include "err.h"

#define BUFFLEN 4096
#define STATUS_OK "200"
#define BUFF_FILE "_tmp"

int sock, err;
struct addrinfo addr_hints, *addr_result;
char *executable, *connection_addr, *connection_port, *host_addr, *host_path;
size_t content_len;
int chunked_field_flag = 0;

__attribute__((destructor))
void clean_up() {
    unlink(BUFF_FILE);
}

void raise_err_usage() {
    fatal("Usage: %s <host address>:<port> <cookie file> <http test address>", executable);
}

void parse_connection_address(char *arg) {
    char *str = arg;
    connection_addr = strsep(&str, ":");
    connection_port = str;
    if (!connection_addr || !strlen(connection_addr) || !connection_port || !strlen(connection_port))
        raise_err_usage();
}

void parse_host(char *arg) {
    char *str;
    if ((str = strstr(arg, "http://")) && str == arg)
        str += 7;
    else if ((str = strstr(arg, "https://")) && str == arg)
        str += 8;
    else
        raise_err_usage();


    host_addr = strsep(&str, "/");
    host_path = str;
}

void connect_socket() {
    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = PF_INET; // IPv4
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    err = getaddrinfo(connection_addr, connection_port, &addr_hints, &addr_result);

    if (err == EAI_SYSTEM) // system error
        syserr("getaddrinfo: %s", gai_strerror(err));
    else if (err != 0) // other error (host not found, etc.)
        fatal("getaddrinfo: %s", gai_strerror(err));

    // initialize socket according to getaddrinfo results
    sock = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
    if (sock < 0)
        syserr("socket");

    // connect socket to the server
    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
        syserr("connect");

    freeaddrinfo(addr_result);
}

void write_to_host(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = vsnprintf(0, 0, fmt, args) + 1;
    va_end(args);

    char buffer[len];

    va_start(args, fmt);
    vsnprintf(buffer, len, fmt, args);
    va_end(args);

    if (write(sock, buffer, len - 1) != len - 1)
        syserr("partial / failed write");
}

void write_cookies_to_host(char *arg) {
    char *line = NULL;
    size_t len = 0;
    ssize_t recval;

    FILE *in_cookies = fopen(arg, "rt");
    if (!in_cookies)
        syserr("fopen");

    while ((recval = getline(&line, &len, in_cookies)) > 0) {
        write_to_host("Set-Cookie: %.*s\r\n", recval - (line[recval - 1] == '\n' ? 1 : 0), line);
    }

    free(line);
    fclose(in_cookies);
}

void read_response() {
    FILE *buff_file = fopen(BUFF_FILE, "wb");
    if (!buff_file)
        syserr("fopen");

    ssize_t rcv_len, rcv_len_total = 0;
    char buffer[BUFFLEN];

    do {
        memset(buffer, 0, BUFFLEN);
        if ((rcv_len = read(sock, buffer, BUFFLEN)) < 0)
            syserr("read");
        if (fwrite(buffer, 1, BUFFLEN, buff_file) < 0)
            syserr("write");

        rcv_len_total += rcv_len;
    } while (rcv_len);

    fclose(buff_file);
}

int parse_status_line(FILE *stream) {
    char *line = NULL;
    size_t len = 0;

    int status_ok = (getline(&line, &len, stream) < 0 || strstr(line, STATUS_OK) == NULL);
    if (status_ok)
        printf("%s", line);

    free(line);

    return status_ok;
}

char *str_to_lower(char *str) {
    for (char *c = str; *c; ++c)
        *c = tolower(*c);

    return str;
}

char *remove_leading_whitespace(char *str) {
    while (*str && isspace(*str))
        str++;
    return str;
}

char *remove_trailing_whitespace(char *str) {
    char *retval = str;

    while (*str && !isspace(*str))
        str++;
    if (isspace(*str))
        *str = '\0';

    return retval;
}

char *remove_whitespace(char *str) {
    if (!str)
        return str;

    return remove_trailing_whitespace(remove_leading_whitespace(str));
}

void print_cookie_report(char *str) {
    printf("%s\r\n", str);
}

void parse_response_headers(FILE *stream) {
    char *key, *value;
    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, stream) > 2) {
        key = str_to_lower(strsep(&line, ":"));
        if (!strcmp(key, "content-length")) {
            value = remove_whitespace(line);
            content_len = strtoul(value, 0, 10);
        } else if (!strcmp(key, "set-cookie")) {
            value = remove_whitespace(strsep(&line, ";"));
            print_cookie_report(value);
        } else if (!strcmp(key, "transfer-encoding") && strstr(str_to_lower(line), "chunked")) {
            chunked_field_flag = 1;
        }
        line = key;
    }
    free(line);
}

int parse_chunk(FILE *stream) {
    size_t chunk_content_len, len = 0;
    char *line = NULL;
    if (getline(&line, &len, stream) < 0) {
        free(line);
        return 1;
    }
    chunk_content_len = strtoul(remove_whitespace(line), 0, 16);
    free(line);

    if (!chunk_content_len || fseeko(stream, chunk_content_len + 2, SEEK_CUR) != 0) {
        return 1;
    }

    content_len += chunk_content_len;
    return 0;
}

void calc_chunk_content_length(FILE *stream) {
    content_len = 0;
    while (!parse_chunk(stream));
}

void print_content_length_report() {
    printf("Dlugosc zasobu: %lu\n", content_len);
}

int parse_response() {
    FILE *stream = fopen(BUFF_FILE, "rb");
    if (!stream)
        syserr("fopen");

    if (parse_status_line(stream) != 0) {
        fclose(stream);
        return 1;
    }
    parse_response_headers(stream);
    if (chunked_field_flag)
        calc_chunk_content_length(stream);

    fclose(stream);
    return 0;
}

int main(int argc, char *argv[]) {
    executable = argv[0];
    if (argc != 4)
        raise_err_usage();

    parse_connection_address(argv[1]);
    parse_host(argv[3]);

    connect_socket();

    write_to_host("GET /%.*s HTTP/1.1\r\n", (host_path ? strlen(host_path) : 0), host_path);
    write_to_host("Host: %s\r\n", host_addr);
    write_cookies_to_host(argv[2]);
    write_to_host("Connection: close\r\n\r\n");

    read_response();
    if (!parse_response())
        print_content_length_report();

    close(sock);
    return 0;
}
