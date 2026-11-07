/* curl wrapper in C. 
  Called from main.cpp via extern "C". */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* data;
    size_t len;
    size_t cap;
} cbuf;

static size_t wr_cb(char* p, size_t s, size_t n, void* ud) {
    cbuf* b = (cbuf*)ud;
    size_t total = s * n;
    if (b->len + total + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + total + 1) nc *= 2;
        char* nd = (char*)realloc(b->data, nc);
        if (!nd) {
            /* OOM: make curl abort with CURLE_WRITE_ERROR instead of
             * silently reporting a successful HTTP 0 response. */
            b->cap = (size_t)-1;
            return 0;
        }
        b->data = nd;
        b->cap = nc;
    }
    memcpy(b->data + b->len, p, total);
    b->len += total;
    b->data[b->len] = 0;
    return total;
}

/* Returns 0 on success (curl code in *status is HTTP code), else curl code.
 * *out is set to an owned buffer (free() it). */
int http_req(const char* url, const char* body, const char* token,
             char** out, long* status) {
    cbuf b = {0, 0, 0};
    CURL* h = curl_easy_init();
    if (!h) return 1;
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wr_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "okhttp/4.10.0");
    if (getenv("QIUI_CURL_DEBUG"))
        curl_easy_setopt(h, CURLOPT_VERBOSE, 1L);
    struct curl_slist* hdrs = NULL;
    char* tok_hdr = NULL;  /* slist stores the pointer; free after perform */
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json; charset=utf-8");
    if (token && *token) {
        size_t n = strlen(token);
        tok_hdr = (char*)malloc(n + sizeof "token: ");
        if (tok_hdr) {
            snprintf(tok_hdr, n + sizeof "token: ", "token: %s", token);
            hdrs = curl_slist_append(hdrs, tok_hdr);
        } else {
            fprintf(stderr, "[!] OOM building token header; request will be unauthenticated\n");
        }
    }
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    if (body) {
        curl_easy_setopt(h, CURLOPT_POST, 1L);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }
    CURLcode rc = curl_easy_perform(h);
    if (rc == CURLE_OK && b.cap == (size_t)-1) rc = CURLE_WRITE_ERROR;
    long code = 0;
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
    *status = code;
    *out = b.data ? b.data : strdup("");
    free(tok_hdr);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
    return (rc == CURLE_OK) ? 0 : (int)rc;
}
