/* Header-free Linux BPF ABI declarations; no build-host kernel headers needed. */
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_SOCKHASH 18
#define SK_PASS 1

/* Only the first ABI field is accessed by these programs. */
struct __sk_buff {
    u32 len;
};

struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

struct bpf_map_def SEC("maps") sockets = {
    BPF_MAP_TYPE_SOCKHASH, sizeof(u64), sizeof(u32), 65536, 0,
};

/* Redirect destinations are registered before attaching either source socket. */
struct bpf_map_def SEC("maps") targets = {
    BPF_MAP_TYPE_SOCKHASH, sizeof(u64), sizeof(u32), 65536, 0,
};

struct relay_counters {
    u64 bytes;
    u64 errors;
};

struct bpf_map_def SEC("maps") counters = {
    BPF_MAP_TYPE_HASH, sizeof(u64), sizeof(struct relay_counters), 65536, 0,
};

/* Both keys and values are SO_COOKIE values, not reusable file descriptors. */
struct bpf_map_def SEC("maps") peers = {
    BPF_MAP_TYPE_HASH, sizeof(u64), sizeof(u64), 65536, 0,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static u64 (*bpf_get_socket_cookie)(struct __sk_buff *skb) = (void *)46;
static long (*bpf_sk_redirect_hash)(struct __sk_buff *skb, void *map,
                                   const void *key, u64 flags) = (void *)72;

SEC("sk_skb/stream_parser")
int relay_parser(struct __sk_buff *skb)
{
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int relay_verdict(struct __sk_buff *skb)
{
    u64 cookie = bpf_get_socket_cookie(skb);
    u64 *peer = bpf_map_lookup_elem(&peers, &cookie);

    /* Inactive sockets keep their normal userspace receive path. */
    if (!peer)
        return SK_PASS;

    /* Capture length before the redirect helper; count admission, not delivery. */
    u64 len = skb->len;
    struct relay_counters *count = bpf_map_lookup_elem(&counters, &cookie);

    /* flags=0 redirects to the peer's egress, not its ingress queue. */
    long verdict = bpf_sk_redirect_hash(skb, &targets, peer, 0);
    if (count) {
        if (verdict == SK_PASS)
            __sync_fetch_and_add(&count->bytes, len);
        else
            __sync_fetch_and_add(&count->errors, 1);
    }
    return verdict;
}

char SEC("license") relay_license[] = "GPL";
