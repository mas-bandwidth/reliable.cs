/*
    compat.c — the C half of the cross-implementation interop gate.

    Built directly against the real reliable.c (clone of mas-bandwidth/reliable,
    pinned to a release tag in CI). Its C# twin is ../Compat.cs. Both emit the
    exact same text for the same mode+seed; scripts/interop.sh diffs them, and any
    byte of difference fails the gate.

    Modes:
      vectors                          wire vectors: packet header sweep (fixed
                                       corners + 1000 PRNG triples), fragment
                                       layouts for a spread of payload sizes.
                                       every header is also decoded and re-encoded
                                       here as a self check.
      scenario <profile> <seed> <n>    two endpoints exchange traffic for n
                                       iterations across a scripted link driven by
                                       a shared deterministic PRNG (xorshift64*).
                                       profiles: clean | lossy |
                                       hostile | wrap (crosses the 16 bit
                                       sequence wrap).
                                       the trace records every transmit, every
                                       processed packet (FNV-1a 64 of the bytes),
                                       per-iteration acks, and periodic + final
                                       counters and stats (float bit patterns).
      empty_packet                     one receiver, six inputs in order: a
                                       zero-length packet, {0}, {1},
                                       max_packet_size+14 zero bytes, one byte
                                       more than that, then a valid packet from
                                       a sender. each line is the input, whether
                                       it was refused, whether the process
                                       callback ran, and the eleven counters.

    All randomness comes from the shared PRNG in an exactly specified draw order;
    the C# side replicates it draw for draw. rand() is never used.
*/

#include "reliable.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* internal functions of reliable.c with external linkage */
int reliable_write_packet_header( uint8_t * packet_data, uint16_t sequence, uint16_t ack, uint32_t ack_bits );
int reliable_read_packet_header( const char * name, uint8_t * packet_data, int packet_bytes, uint16_t * sequence, uint16_t * ack, uint32_t * ack_bits );

/* ---------------------------------------------------------------- */
/* shared deterministic PRNG: xorshift64* (identical in Compat.cs)  */

static uint64_t rng_state;

static void rng_seed( uint64_t seed )
{
    rng_state = seed ? seed : 0x9E3779B97F4A7C15ull;
}

static uint64_t rng_next( void )
{
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static uint32_t rng_u32( void )
{
    return (uint32_t) ( rng_next() >> 32 );
}

/* inclusive range. draw order is part of the shared spec: exactly one rng_u32 per call */
static int rng_int( int a, int b )
{
    return a + (int) ( rng_u32() % (uint32_t) ( b - a + 1 ) );
}

/* ---------------------------------------------------------------- */
/* FNV-1a 64 over packet bytes (identical in Compat.cs)             */

static uint64_t fnv1a64( const uint8_t * data, int bytes )
{
    uint64_t hash = 14695981039346656037ull;
    for ( int i = 0; i < bytes; i++ )
    {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static void print_hex( const uint8_t * data, int bytes )
{
    for ( int i = 0; i < bytes; i++ )
        printf( "%02x", data[i] );
}

/* ---------------------------------------------------------------- */
/* vectors mode                                                     */

static void emit_header_vector( uint16_t sequence, uint16_t ack, uint32_t ack_bits )
{
    uint8_t buffer[16];
    memset( buffer, 0, sizeof( buffer ) );
    int bytes = reliable_write_packet_header( buffer, sequence, ack, ack_bits );

    /* self check: decode and re-encode must round trip exactly */
    uint16_t read_sequence, read_ack;
    uint32_t read_ack_bits;
    int read_bytes = reliable_read_packet_header( "vectors", buffer, bytes, &read_sequence, &read_ack, &read_ack_bits );
    if ( read_bytes != bytes || read_sequence != sequence || read_ack != ack || read_ack_bits != ack_bits )
    {
        printf( "SELFCHECK-FAILED HDR %u %u %u\n", sequence, ack, ack_bits );
        exit( 1 );
    }

    printf( "HDR %u %u %u ", sequence, ack, ack_bits );
    print_hex( buffer, bytes );
    printf( "\n" );
}

static int vectors_frag_count;

static void vectors_transmit( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence;
    printf( "FRAG %d %d ", vectors_frag_count++, packet_bytes );
    print_hex( packet_data, packet_bytes );
    printf( "\n" );
}

static int vectors_process( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence; (void) packet_data; (void) packet_bytes;
    return 1;
}

static void run_vectors( void )
{
    /* the elision-rule corners (same values as the C repo's conformance generator) */
    static const uint16_t seqs[] = { 0, 1, 255, 256, 1000, 32768, 65535, 7 };
    static const uint16_t acks[] = { 0, 1, 254, 255, 256, 999, 65535, 32760 };
    static const uint32_t bits[] = { 0xFFFFFFFFu, 0x00000000u, 0xFFFFFF00u, 0x00FFFFFFu,
                                     0xDEADBEEFu, 0xFF00FF00u, 0x000000FFu, 0xFFFF00FFu };

    for ( int a = 0; a < 8; a++ )
        for ( int b = 0; b < 8; b++ )
            for ( int c = 0; c < 8; c++ )
                emit_header_vector( seqs[a], acks[b], bits[c] );

    /* 1000 PRNG triples across the whole space */
    rng_seed( 0x1234567855AA55AAull );
    for ( int i = 0; i < 1000; i++ )
    {
        uint16_t sequence = (uint16_t) rng_u32();
        uint16_t ack = (uint16_t) rng_u32();
        uint32_t ack_bits = rng_u32();
        emit_header_vector( sequence, ack, ack_bits );
    }

    /* fragment layouts: one endpoint, several payload sizes around the corners */
    static const int payload_sizes[] = { 501, 999, 1000, 1001, 1500, 2200, 4000, 7999, 8000 };

    struct reliable_config_t config;
    reliable_default_config( &config );
    reliable_copy_string( config.name, "vectors", sizeof( config.name ) );
    config.max_packet_size = 8000;
    config.fragment_above = 500;
    config.fragment_size = 1000;
    config.max_fragments = 8;
    config.transmit_packet_function = vectors_transmit;
    config.process_packet_function = vectors_process;

    struct reliable_endpoint_t * endpoint = reliable_endpoint_create( &config, 100.0 );

    for ( int s = 0; s < (int) ( sizeof( payload_sizes ) / sizeof( payload_sizes[0] ) ); s++ )
    {
        int payload_bytes = payload_sizes[s];
        uint8_t payload[8192];
        uint16_t sequence = reliable_endpoint_next_packet_sequence( endpoint );
        payload[0] = (uint8_t) ( sequence & 0xFF );
        payload[1] = (uint8_t) ( ( sequence >> 8 ) & 0xFF );
        for ( int i = 2; i < payload_bytes; i++ )
            payload[i] = (uint8_t) ( ( i + sequence ) % 256 );
        printf( "FRAGSET %d %d\n", (int) sequence, payload_bytes );
        vectors_frag_count = 0;
        reliable_endpoint_send_packet( endpoint, payload, payload_bytes );
    }

    reliable_endpoint_destroy( endpoint );
}

/* ---------------------------------------------------------------- */
/* malformed mode                                                   */

/* one hostile / boundary input per checklist item 5: zero length, oversize,
   truncated headers, bad fragment counts. each vector is fed to a fresh
   endpoint; the line reports what the endpoint did and the eleven counters.
   the C# twin is Reliable.Compat.Program.RunMalformed. identical text. */

#define MALFORMED_MAX_PACKET 100

static const char * counter_names[11] =
{
    "sent", "received", "acked", "stale", "invalid",
    "too_large_send", "too_large_receive", "fragments_sent",
    "fragments_received", "fragments_invalid", "duplicate",
};

static uint16_t malformed_delivered_sequence;
static int malformed_delivered_length;
static int malformed_delivered;

static int malformed_process( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) packet_data;
    malformed_delivered = 1;
    malformed_delivered_sequence = sequence;
    malformed_delivered_length = packet_bytes;
    return 1;
}

static void malformed_transmit( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence; (void) packet_data; (void) packet_bytes;
}

static void run_malformed( void )
{
    struct reliable_config_t config;
    reliable_default_config( &config );
    reliable_copy_string( config.name, "malformed", sizeof( config.name ) );
    config.max_packet_size = MALFORMED_MAX_PACKET;
    config.fragment_above = 50;
    config.fragment_size = 50;
    config.max_fragments = 16;
    config.transmit_packet_function = malformed_transmit;
    config.process_packet_function = malformed_process;

    uint8_t oversize[MALFORMED_MAX_PACKET + 16];
    memset( oversize, 0, sizeof( oversize ) );

    const struct { const uint8_t * data; int bytes; const char * label; } vectors[] =
    {
        { (const uint8_t *) "",              0,  "zero-length" },
        { oversize,                          sizeof( oversize ), "oversize" },
        { (const uint8_t *) "\x00",           1,  "prefix-only" },
        { (const uint8_t *) "\x00\x01",       2,  "seq-truncated" },
        { (const uint8_t *) "\x20\x01\x02",   3,  "ack-diff-missing" },
        { (const uint8_t *) "\x01\x00\x01",   3,  "fragment-short" },
        { (const uint8_t *) "\x01\x00\x00\x05\x02", 5, "fragment-id-range" },
        { (const uint8_t *) "\x01\x00\x00\x00\xFF", 5, "fragment-too-many" },
        { (const uint8_t *) "\x01\x00\x00\x00\x00", 5, "fragment-no-header" },
        { (const uint8_t *) "\x00\x00\x00\x00\x00", 5, "valid-minimal" },
    };

    int num_vectors = (int) ( sizeof( vectors ) / sizeof( vectors[0] ) );

    for ( int n = 0; n < num_vectors; n++ )
    {
        struct reliable_endpoint_t * endpoint = reliable_endpoint_create( &config, 100.0 );
        RELIABLE_CONST uint64_t * counters = reliable_endpoint_counters( endpoint );

        uint64_t before[RELIABLE_ENDPOINT_NUM_COUNTERS];
        for ( int i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; i++ )
            before[i] = counters[i];

        malformed_delivered = 0;
        malformed_delivered_sequence = 0;
        malformed_delivered_length = 0;

        reliable_endpoint_receive_packet( endpoint, (uint8_t *) vectors[n].data, vectors[n].bytes );

        const char * changed = "none";
        for ( int i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; i++ )
        {
            if ( counters[i] != before[i] )
            {
                changed = counter_names[i];
                break;
            }
        }

        printf( "%d %s %s ", n, malformed_delivered ? "accepted" : "refused", changed );
        if ( malformed_delivered )
            printf( "%u %d", malformed_delivered_sequence, malformed_delivered_length );
        else
            printf( "-" );
        for ( int i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; i++ )
            printf( " %" PRIu64, counters[i] );
        printf( "\n" );

        reliable_endpoint_destroy( endpoint );
    }
}

/* ---------------------------------------------------------------- */
/* empty_packet mode                                                */

/* one receiver, six inputs, in order: a zero-length packet, a one-byte
   packet {0}, a one-byte packet {1}, max_packet_size + 14 zero bytes, one
   byte more than that, then a valid packet from a sender. each line is
   <input> <refused|accepted> <process callback ran 0|1> <eleven counters>.
   counters accumulate on that same receiver. the C# twin is RunEmptyPacket.
   identical text. */

static int empty_process_ran;
static uint8_t empty_sent[64];
static int empty_sent_bytes;

static int empty_process( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence; (void) packet_data; (void) packet_bytes;
    empty_process_ran = 1;
    return 1;
}

static int empty_process_ignore( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence; (void) packet_data; (void) packet_bytes;
    return 1;
}

static void empty_transmit_ignore( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence; (void) packet_data; (void) packet_bytes;
}

static void empty_transmit_capture( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence;
    if ( packet_bytes <= 0 || packet_bytes > (int) sizeof( empty_sent ) )
    {
        fprintf( stderr, "empty_packet: sent packet does not fit (%d)\n", packet_bytes );
        exit( 1 );
    }
    memcpy( empty_sent, packet_data, (size_t) packet_bytes );
    empty_sent_bytes = packet_bytes;
}

static void empty_print( const char * label, struct reliable_endpoint_t * endpoint )
{
    RELIABLE_CONST uint64_t * counters = reliable_endpoint_counters( endpoint );
    printf( "%s %s %d", label, empty_process_ran ? "accepted" : "refused", empty_process_ran );
    int i;
    for ( i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; i++ )
        printf( " %" PRIu64, counters[i] );
    printf( "\n" );
}

static void empty_feed( const char * label, struct reliable_endpoint_t * endpoint, uint8_t * data, int bytes )
{
    empty_process_ran = 0;
    reliable_endpoint_receive_packet( endpoint, data, bytes );
    empty_print( label, endpoint );
}

static void run_empty_packet( void )
{
    struct reliable_config_t receiver_config;
    reliable_default_config( &receiver_config );
    reliable_copy_string( receiver_config.name, "receiver", sizeof( receiver_config.name ) );
    receiver_config.transmit_packet_function = empty_transmit_ignore;
    receiver_config.process_packet_function = empty_process;

    struct reliable_config_t sender_config;
    reliable_default_config( &sender_config );
    reliable_copy_string( sender_config.name, "sender", sizeof( sender_config.name ) );
    sender_config.transmit_packet_function = empty_transmit_capture;
    sender_config.process_packet_function = empty_process_ignore;

    struct reliable_endpoint_t * receiver = reliable_endpoint_create( &receiver_config, 0.0 );
    struct reliable_endpoint_t * sender = reliable_endpoint_create( &sender_config, 0.0 );
    if ( !receiver || !sender )
    {
        fprintf( stderr, "empty_packet: endpoint create failed\n" );
        exit( 1 );
    }

    int max_packet_size = receiver_config.max_packet_size;
    int limit = max_packet_size + RELIABLE_MAX_PACKET_HEADER_BYTES + RELIABLE_FRAGMENT_HEADER_BYTES;
    uint8_t * zeros = (uint8_t *) calloc( (size_t) limit + 1, 1 );
    if ( !zeros )
    {
        fprintf( stderr, "empty_packet: out of memory\n" );
        exit( 1 );
    }

    uint8_t sentinel = 0x2A;
    empty_feed( "zero-length", receiver, &sentinel, 0 );

    uint8_t byte0 = 0;
    empty_feed( "byte-0", receiver, &byte0, 1 );

    uint8_t byte1 = 1;
    empty_feed( "byte-1", receiver, &byte1, 1 );

    empty_feed( "max-plus-14", receiver, zeros, limit );
    empty_feed( "max-plus-15", receiver, zeros, limit + 1 );

    uint8_t payload = 0x11;
    empty_sent_bytes = 0;
    reliable_endpoint_send_packet( sender, &payload, 1 );
    if ( empty_sent_bytes <= 0 )
    {
        fprintf( stderr, "empty_packet: sender produced no packet\n" );
        exit( 1 );
    }
    empty_feed( "valid", receiver, empty_sent, empty_sent_bytes );

    free( zeros );
    reliable_endpoint_destroy( receiver );
    reliable_endpoint_destroy( sender );
}

/* ---------------------------------------------------------------- */
/* scenario mode                                                    */

#define MAX_QUEUE 8192
#define SCENARIO_MAX_PACKET_BYTES 9000

struct queued_packet_t
{
    uint8_t * data;
    int bytes;
};

struct link_t
{
    struct queued_packet_t packets[MAX_QUEUE];
    int num_packets;
};

struct scenario_t
{
    struct reliable_endpoint_t * a;
    struct reliable_endpoint_t * b;
    struct link_t a_to_b;
    struct link_t b_to_a;
    int loss_pct;
    int corrupt_pct;
    int duplicate_pct;
    int inject;
    int process_reject_pct;
    int warp_sends;
};

static struct scenario_t scenario;

static int hex_dump_payloads = 0;
static int quiet = 0;

static void link_queue( struct link_t * link, const uint8_t * data, int bytes )
{
    if ( link->num_packets == MAX_QUEUE || bytes <= 0 )
        return;
    uint8_t * copy = (uint8_t*) malloc( bytes );
    memcpy( copy, data, bytes );
    link->packets[link->num_packets].data = copy;
    link->packets[link->num_packets].bytes = bytes;
    link->num_packets++;
}

static void link_clear( struct link_t * link )
{
    for ( int i = 0; i < link->num_packets; i++ )
        free( link->packets[i].data );
    link->num_packets = 0;
}

/* draw order per flush: fisher-yates (one draw per swap, i from n-1 down to 1),
   then per packet in post-shuffle order: loss draw; if lost, nothing more; else
   corrupt draw (+ position and bit draws only when corrupting), then duplicate
   draw. identical in Compat.cs. */
static void link_flush( struct link_t * link, struct reliable_endpoint_t * to )
{
    for ( int i = link->num_packets - 1; i > 0; i-- )
    {
        int j = rng_int( 0, i );
        struct queued_packet_t tmp = link->packets[i];
        link->packets[i] = link->packets[j];
        link->packets[j] = tmp;
    }

    for ( int i = 0; i < link->num_packets; i++ )
    {
        uint8_t * data = link->packets[i].data;
        int bytes = link->packets[i].bytes;

        if ( scenario.loss_pct > 0 && rng_int( 0, 99 ) < scenario.loss_pct )
            continue;

        if ( scenario.corrupt_pct > 0 && rng_int( 0, 99 ) < scenario.corrupt_pct )
        {
            /* two sequenced statements: the index/bit draw order is part of the
               shared spec, and an expression with two rng calls has unspecified
               evaluation order in C */
            int corrupt_index = rng_int( 0, bytes - 1 );
            int corrupt_bit = rng_int( 0, 7 );
            data[corrupt_index] ^= (uint8_t) ( 1 << corrupt_bit );
        }

        int copies = ( scenario.duplicate_pct > 0 && rng_int( 0, 99 ) < scenario.duplicate_pct ) ? 2 : 1;
        for ( int c = 0; c < copies; c++ )
        {
            if ( hex_dump_payloads )
                printf( "R %016" PRIx64 " %d\n", fnv1a64( data, bytes ), bytes );
            reliable_endpoint_receive_packet( to, data, bytes );
        }
    }

    link_clear( link );
}

static void scenario_transmit( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    if ( !quiet )
        printf( "T %c %u %d %016" PRIx64 "\n", id == 0 ? 'A' : 'B', sequence, packet_bytes, fnv1a64( packet_data, packet_bytes ) );
    if ( id == 0 )
        link_queue( &scenario.a_to_b, packet_data, packet_bytes );
    else
        link_queue( &scenario.b_to_a, packet_data, packet_bytes );
}

static int scenario_process( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    if ( quiet )
        return 1;
    int accept = 1;
    if ( scenario.process_reject_pct > 0 && rng_int( 0, 99 ) < scenario.process_reject_pct )
        accept = 0;
    printf( "P %c %u %d %016" PRIx64 " %d", id == 0 ? 'A' : 'B', sequence, packet_bytes, fnv1a64( packet_data, packet_bytes ), accept );
    if ( hex_dump_payloads )
    {
        printf( " " );
        print_hex( packet_data, packet_bytes );
    }
    printf( "\n" );
    return accept;
}

static uint32_t float_bits( float value )
{
    uint32_t bits;
    memcpy( &bits, &value, 4 );
    return bits;
}

static void print_endpoint_state( const char * tag, struct reliable_endpoint_t * endpoint )
{
    RELIABLE_CONST uint64_t * counters = reliable_endpoint_counters( endpoint );
    printf( "C %s", tag );
    for ( int i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; i++ )
        printf( " %" PRIu64, counters[i] );
    printf( "\n" );

    float sent_bw, received_bw, acked_bw;
    reliable_endpoint_bandwidth( endpoint, &sent_bw, &received_bw, &acked_bw );
    printf( "S %s %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
        tag,
        float_bits( reliable_endpoint_rtt( endpoint ) ),
        float_bits( reliable_endpoint_rtt_min( endpoint ) ),
        float_bits( reliable_endpoint_rtt_max( endpoint ) ),
        float_bits( reliable_endpoint_rtt_avg( endpoint ) ),
        float_bits( reliable_endpoint_jitter_avg_vs_min_rtt( endpoint ) ),
        float_bits( reliable_endpoint_jitter_max_vs_min_rtt( endpoint ) ),
        float_bits( reliable_endpoint_jitter_stddev_vs_avg_rtt( endpoint ) ),
        float_bits( reliable_endpoint_packet_loss( endpoint ) ),
        float_bits( sent_bw ),
        float_bits( received_bw ),
        float_bits( acked_bw ) );
}

static void run_scenario( const char * profile, uint64_t seed, int iterations )
{
    memset( &scenario, 0, sizeof( scenario ) );

    if ( strcmp( profile, "clean" ) == 0 )
    {
        /* everything arrives, possibly reordered */
    }
    else if ( strcmp( profile, "lossy" ) == 0 )
    {
        scenario.loss_pct = 10;
        scenario.duplicate_pct = 5;
        scenario.process_reject_pct = 2;
    }
    else if ( strcmp( profile, "wrap" ) == 0 )
    {
        /* lossy link, but first both endpoints are quietly warped to sequence
           ~64900 so the traced phase crosses the 16 bit wrap */
        scenario.loss_pct = 10;
        scenario.duplicate_pct = 5;
        scenario.process_reject_pct = 2;
        scenario.warp_sends = 64900;
    }
    else if ( strcmp( profile, "hostile" ) == 0 )
    {
        scenario.loss_pct = 10;
        scenario.corrupt_pct = 20;
        scenario.duplicate_pct = 5;
        scenario.inject = 1;
        scenario.process_reject_pct = 2;
    }
    else
    {
        fprintf( stderr, "unknown profile: %s\n", profile );
        exit( 2 );
    }

    rng_seed( seed );

    struct reliable_config_t config;
    reliable_default_config( &config );
    config.max_packet_size = 8000;
    config.fragment_above = 500;
    config.fragment_size = 500;
    config.max_fragments = 16;
    config.transmit_packet_function = scenario_transmit;
    config.process_packet_function = scenario_process;

    double time = 100.0;

    reliable_copy_string( config.name, "a", sizeof( config.name ) );
    config.id = 0;
    scenario.a = reliable_endpoint_create( &config, time );

    reliable_copy_string( config.name, "b", sizeof( config.name ) );
    config.id = 1;
    scenario.b = reliable_endpoint_create( &config, time );

    printf( "SCENARIO %s %" PRIu64 " %d\n", profile, seed, iterations );

    uint8_t payload[SCENARIO_MAX_PACKET_BYTES];

    /* warp phase: tiny packets, delivered verbatim in queue order, nothing
       traced, no PRNG draws, no update. both halves implement this
       identically; the traced phase then starts near the sequence wrap. */
    if ( scenario.warp_sends > 0 )
    {
        quiet = 1;
        uint8_t tiny[1] = { 0 };
        for ( int i = 0; i < scenario.warp_sends; i++ )
        {
            reliable_endpoint_send_packet( scenario.a, tiny, 1 );
            reliable_endpoint_send_packet( scenario.b, tiny, 1 );
            for ( int j = 0; j < scenario.a_to_b.num_packets; j++ )
                reliable_endpoint_receive_packet( scenario.b, scenario.a_to_b.packets[j].data, scenario.a_to_b.packets[j].bytes );
            for ( int j = 0; j < scenario.b_to_a.num_packets; j++ )
                reliable_endpoint_receive_packet( scenario.a, scenario.b_to_a.packets[j].data, scenario.b_to_a.packets[j].bytes );
            link_clear( &scenario.a_to_b );
            link_clear( &scenario.b_to_a );
            reliable_endpoint_clear_acks( scenario.a );
            reliable_endpoint_clear_acks( scenario.b );
        }
        quiet = 0;
    }

    for ( int iteration = 0; iteration < iterations; iteration++ )
    {
        /* one packet per endpoint per iteration. size class draw, then size draw. */
        for ( int side = 0; side < 2; side++ )
        {
            struct reliable_endpoint_t * endpoint = side == 0 ? scenario.a : scenario.b;
            int size_class = rng_int( 0, 99 );
            int payload_bytes;
            if ( size_class < 50 )
                payload_bytes = rng_int( 1, 400 );          /* unfragmented */
            else if ( size_class < 95 )
                payload_bytes = rng_int( 401, 4000 );       /* fragmented */
            else
                payload_bytes = rng_int( 8001, 9000 );      /* too large: dropped + counted */

            uint16_t sequence = reliable_endpoint_next_packet_sequence( endpoint );
            payload[0] = (uint8_t) ( sequence & 0xFF );
            if ( payload_bytes > 1 )
                payload[1] = (uint8_t) ( ( sequence >> 8 ) & 0xFF );
            for ( int i = 2; i < payload_bytes; i++ )
                payload[i] = (uint8_t) ( ( i + sequence ) % 256 );

            reliable_endpoint_send_packet( endpoint, payload, payload_bytes );
        }

        link_flush( &scenario.a_to_b, scenario.b );
        link_flush( &scenario.b_to_a, scenario.a );

        if ( scenario.inject )
        {
            for ( int side = 0; side < 2; side++ )
            {
                struct reliable_endpoint_t * endpoint = side == 0 ? scenario.a : scenario.b;
                int inject_bytes = rng_int( 1, 2000 );
                for ( int i = 0; i < inject_bytes; i++ )
                    payload[i] = (uint8_t) rng_int( 0, 255 );
                reliable_endpoint_receive_packet( endpoint, payload, inject_bytes );
            }
        }

        reliable_endpoint_update( scenario.a, time );
        reliable_endpoint_update( scenario.b, time );

        int num_acks;
        uint16_t * acks;

        acks = reliable_endpoint_get_acks( scenario.a, &num_acks );
        printf( "A A" );
        for ( int i = 0; i < num_acks; i++ )
            printf( " %u", acks[i] );
        printf( "\n" );

        acks = reliable_endpoint_get_acks( scenario.b, &num_acks );
        printf( "A B" );
        for ( int i = 0; i < num_acks; i++ )
            printf( " %u", acks[i] );
        printf( "\n" );

        reliable_endpoint_clear_acks( scenario.a );
        reliable_endpoint_clear_acks( scenario.b );

        if ( ( iteration % 100 ) == 99 )
        {
            print_endpoint_state( "A", scenario.a );
            print_endpoint_state( "B", scenario.b );
        }

        time += 0.016;
    }

    printf( "FINAL\n" );
    print_endpoint_state( "A", scenario.a );
    print_endpoint_state( "B", scenario.b );

    link_clear( &scenario.a_to_b );
    link_clear( &scenario.b_to_a );
    reliable_endpoint_destroy( scenario.a );
    reliable_endpoint_destroy( scenario.b );
}

/* ---------------------------------------------------------------- */
/* fragment_window mode                                             */
/*
    Differential pins for the fragment / received-window fix (C PR 68).

    A lone fragment must not move the received-packet window: only an accepted
    packet may. The crafted sequences of the C fix's cases A (512), B (32512)
    and C (an in-order fragmented packet at 0) are fed, each followed by a
    genuine sequence 0, both to a cold receiver and to one already advanced to
    1000, with a lone last fragment carrying zero and one payload byte. One
    line per input, byte for byte identical to Compat.cs.
*/

static int fw_delivered;
static uint16_t fw_delivered_sequence;
static int fw_delivered_length;

static int fw_process( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) packet_data;
    fw_delivered = 1;
    fw_delivered_sequence = sequence;
    fw_delivered_length = packet_bytes;
    return 1;
}

static void fw_transmit( void * context, uint64_t id, uint16_t sequence, uint8_t * packet_data, int packet_bytes )
{
    (void) context; (void) id; (void) sequence; (void) packet_data; (void) packet_bytes;
}

static struct reliable_endpoint_t * fw_endpoint( void )
{
    struct reliable_config_t config;
    reliable_default_config( &config );
    reliable_copy_string( config.name, "fragment_window", sizeof( config.name ) );
    config.max_packet_size = 8000;
    config.fragment_above = 500;
    config.fragment_size = 500;
    config.max_fragments = 16;
    config.transmit_packet_function = fw_transmit;
    config.process_packet_function = fw_process;
    return reliable_endpoint_create( &config, 100.0 );
}

/* a lone fragment: prefix 1, sequence LE, fragment id, count-1, then payload.
   fragment 0 embeds the canonical packet header, exactly like the sender. */
static int fw_build_fragment( uint8_t * buffer, uint16_t sequence, int fragment_id, int num_fragments, int payload_bytes )
{
    int p = 0;
    buffer[p++] = 1;
    buffer[p++] = (uint8_t) ( sequence & 0xFF );
    buffer[p++] = (uint8_t) ( sequence >> 8 );
    buffer[p++] = (uint8_t) fragment_id;
    buffer[p++] = (uint8_t) ( num_fragments - 1 );
    if ( fragment_id == 0 )
        p += reliable_write_packet_header( buffer + p, sequence, 0xFFFF, 0 );
    for ( int i = 0; i < payload_bytes; i++ )
        buffer[p++] = (uint8_t) ( i + sequence );
    return p;
}

static int fw_genuine_bytes( uint8_t * buffer )
{
    int h = reliable_write_packet_header( buffer, 0, 0xFFFF, 0 );
    buffer[h] = 0;
    return h + 1;
}

/* advance the receiver to sequence 1000 with genuine in-order packets */
static void fw_advance( struct reliable_endpoint_t * endpoint, int count )
{
    uint8_t packet[16];
    for ( int i = 0; i < count; i++ )
    {
        int h = reliable_write_packet_header( packet, (uint16_t) i, 0xFFFF, 0 );
        packet[h] = 0;
        reliable_endpoint_receive_packet( endpoint, packet, h + 1 );
    }
}

static void fw_report( const char * label, uint16_t sequence, int refused, struct reliable_endpoint_t * endpoint )
{
    RELIABLE_CONST uint64_t * counters = reliable_endpoint_counters( endpoint );
    printf( "%s %u %s %d", label, sequence, refused ? "refused" : "accepted", fw_delivered ? 1 : 0 );
    for ( int i = 0; i < RELIABLE_ENDPOINT_NUM_COUNTERS; i++ )
        printf( " %" PRIu64, counters[i] );
    printf( "\n" );
}

/* feed one fragment then a genuine sequence 0, and report the result */
static void fw_fragment_then_genuine( const char * label, struct reliable_endpoint_t * endpoint,
                                      uint16_t sequence, int fragment_id, int num_fragments, int payload_bytes )
{
    uint8_t fragment[600];
    int fragment_bytes = fw_build_fragment( fragment, sequence, fragment_id, num_fragments, payload_bytes );

    RELIABLE_CONST uint64_t * counters = reliable_endpoint_counters( endpoint );
    uint64_t before = counters[9]; /* fragments_invalid */

    fw_delivered = 0;
    fw_delivered_sequence = 0;
    fw_delivered_length = 0;

    reliable_endpoint_receive_packet( endpoint, fragment, fragment_bytes );

    int refused = counters[9] != before;

    uint8_t genuine[16];
    reliable_endpoint_receive_packet( endpoint, genuine, fw_genuine_bytes( genuine ) );

    fw_report( label, sequence, refused, endpoint );
}

static void run_fragment_window( void )
{
    /* case A: in-window lone last fragment, then genuine sequence 0 */
    {
        struct reliable_endpoint_t * endpoint = fw_endpoint();
        fw_fragment_then_genuine( "A", endpoint, 512, 1, 2, 0 );
        reliable_endpoint_destroy( endpoint );
    }

    /* case B: out-of-window lone last fragment, then genuine sequence 0 */
    {
        struct reliable_endpoint_t * endpoint = fw_endpoint();
        fw_fragment_then_genuine( "B", endpoint, 32512, 1, 2, 0 );
        reliable_endpoint_destroy( endpoint );
    }

    /* case C: in-order fragmented packet at sequence 0 (500 + 250 = 1.5 x
       fragment_size), then a genuine sequence 0 */
    {
        struct reliable_endpoint_t * endpoint = fw_endpoint();
        uint8_t fragment[600];
        int first = fw_build_fragment( fragment, 0, 0, 2, 500 );
        reliable_endpoint_receive_packet( endpoint, fragment, first );
        int second = fw_build_fragment( fragment, 0, 1, 2, 250 );
        reliable_endpoint_receive_packet( endpoint, fragment, second );
        uint8_t genuine[16];
        reliable_endpoint_receive_packet( endpoint, genuine, fw_genuine_bytes( genuine ) );
        fw_report( "C", 0, 0, endpoint );
        reliable_endpoint_destroy( endpoint );
    }

    /* scan: every boundary sequence as a lone last fragment with zero and one
       payload byte, cold and advanced to 1000 */
    static const uint16_t sequences[] =
    {
        0, 1, 255, 256, 511, 512, 513, 32511, 32512, 32513, 32768, 65280, 65535,
    };
    int num_sequences = (int) ( sizeof( sequences ) / sizeof( sequences[0] ) );

    for ( int i = 0; i < num_sequences; i++ )
    {
        for ( int advanced = 0; advanced < 2; advanced++ )
        {
            for ( int payload = 0; payload < 2; payload++ )
            {
                struct reliable_endpoint_t * endpoint = fw_endpoint();
                if ( advanced )
                    fw_advance( endpoint, 1000 );
                char label[8];
                snprintf( label, sizeof( label ), "%s%d", advanced ? "adv" : "cold", payload );
                fw_fragment_then_genuine( label, endpoint, sequences[i], 1, 2, payload );
                reliable_endpoint_destroy( endpoint );
            }
        }
    }
}

/* ---------------------------------------------------------------- */

int main( int argc, char ** argv )
{
    reliable_init();

    /* debugging aid for gate mismatches: dump full payload hex in P lines */
    if ( getenv( "RELIABLE_COMPAT_HEX" ) )
        hex_dump_payloads = 1;

    if ( argc >= 2 && strcmp( argv[1], "vectors" ) == 0 )
    {
        run_vectors();
    }
    else if ( argc >= 2 && strcmp( argv[1], "malformed" ) == 0 )
    {
        run_malformed();
    }
    else if ( argc >= 2 && strcmp( argv[1], "fragment_window" ) == 0 )
    {
        run_fragment_window();
    }
    else if ( argc >= 2 && strcmp( argv[1], "empty_packet" ) == 0 )
    {
        run_empty_packet();
    }
    else if ( argc >= 5 && strcmp( argv[1], "scenario" ) == 0 )
    {
        run_scenario( argv[2], strtoull( argv[3], NULL, 10 ), atoi( argv[4] ) );
    }
    else
    {
        fprintf( stderr, "usage: compat vectors | compat malformed | compat fragment_window | compat empty_packet | compat scenario <clean|lossy|hostile|wrap> <seed> <iterations>\n" );
        return 2;
    }

    reliable_term();

    return 0;
}
