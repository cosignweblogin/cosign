/*
 *
 * banner from cosignd 2.x to 3.0.x:
 *
 * "220 2 Collaborative Web Single Sign-On"
 *
 * banner from cosignd 3.1+:
 *
 * "220 2 Collaborative Web Single Sign-On [COSIGNv3 FACTORS=N REKEY ...]"
 *
 * 
 */
struct capability {
    char		*capa_name;
    unsigned int	capa_nlen;
    unsigned int	capa_mask;
    int			(*capa_cb)( int, char *, int, void * );
};

#define COSIGN_CAPA_DEFAULTS	0
#define COSIGN_CAPA_FACTORS	(1<<0)
#define COSIGN_CAPA_REKEY	(1<<1)

#define COSIGN_CONN_SUPPORTS_FACTORS(c)	((c)->conn_capa & COSIGN_CAPA_FACTORS)
#define COSIGN_CONN_SUPPORTS_REKEY(c)	((c)->conn_capa & COSIGN_CAPA_REKEY)

#define COSIGN_PROTO_V0		0
#define COSIGN_PROTO_V2		2
#define COSIGN_PROTO_V3		3

#define COSIGN_PROTO_FACTORS	COSIGN_PROTO_V2
#define COSIGN_PROTO_REKEY	COSIGN_PROTO_V3
#define COSIGN_PROTO_CURRENT	COSIGN_PROTO_V3

#define COSIGN_PROTO_MIN_REQUIRED(p, v) \
			((p) >= (v) && (p) <= COSIGN_PROTO_CURRENT)
#define COSIGN_PROTO_SUPPORTS_REKEY(p) \
			COSIGN_PROTO_MIN_REQUIRED((p), COSIGN_PROTO_REKEY)
#define COSIGN_PROTO_SUPPORTS_FACTORS(p) \
			COSIGN_PROTO_MIN_REQUIRED((p), COSIGN_PROTO_FACTORS)
