#ifdef APXS2
#define cosign_log( level, server, ... )	ap_log_error( APLOG_MARK, (level)|APLOG_NOERRNO, 0, (server), __VA_ARGS__)
#else /* APXS 1 */
#define cosign_log( level, server, ... )	ap_log_error( APLOG_MARK, (level)|APLOG_NOERRNO, (server),  __VA_ARGS__)
#endif 
