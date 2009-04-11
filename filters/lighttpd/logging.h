/*
 * these are actually unused by lighttpd, but in order to re-use the common
 * cosign filter code, we need to have them defined. the lighttpd cosign_log
 * macro totally ignores them, since lighttpd's logging facility doesn't
 * provide log levels.
 */
#define APLOG_ERR	0
#define APLOG_NOTICE	1

void	cosign_log( int level, server *srv, char *fmt, ... );
