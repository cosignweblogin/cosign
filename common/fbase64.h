#define SZ_FBASE64_E( x )	(((x)+2)/3*4+1)
#define SZ_FBASE64_D( x )	(((x)*3)/4)

void	fbase64_e( unsigned char *, int, char * );
void	fbase64_d( char *, int, unsigned char * );
