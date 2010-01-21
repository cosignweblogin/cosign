struct subfile_list {
    char	sl_letter;
    int		sl_type;
    char	*sl_data;
};

#define SUBF_STR	1
#define SUBF_STR_ESC	2

#define SUBF_OPT_DEFAULTS	0
#define SUBF_OPT_NOCACHE	(1<<0)
#define SUBF_OPT_SETSTATUS	(1<<1)
#define SUBF_OPT_LOG		(1<<2)
#define SUBF_OPT_ERROR		(SUBF_OPT_SETSTATUS | SUBF_OPT_LOG)

void subfile( char *, struct subfile_list *, int, ... );
