struct subfile_list {
    char	sl_letter;
    int		sl_type;
    char	*sl_data;
};

#define SUBF_STR	1
#define SUBF_STR_ESC	2

void subfile( char *, struct subfile_list *, int );
