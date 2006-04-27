/*
 * Copyright (c) 2002 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

struct userinfo
{
	char	ui_login[ 131 ];
	char	ui_ipaddr[ 256 ];
	char	*ui_factors[ COSIGN_MAXFACTORS ];
};

struct login_param
{
    char	*lp_cookie;
    char	*lp_user;
    char	*lp_realm;
    char	*lp_ip;
    char	*lp_krb;

};

struct logout_param
{
    char	*lp_cookie;
    char	*lp_ip;	
};

struct reg_param
{
    char	*rp_cookie;
    char	*rp_ip;
    char	*rp_scookie;
};

struct check_param
{
    char		*cp_cookie;
    struct userinfo	*cp_ui;
};


int cosign_login( struct connlist *, char *, char *, char *, char *, char * );
int cosign_logout( struct connlist *, char *, char * );
int cosign_register( struct connlist *, char *, char *, char * );
int cosign_check( struct connlist *, char *, struct userinfo * );
int ssl_setup(char *, char *, char * );
