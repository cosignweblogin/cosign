struct uservarlist;

int cosign_login_krb5( struct connlist *, char *, char *, char *, char *, char *, char *, struct subparams *, char **, struct uservarlist *  );
int cosign_login_mysql( struct connlist *, char *, char *, char *, char *, char *, char *, struct subparams *, char **, struct uservarlist *  );
int cosign_login_pam( struct connlist *, char *, char *, char *, char *, char *, char *, struct subparams *, char **, struct uservarlist *  );
