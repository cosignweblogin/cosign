cron:
    The included script will delete any file in
    /var/cosign/(filter|daemon) that is older than a day. If you change
    the location of either the filter database or the cosign
    database, the path this script uses will need to be updated
    appropriately.

    also, located in daemon/, is a program called "monster". This is a
    more agressive cookie and ticket removal program. The default idle
    time is 90 minutes, meaning it removes all cookies that are
    a) logged out at the time it runs or b) have not been used in the
    last 90 minutes. You can set the idle time out to be an arbitrary
    number of seconds e.g. "monster -i 6000" .

logout:
    The scripts directory contains scripts that might be useful when
    running a cosign weblogin server or authentication filter.

    The scripts in 'logout' do not replace the central logout cgi (
    that runs on the weblogin server ) but are intended to run on
    authentication filter hosts ( clients of the central weblogin
    server ).  These scripts expire and nullify the service's cosign
    cookie, provide an opportunity for local session cleanup, and
    redirect the user to the central logout cgi ( where he or she may
    choose to terminate the cosign session ).  This eliminates the
    problem of logged out users backing up to an authenticated site
    before the site's local cookie cache has expired.

    These logout scripts are not intended to present any html to the
    user.  You should, however, make allowances for appropriate error
    screens if your session cleanup is somehow destructive ( e.g. there
    are unsaved changes pending ).

startup:

