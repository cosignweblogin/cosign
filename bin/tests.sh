#! /bin/sh

# run a series of sanity checks against cosignd and cosign.cgi.

die() {
    echo "ERROR: $*" 1>&2

    exit 2
}

ps_ef() {
    ps -ef >/dev/null && ps -ef && return
    ps auxww >/dev/null && ps auxww
}

mkdirs() {
    dirs="$*"

    for d in ${dirs}; do
	mkdir "${d}" 2>/dev/null || [ -d "${d}" ] || die "failed to mkdir ${d}"
    done
}

create_openssl_cnf() {
    cat > openssl.cnf <<EOF
[ ca ]
default_ca	= CA_default

[ CA_default ]
dir		= ./CA
database	= \$dir/index.txt
new_certs_dir	= \$dir/newcerts
certificate	= \$dir/private/cacert.pem
serial		= \$dir/serial
private_key	= \$dir/private/cakey.pem
RANDFILE	= \$dir/private/.rand

default_days	= 365
default_crl_days= 30
default_md	= sha1

policy		= policy_match

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = supplied

[ req ]
default_bits		= 1024
default_md		= sha1
distinguished_name	= req_distinguished_name

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = US
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = SomeState

localityName                    = Locality Name (eg, city)
localityName_default            = SomeCity

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = Cosign Test

organizationalUnitName          = Organizational Unit Name (eg, section)
#organizationalUnitName_default =

commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64

emailAddress                    = Email Address
emailAddress_max                = 64

EOF
}

req_answers() {
    echo "US"
    echo "Pandemonium"
    echo "Dis"
    echo "cosign"
    echo "cosign make tests"
}

req_email() {
    echo "cosign@localhost.localdomain"
}


ca_password() {
    echo "cosignmaketests.$$"
}

ca_commonname() {
    echo "cosign test CA"
}

# cribbed from openssl's make-dummy-cert
ca_answers() {
    ca_password
    req_answers
    ca_commonname
    req_email
}

clear_ca() {
    [ -d "CA" ] || return

    pushd CA >/dev/null

    dirs="certs crl newcerts private"
    for d in ${dirs}; do
	(cd "${d}"; find . -type f -print0 | xargs -0 rm -f 2>/dev/null)
	(cd "${d}"; find . -type d -print0 | xargs -0 rmdir 2>/dev/null)
	rmdir "${d}"
    done

    rm -f "serial" "index.txt"

    popd >/dev/null
}

create_ca_paths() {
    dirs="CA CA/certs CA/crl CA/newcerts CA/private"
    
    mkdirs "${dirs}"

    touch CA/index.txt || die "failed to create CA/index.txt"

    echo "01" > "CA/serial"
    [ -f "CA/serial" ] || die "failed to create CA/serial"
}

create_ca_cert_and_key() {
    ca_key="private/cakey.pem"
    ca_crt="private/cacert.pem"

    pushd CA >/dev/null

    rm -f "${ca_key}"
    rm -f "${ca_crt}"

    ca_answers | openssl req -new -x509 -days 1 \
		    -passout stdin \
		    -keyout "${ca_key}" \
		    -out "${ca_crt}" > /dev/null 2>&1

    [ -f "${ca_key}" ] || die "failed to create CA key!"
    [ -f "${ca_crt}" ] || die "failed to create CA cert!"

    popd >/dev/null
}

create_hashed_ca_path() {
    ca_path="certs/CA"
    cacert_name="cacert.pem"
    src_crt="CA/private/${cacert_name}"
    dst_crt="${ca_path}/${cacert_name}"

    mkdir -p "${ca_path}"

    cp -f "${src_crt}" "${dst_crt}"

    [ -f "${dst_crt}" ] || die "failed to copy CA certificate to CA path!"

    hash=$(openssl x509 -hash -noout -in "${dst_crt}")
    [ -n "${hash}" ] || die "failed to hash ${dst_crt}!"

    (cd "${ca_path}" && ln -sf "${cacert_name}" "${hash}.0")
}

create_ca() {
    clear_ca
    create_ca_paths
    create_ca_cert_and_key
    create_hashed_ca_path
}

cert_answers() {
    cn="$1"

    [ -n "${cn}" ] || cn="localhost.localdomain"

    req_answers
    echo "${cn}"
    req_email
}

# again, partially cribbed from openssl's make-dummy-cert
create_cert() {
    cn="$1"

    [ -n "${cn}" ] || die "no certificate name provided to create_cert"

    if [ -f "${cn}.key" ]; then
	echo "Removing old ${cn}.key..."
	rm -f "${cn}.key"
    fi
    if [ -f "${cn}.csr" ]; then
	echo "Removing old ${cn}.csr..."
	rm -f "${cn}.csr"
    fi
    if [ -f "${cn}.crt" ]; then
	echo "Removing old ${cn}.crt..."
	rm -f "${cn}.crt"
    fi

    cert_answers "$cn" | openssl req -new -nodes -days 1 \
			    -config ./openssl.cnf \
			    -keyout "${cn}.key" \
			    -out "${cn}".csr > /dev/null 2>&1

    [ -f "${cn}.key" -a -f "${cn}.csr" ] || \
		die "failed to create certificate-signing request!"

    ca_password | openssl ca -policy policy_match \
				-keyfile "CA/private/cakey.pem" \
				-cert "CA/private/cacert.pem" \
				-config ./openssl.cnf \
				-passin stdin \
				-days 1 -batch \
				-in "${cn}.csr" \
				-out "${cn}.crt" > /dev/null 2>&1

    rm -f "${cn}.csr"
			
    [ -f "${cn}.crt" ] || die "failed to create certificate for ${cn}"
    mv -f "${cn}.crt" "certs/${cn}.crt"
    mv -f "${cn}.key" "certs/${cn}.key"
}

mkhashdirs() {
    dbdir="$1"

    [ -d "${dbdir}" ] || die "no path passed to mkhashdirs!"

    h="a b c d e f g h i j k l m n o p q r s t u v w x y z"
    h="${h} A B C D E F G H I J K L M N O P Q R S T U V W X Y Z"
    h="${h} 0 1 2 3 4 5 6 7 8 9 + -"

    pushd "${dbdir}" >/dev/null

    for i in ${h}; do
	mkdir -p -- "${i}"
    done

    popd
}

create_cosign_paths() {
    dirs="cosign cosign/cache cosign/db cosign/etc"

    mkdirs "${dirs}"
    mkhashdirs "cosign/db"

    # clear old cookies from any previous test runs
    find "cosign/db" -depth -type f -print0 | xargs -0 rm -f
}

create_cosign_conf() {
    cosign_conf="cosign/etc/cosign.conf"
    
    cat > "${cosign_conf}" <<EOF
# autogenerated by cosign's "make tests" target

# CNs allowed to use LOGIN, LOGOUT, REGISTER, and replication.
cgi localhost-cgi

# shared
set cosignhost		localhost
set cosigncadir		$(pwd)/certs/CA
set cosigncert		$(pwd)/certs/localhost-cgi.crt
set cosignkey		$(pwd)/certs/localhost-cgi.key
set cosignport		33666

# daemon-only
set cosigndb		$(pwd)/cosign/db
set cosigndbhashlen	1
set cosigndticketcache	$(pwd)/cosign/cache

# cgi-only
set cosigntmpldir	$(pwd)/../html
set cosignticketcache	$(pwd)/cosign/cache

# services
service cosign-test-client https://localhost/cosign/valid 0 test-client

EOF
}

cosign_cookie() {
    prefix="$1"

    [ -n "${prefix}" ] || die "cosign_cookie requires a prefix"

    echo "${prefix}=$(openssl rand -hex 60)/$(date +%s)"
}

cosign_login_cookie() {
    echo $(cosign_cookie "cosign")
}

cosign_service_cookie() {
    service="$1"

    [ -n "${service}" ] || die "cosign_service_cookie requires a service name"

    echo $(cosign_cookie "${service}")
}

cosignd_start() {
    cosign_conf="$1"
    cosignd_path="$(pwd)/../daemon/cosignd"

    [ -f "${cosign_conf}" ] || die "invalid cosign.conf: ${cosign_conf}"
    [ -f "${cosignd_path}" -a -x "${cosignd_path}" ] || \
		die "invalid cosignd path: ${cosignd_path}"

    # test 1: parsing of cosign.conf
    "${cosignd_path}" -n -c "${cosign_conf}"

    # test 2: start cosignd. reads pki stuff, configuration, binds to port, etc.
    "${cosignd_path}" -c "${cosign_conf}" \
		-x "$(pwd)/certs/CA" \
		-y "$(pwd)/certs/localhost.crt" \
		-z "$(pwd)/certs/localhost.key" \
		#> /dev/null 2>&1
}

cosignd_stop() {
    cosignd_path="$(pwd)/../daemon/cosignd"

    pid=$(ps_ef | grep "${cosignd_path}" | sed -e '/grep/d' | awk '{print $2}')
    [ -n "${pid}" ] || return
    
    kill -TERM ${pid}
}

cgi_setup_env() {
    # required CGI environment variables
    GATEWAY_INTERFACE="CGI/1.1"; export GATEWAY_INTEFACE
    HTTP_USER_AGENT="cosign-make-tests/1.0"; export HTTP_USER_AGENT
    REQUEST_METHOD="GET"; export REQUEST_METHOD
    REMOTE_ADDR="127.0.0.1"; export REMOTE_ADDR
    REMOTE_HOST="localhost"; export REMOTE_HOST
    SCRIPT_NAME="cosign.cgi"; export SCRIPT_NAME
    SERVER_NAME="localhost.localdomain"; export SERVER_NAME
    SERVER_PROTOCOL="HTTP/1.1"; export SERVER_PROTOCOL
    SERVER_PORT="443"; export SERVER_PORT
    SERVER_SOFTWARE="Apache"; export SERVER_SOFTWARE

    # make sure cosign.cgi can find the cosign.conf
    COSIGN_CGI_CONF="$(pwd)/cosign/etc/cosign.conf"; export COSIGN_CGI_CONF
}

cgi_set_cookie() {
    HTTP_COOKIE="$1"; export HTTP_COOKIE
}

cgi_set_request_method() {
    REQUEST_METHOD="$1"; export REQUEST_METHOD
}

cgi_set_content_type() {
    CONTENT_TYPE="$1"; export CONTENT_TYPE
}

cgi_set_remote_user() {
    REMOTE_USER="$1"; export REMOTE_USER
}

cgi_set_query_string() {
    QUERY_STRING="$*"; export QUERY_STRING
}

cgi_cmd() {
    cmd="$1"
    shift
    args="$*"
    
    cosign_cgi_path="$(pwd)/../cgi/cosign.cgi"

    [ -f "${cosign_cgi_path}" -a -x "${cosign_cgi_path}" ] || \
		die "invalid cosign.cgi path: ${cosign_cgi_path}"

    [ -n "${cmd}" ] || die "cgi_cmd requires args"
    
    cgi_setup_env

    "${cosign_cgi_path}" basic
}

cgi_get_path() {
    cosign_cgi_path="$(pwd)/../cgi/cosign.cgi"

    [ -f "${cosign_cgi_path}" -a -x "${cosign_cgi_path}" ] || \
		die "invalid cosign.cgi path: ${cosign_cgi_path}"

    echo "${cosign_cgi_path}"
}

# GET login page, no cookie in env. should return login.html.
cgi_get_login_screen() {
    cgi_setup_env

    $(cgi_get_path) 
}

cgi_login() {
    user="$1"
    type="$2"
    cgi_path=$(cgi_get_path)
    cookie=$(cosign_login_cookie)

    [ -n "${user}" ] || die "cgi_login requires a username"

    cgi_setup_env
    cgi_set_cookie "${cookie}"

    if [ x"${type}" == x"basic" ]; then
	cgi_set_remote_user "${user}"

	"${cgi_path}" basic
    else
	# should return login_error.html
	echo "bad_password" | "${cgi_path}"
    fi
}

cgi_register_service() {
    svc_name="$1"
    user="$2"
    cgi_path=$(cgi_get_path)

    [ -n "${svc_name}" ] || die "cgi_register_service requires a name"
    [ -n "${user}" ] || die "cgi_register_service requires a user"
    [ -n "${HTTP_COOKIE}" ] || die "cgi_register_service: HTTP_COOKIE not set"

    cgi_setup_env
    cgi_set_query_string "${svc_name}&https://localhost/"
    cgi_set_remote_user "${user}"

    "${cgi_path}"
}

cgi_logout() {
    cookie="${HTTP_COOKIE}"
    logout_cgi_path="$(pwd)/../cgi/logout"

    [ -f "${logout_cgi_path}" -a -x "${logout_cgi_path}" ] || \
		die "invalid logout cgi path: ${logout_cgi_path}"

    [ -n "${cookie}" ] || echo "cgi_logout: no HTTP_COOKIE set" 

    cgi_setup_env

    # XXX also confirm GET of logout cgi works

    # set up the logout confirmation post
    cgi_set_request_method POST
    cgi_set_content_type "application/x-www-form-urlencoded"

    # simulate the logout POST
    echo "verify=Log+Out" | "${logout_cgi_path}"
}

parse_header() {
    echo "$*" | sed -e 's/://' | read header value
}

on_exit() {
    cosignd_stop
}

main() {
    echo "Running tests..."

    mkdirs "tmp"

    # create PKI for cosignd and clients
    create_openssl_cnf
    create_ca

    # cert for cosignd. the CN must match value of cosignhost in cosign.conf.
    create_cert "localhost"

    # cert used by cgi.
    create_cert "localhost-cgi"

    # cert used by cgi not allowed to LOGIN. tests regex anchors.
    create_cert "not-localhost-cgi-cn"

    # create server-side hierarchy for cosignd and cgi
    create_cosign_paths
    create_cosign_conf
    cosignd_stop
    cosignd_start "$(pwd)/cosign/etc/cosign.conf"

    # test login screen. cgi responds with login.html to GET with no cookie.
    cgi_get_login_screen

    # test 3: Basic Auth
    cgi_login "cosigntest" "basic"

    sleep 1

    # test 4: service registration
    cgi_register_service "cosign-test-client" "cosigntest"

    sleep 1

    # test 4: Logout
    cgi_logout

    # EXIT trap calls cosignd_stop.
}


trap on_exit EXIT
main

exit $?
