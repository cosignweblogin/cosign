#! /bin/sh

# run a series of sanity checks against cosignd and cosign.cgi.

die() {
    echo "ERROR: $*" 1>&2

    exit 2
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
    pushd CA >/dev/null

    dirs="certs crl newcerts private"
    for d in ${dirs}; do
	(cd "${d}"; find . -type f -print0 | xargs -0 rm -f 2>/dev/null)
	(cd "${d}"; find . -type f -print0 | xargs -0 rmdir 2>/dev/null)
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
}

create_cosign_conf() {
    cosign_conf="cosign/etc/cosign.conf"
    
    pwd
    cat > "${cosign_conf}" <<EOF
# autogenerated by cosign's "make tests" target

# shared
set cosigncadir		$(pwd)/certs/CA
set cosigncert		$(pwd)/certs/localhost-cgi.crt
set cosignkey		$(pwd)/certs/localhost-cgi.key

# daemon-only
set cosigndb		$(pwd)/cosign/db
set cosigndbhashlen	1
set cosigndticketcache	$(pwd)/cosign/cache

# cgi-only
cgi localhost-cgi
set cosignticketcache	$(pwd)/cosign/cache

# services
service cosign-test-client https://localhost/cosign/valid 0 test-client

EOF
}

cosign_cookie() {
    prefix="$1"

    [ -n "${prefix}" ] || die "cosign_cookie requires a prefix"

    echo "${prefix}=$(openssl rand -hex 120)"
}

cosign_login_cookie() {
    $(cosign_cookie "cosign")
}

cosign_service_cookie() {
    service="$1"

    [ -n "${service}" ] || die "cosign_service_cookie requires a service name"

    $(cosign_cookie "${service}")
}

start_cosignd() {
    cosign_conf="$1"
    cosignd_path="$(pwd)/../daemon/cosignd"

    [ -f "${cosign_conf}" ] || die "invalid cosign.conf: ${cosign_conf}"
    [ -f "${cosignd_path}" -a -x "${cosignd_path}" ] || \
		die "invalid cosignd path: ${cosignd_path}"

    # test 1: parsing of cosign.conf
    "${cosignd_path}" -n -c "${cosign_conf}"

    # test 2: start cosignd. reads pki stuff, configuration, binds to port, etc.
    "${cosignd_path}" -c "${cosign_conf}" > /dev/null 2>&1
}


cgi_login() {
    user="$1"
    cookie=$(cosign_login_cookie)

    [ -n "${user}" ] || die "cgi_login requires a username"

    cgi_setup_env "${user}"
    cgi_cmd LOGIN ${cookie} 127.0.0.1 ${user} basic
}

main() {
    # create PKI for cosignd and clients
    create_openssl_cnf
    create_ca
    create_cert "localhost-cosignd"
    create_cert "localhost-cgi"

    # create server-side hierarchy for cosignd and cgi
    create_cosign_paths
    create_cosign_conf
    start_cosignd "$(pwd)/cosign/etc/cosign.conf"

    echo $(cosign_login_cookie)
    #cgi_login "cosigntest"
}


main

exit $?
