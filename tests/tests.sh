#! /bin/sh

# run a series of sanity checks against cosignd and cosign.cgi.

# globals
test_count=10
test_index=1
tests_passed=0
tests_failed=0
test_log_name=

# colors
red="[31m"
grn="[32m"
clr="[0m"

die() {
    echo "${red}ERROR: $*${clr}" 1>&2

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

rand_bytes() {
    count=$(echo $1 | sed -e 's/[^0-9]*\([0-9][0-9]*\).*/\1/')
    if [ -z "${count}" ]; then
	count=10
    elif [ ${count} -le 0 ]; then
	count=10
    fi

    openssl rand "${count}"
}

test_cmp() {
    i=0
    type=
    test_file=
    expected=
    actual=

    for a in "$@"; do
	i=$((i + 1))
	case $i in
	1)
	    type="${a}"
	    ;;

	2)
	    test_file="${a}"
	    ;;

	3)
	    expected="${a}"
	    ;;

	4)
	    actual="${a}"
	    ;;

	*)
	    die "test_cmp: unexpected argument list length ${i}"
	    ;;

	esac
    done

    [ -n "${type}" -a -n "${test_file}" ] || \
		die "test_cmp: missing required arguments"

    if [ x"${expected}" = x"${actual}" ]; then
	return 0
    else
	return 1
    fi
}

test_read_cmd() {
    test_file="$1"

    [ -f "${test_file}" ] || \
		die "test_read_cmd: bad test file \"${test_file}\""
    
    awk '/^#BEGIN:TEST$/ { istest = 1 } istest == 1' < "${test_file}" | \
		awk '/^#END:TEST$/ { print; exit 0; } { print; }'
}

test_read_expected_output() {
    tf="$1"

    [ -f "${tf}" ] || die "test_read_expected_output: bad test file \"${tf}\""
    
    awk '/^#BEGIN:EXPECTED_OUTPUT$/ { getline; p = 1; } p == 1' < "${tf}" | \
		awk '/^#END:EXPECTED_OUTPUT$/ { exit 0; } { print; }'
}

test_log() {
    # append output to test log.
    tee -a "${test_log_name}"
}

test_run() {
    local test_file="$1"
    local linenum=0
    local actual_out=
    local actual_status=
    desc=
    cmd=
    out=
    status=

    [ -f "${test_file}" ] || die "missing test file ${test_file}"

    # test file format, command must come last:
    #
    #	"description" description text etc ...
    #	"exit_status" [0|1|2|...|255]
    #		if empty, don't compare exit statuses.
    #
    #	#BEGIN:TEST
    #	[...test script content...]
    #	#END:TEST
    #
    #	#BEGIN:EXPECTED_OUTPUT
    #	[...expected output...]
    #	#END:EXPECTED_OUTPUT

    while read keyword value; do
	[ x"${keyword}" = x"#BEGIN:TEST" ] && break

	case ${keyword} in
	description)
	    desc="${value}"
	    ;;

	exit_status)
	    status="${value}"
	    ;;

	*)
	    ;;
	esac
    done < "${test_file}"

    [ -n "${desc}" -a -n "${status}" ] || \
	    die "${test_file}: invalid test file, missing required keyword"

    cmd=$(test_read_cmd "${test_file}")
    [ -n "${cmd}" ] || die "no test script found in ${test_file}"

    echo "#### Starting test ${test_index} - ${desc} ####" | \
		test_log >/dev/null 2>&1
    printf "Test %2s - %-60s" "${test_index}" "${desc}..."
    actual_out=$(eval "${cmd}" | test_log | \
		 headers_trim | tee "tmp/${test_index}.$$")
    actual_status=$?

    test_cmp status ${test_file} ${status} ${actual_status}
    if [ $? -eq 0 ]; then
	test_read_expected_output "${test_file}" | \
		 diff -q -c - "tmp/${test_index}.$$" >/dev/null
    fi

    if [ $? -eq 0 ]; then
	echo "${grn}PASSED${clr}"
	tests_passed=$((tests_passed + 1))

	echo "#### Test ${test_index} - ${desc}: PASSED ####" | \
		test_log >/dev/null 2>&1
    else
	echo "${red}FAILED${clr}"
	echo "     Expected Status: ${status}"
	echo "       Actual Status: ${actual_status}"
	echo "     Expected Output: ${out}"
	echo "       Actual Output: ${actual_out}"

	tests_failed=$((tests_failed + 1))

	# append differences to test log
	echo "#### Test ${test_index} - ${desc}: FAILED ####" | \
		test_log >/dev/null 2>&1
	echo "#### Output mismatch, diffing... ####" | test_log >/dev/null 2>&1
	test_read_expected_output "${test_file}" | \
		diff -c - "tmp/${test_index}.$$" | test_log >/dev/null 2>&1
    fi

    # simple formatting in the testlog
    echo | test_log >/dev/null 2>&1
    echo | test_log >/dev/null 2>&1
}

tests_run() {
    if [ -z "${test_log_name}" ]; then
	test_log_name=$(date '+%Y%m%d-%H:%M:%S').testlog
    fi

    tests=$(ls tests/* | sort)

    for t in ${tests}; do
	test_run "${t}"
	test_index=$((test_index + 1))
    done

    echo
    echo "Test log: $(pwd)/${test_log_name}"

    echo
    echo "Test results: "
    echo "        ${grn}Passed:${clr} ${tests_passed}"
    echo "        ${red}Failed:${clr} ${tests_failed}"
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
    cgi_cn="$1"
    
    cat > "${cosign_conf}" <<EOF
# autogenerated by cosign's "make tests" target

# CNs allowed to use LOGIN, LOGOUT, REGISTER, and replication.
cgi ${cgi_cn}

# shared
set cosignhost		localhost
set cosigncadir		$(pwd)/certs/CA
set cosigncert		$(pwd)/certs/${cgi_cn}.crt
set cosignkey		$(pwd)/certs/${cgi_cn}.key
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
service cosign-test-reauth https://localhost/cosign/valid 0 test-client

# reauth
reauth cosign-test-reauth TEST_FACTOR

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
    flag="$1"
    if [ x"${flag}" = x"-n" ]; then
	shift
    fi

    cosign_conf="$1"
    cosignd_path="$(pwd)/../daemon/cosignd"

    [ -f "${cosign_conf}" ] || die "invalid cosign.conf: ${cosign_conf}"
    [ -f "${cosignd_path}" -a -x "${cosignd_path}" ] || \
		die "invalid cosignd path: ${cosignd_path}"

    # test 2: start cosignd. reads pki stuff, configuration, binds to port, etc.
    if [ x"${flag}" = x"-n" ]; then
	"${cosignd_path}" -n -c "${cosign_conf}" \
		    -x "$(pwd)/certs/CA" \
		    -y "$(pwd)/certs/localhost.crt" \
		    -z "$(pwd)/certs/localhost.key"
    else
	"${cosignd_path}" -c "${cosign_conf}" \
		    -x "$(pwd)/certs/CA" \
		    -y "$(pwd)/certs/localhost.crt" \
		    -z "$(pwd)/certs/localhost.key"
    fi
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
    SCRIPT_NAME="/cosign.cgi"; export SCRIPT_NAME
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

cgi_fuzz_login() {
    type="$1"
    user="$2"
    cgi_path=$(cgi_get_path)
    cookie=$(cosign_login_cookie)
    fuzz_file="tmp/cosign_cgi_fuzz.$$"

    if [ -z "${user}" ]; then
	user="cosigntest"
    fi

    unset REMOTE_USER
    cgi_setup_env
    cgi_set_cookie "${cookie}"
    cgi_set_request_method "POST"
    cgi_set_content_type "application/x-www-form-urlencoded"

    mkdirs "tmp"

    case "${type}" in
    random_user)
	printf "login=" > "${fuzz_file}"
	rand_bytes >> "${fuzz_file}"
	printf "&password=badpass\n" >> "${fuzz_file}"
	"${cgi_path}" < "${fuzz_file}"
	;;

    random_password)
	printf "login=${user}&password=" > "${fuzz_file}"
	rand_bytes >> "${fuzz_file}"
	cp "${fuzz_file}" /tmp/t
	"${cgi_path}" < "${fuzz_file}"
	;;

    random_post)
	rand_bytes 1024 | "${cgi_path}"
	;;

    valid_chars)
	echo "login=${user}&password=password\r\nLOGIN ${cookie} 127.0.0.1 cosigntest FUZZ\r\n" | "${cgi_path}"
	;;

    *)
	;;

    esac
}

cgi_login() {
    type="$1"
    user="$2"
    pass="$3"
    cgi_path=$(cgi_get_path)
    cookie=$(cosign_login_cookie)

    [ -n "${user}" ] || die "cgi_login requires a username"

    cgi_setup_env
    cgi_set_cookie "${cookie}"
    cgi_set_request_method "POST"

    case "${type}" in
    basic)
	cgi_set_request_method "GET"
	cgi_set_remote_user "${user}"
	"${cgi_path}" basic
	;;

    login)
	cgi_set_content_type "application/x-www-form-urlencoded"
	echo "login=${user}&password=${pass}" | "${cgi_path}"
	;;

    fuzz)
	cgi_fuzz_login
	;;

    esac
}

cgi_register_service() {
    svc_name="$1"
    user="$2"
    cgi_path=$(cgi_get_path)

    [ -n "${svc_name}" ] || die "cgi_register_service requires a name"
    [ -n "${user}" ] || die "cgi_register_service requires a user"
    [ -n "${HTTP_COOKIE}" ] || die "cgi_register_service: HTTP_COOKIE not set"

    cgi_setup_env
    cgi_set_query_string "basic&${svc_name}&https://localhost/"
    cgi_set_remote_user "${user}"

    "${cgi_path}"
}

cgi_logout() {
    cookie="${HTTP_COOKIE}"
    logout_cgi_path="$(pwd)/../cgi/logout"
    prompt="$1"

    [ -f "${logout_cgi_path}" -a -x "${logout_cgi_path}" ] || \
		die "invalid logout cgi path: ${logout_cgi_path}"

    [ -n "${cookie}" ] || echo "cgi_logout: no HTTP_COOKIE set" 
    
    cgi_setup_env
    if [ x"${prompt}" = x"prompt" ]; then
	# this is just a GET of the logout cgi, return logout prompt HTML.
	"${logout_cgi_path}"
	return
    fi

    # set up the logout confirmation post
    cgi_set_request_method POST
    cgi_set_content_type "application/x-www-form-urlencoded"

    # simulate the logout POST
    echo "verify=Log+Out" | "${logout_cgi_path}"
}

parse_header() {
    echo "$*" | sed -e 's/://' | read header value

    case "${header}" in
    Set-Cookie)
	;;
    Cookie)
	;;
    
    
    esac
}

headers_trim() {
    awk '/^$/ { if ( p != 1 ) { getline; p = 1 }} p == 1'
}

header_match_regex() {
    src_file="$1"
    header="$2"
    regex="$3"

    [ -f "${src_file}" ] || \
		die "header_match_regex: bad input file ${src_file}"

    [ -n "${header}" -a -n "${regex}" ] || \
		die "header_match_regex: missing required header and pattern"

    line=$(awk '/^'"${header}"': / { print; exit 0 }' < "${src_file}")
    if [ -z "${line}" ]; then
	echo "Required header \"${header}\" not found in output"
	return 1
    fi

    # move past the header name
    line=$(echo "${line}" | cut -f 2- -d ' ')

    echo "${line}" | egrep -q "${regex}" 2>/dev/null
    if [ $? -ne 0 ]; then
	echo "${header} pattern does not match header output"
	echo "\t\"${line}\" !=~ \"${regex}\""
	return 1
    fi

    return 0
}

check_headers() {
    matches=0
    f=$1
    shift

    if [ ! -f "${f}" -o ! -s "${f}" ]; then
	echo "Bad output file ${f}"
	return 1
    fi

    sed -e '/^[A-Za-z][-A-Za-z]*:/!d' -e 's/://' < "${f}" > "${f}.$$"
    mv -f "${f}.$$" "${f}"

    while read header value; do
	echo "$header: $value" >> /tmp/tttt
	for h in $*; do
	    if [ x"${h}" = x"${header}" ]; then
		matches=$((matches + 1))
	    fi
	done

	#validate_header
    done < "${f}"

    #[ -f "${f}" ] && rm -f "${f}"

    if [ ${matches} -eq $# ]; then
	return 0
    fi

    return 1
}

on_exit() {
    cosignd_stop
    if [ ${tests_failed} -eq 0 ]; then
	(cd tmp && rm -f *)
    fi
}

main() {
    #color_test

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
    create_cosign_conf "localhost-cgi"

    cosignd_stop
    tests_run
}

trap on_exit EXIT
main

exit $?
