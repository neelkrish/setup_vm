#!/usr/bin/env bash
set -e

export USER="${SUDO_USER:-"root"}"
if [ "x${USER}" == "xroot" ]; then
  export USER=$(basename "${HOME}")
fi
# Failed to get username from HOME path
if [ "x${USER}" == "x/" ]; then
  export USER="root"
fi

http_get() {
  export host="${1}"
  export port="${2}"
  export path="${3}"
  export outfile="${4}"

  if [ "x${outfile}" == "x" ]; then
    export outfile="/dev/stdout"
  fi

  exec 3<>/dev/tcp/${host}/${port}

  cat >&3 << EOF
GET ${path} HTTP/1.0
Host: ${host}
User-Agent: bash/42
Accept: */*

EOF
  bytes="none"
  # Read past the headers
  while [[ "${bytes}" != $'\r' ]]
  do
    read -u 3 -r -a bytes
  done
  # Dump the body to /tmp/output
  cat > "${outfile}" <&3
  exec 3>&-
}

kerberos_setup() {
  # https://www.chromium.org/administrators/linux-quick-start
  dirs=(opt/chrome chromium)
  for dir in ${dirs[@]}; do
    mkdir -p /etc/${dir}/policies/{managed,recommended}
    chmod -w /etc/${dir}/policies/managed
    touch /etc/${dir}/policies/managed/intel_kerberos.json
    tee /etc/${dir}/policies/managed/intel_kerberos.json > /dev/null <<EOF
{
  "AuthNegotiateDelegateWhitelist": "*.intel.com,*.corp.intel.com,*.amr.corp.intel.com",
  "AuthServerWhitelist": "*.intel.com,*.corp.intel.com,*.amr.corp.intel.com",
  "ProxySettings": {
    "ProxyMode": "auto_detect"
  }
}
EOF
  # TODO kinit and such
  done
}

cert_setup_fedora() {
  rm -rf /etc/ca-certificates-intel
  cp -r "${tmp_cert_dir}" /etc/ca-certificates-intel
  trust anchor /etc/ca-certificates-intel/*.crt 1>/dev/null 2>&1
  update-ca-trust 1>/dev/null 2>&1
}

cert_setup_debian() {
  rename 's/ /_/g' *
  rename 's/\(/_/g' *
  rename 's/\)/_/g' *
  rm -rf /usr/local/share/ca-certificates/intel
  cp -r "${tmp_cert_dir}" /usr/local/share/ca-certificates/intel
  update-ca-certificates 1>/dev/null 2>&1
}

cert_setup() {
  echo "[+] cert_setup BEGIN"

  export CIRCUIT_URL="https://employeecontent.intel.com/content/news/home/circuithome.html"

  echo "[*] cert_setup installing required packages"
  if [ "x${ID}" == "xfedora" ]; then
    dnf -y install unzip ca-certificates nss-tools python3 1>/dev/null 2>&1
  elif [ "x${ID}" == "xdebian" ]; then
    apt-get -y install unzip rename ca-certificates curl libnss3-tools python3 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xdebian" ]; then
    apt-get -y install unzip rename ca-certificates curl libnss3-tools python3 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xclear-linux-os" ]; then
		# Somethings whacky with filenames with spaces, I gave up and used python
    swupd bundle-add unzip python3-basic curl cryptography 1>/dev/null 2>&1
  else
    echo "[*] cert_setup unknown distro required packages not installed"
  fi

  echo "[*] cert_setup downloading certs"
  tmp_cert_dir=$(mktemp -d)
  cd "${tmp_cert_dir}"
  http_get certificates.intel.com 80 \
    '/repository/certificates/Intel%20Root%20Certificate%20Chain%20Base64.zip' \
    root.zip
  http_get certificates.intel.com 80 \
    '/repository/certificates/IntelSHA2RootChain-Base64.zip' \
    root_sha2.zip
  # Validate hashs
  cat > sha.sums <<'EOF'
  93172bfb95c7c92f617bfc5d81d55bc87632cdbdf456445d1faac400a6e512e049b8887ce91800341d50625438c55d11 root_sha2.zip
1aefbefe8fb9a5235f2edff2481bd3849fefbbc0b7f4369faa9bccb49b57dac8053c71d7fe9d983c302ef99e227d70df root.zip
EOF
  sha384sum -c sha.sums 1>/dev/null 2>&1 \
    || (echo "[-] cert_setup SHA384 mismatch on root cert zipfiles" >&2 \
        && return 1)

  for i in $(ls *.zip); do unzip -o "$i" 1>/dev/null 2>&1 ; done
  rm *.zip

  echo "[*] cert_setup installing certs for chromium"
  mkdir -p "${HOME}/.pki/nssdb"
  python3 -c 'import os, subprocess, glob; list(map(lambda filename: subprocess.check_call(["certutil", "-d", "sql:" + os.path.expanduser("~") + "/.pki/nssdb", "-A", "-t", "C,,", "-n", filename, "-i", filename]), list(glob.glob("*.crt"))))'
  chown -R "${USER}:${USER}" "${HOME}/.pki/nssdb"

  echo "[*] cert_setup installing certs"
  if [ "x${ID}" == "xfedora" ]; then
    cert_setup_fedora
  elif [ "x${ID}" == "xdebian" ]; then
    cert_setup_debian
  elif [ "x${ID_LIKE}" == "xdebian" ]; then
    cert_setup_debian
  elif [ "x${ID_LIKE}" == "xclear-linux-os" ]; then
    python3 -c 'import subprocess, glob; subprocess.check_output(["clrtrust", "add", "--force", *list(glob.glob("*.crt"))])' 1>/dev/null 2>&1
  else
    echo "[-] cert_setup unknown distro" >&2
    return 1
  fi

  echo "[*] cert_setup checking valiation of Circuit HTTPS"
  curl "${CIRCUIT_URL}" 1>/dev/null 2>&1 \
    || (echo "[-] cert_setup Circuit HTTPS validation failed" >&2 \
        && return 1)
  echo "[*] cert_setup Circuit HTTPS validation success"

  rm -rf "${tmp_cert_dir}"

  echo "[+] cert_setup END"
}

proxy_setup() {
  echo "[+] proxy_setup BEGIN"

  export PROXY_HOST=${PROXY_HOST:-"proxy-dmz.intel.com"}
  export HTTP_PROXY_PORT=${HTTP_PROXY_PORT:-"911"}
  export HTTPS_PROXY_PORT=${HTTPS_PROXY_PORT:-"912"}
  export SOCKS_PROXY_PORT=${SOCKS_PROXY_PORT:-"1080"}
  export FTP_PROXY="http://${PROXY_HOST}:${HTTP_PROXY_PORT}/"
  export HTTP_PROXY=$FTP_PROXY
  export HTTPS_PROXY="http://${PROXY_HOST}:${HTTPS_PROXY_PORT}/"
  export SOCKS_PROXY="http://${PROXY_HOST}:${SOCKS_PROXY_PORT}/"
  export NO_PROXY="10.54.0.0/16,192.168.39.0/24,localhost,127.0.0.0/8,::1,intel.com"
  export ftp_proxy="${FTP_PROXY}"
  export http_proxy="${HTTP_PROXY}"
  export https_proxy="${HTTPS_PROXY}"
  export socks_proxy="${SOCKS_PROXY}"
  export no_proxy="${NO_PROXY}"

  # Set the gnome settings (still works if you're running this with sudo)
  if type -P gsettings 1>/dev/null 2>&1; then
    echo "[*] proxy_setup setting gnome proxies"
    # Download the file body to /etc/autoproxy.pac
    http_get autoproxy.intel.com 80 / /etc/autoproxy.pac
    # Ensure it downloaded correctly
    grep -q FindProxyForURL /etc/autoproxy.pac
    gsettings set org.gnome.system.proxy autoconfig-url 'file:///etc/autoproxy.pac' \
      1>/dev/null 2>&1 \
      || echo "[-] proxy_setup failed to set gnome proxy autoconfig-url" >&2
    gsettings set org.gnome.system.proxy mode 'auto' \
      1>/dev/null 2>&1 \
      || echo "[-] proxy_setup failed to set gnome proxy mode to auto" >&2
  fi

  echo "[*] proxy_setup set /etc/environment"
  cat >> /etc/environment <<EOF
FTP_PROXY="${FTP_PROXY}"
HTTP_PROXY="${HTTP_PROXY}"
HTTPS_PROXY="${HTTPS_PROXY}"
SOCKS_PROXY="${SOCKS_PROXY}"
NO_PROXY="${NO_PROXY}"
ftp_proxy="${FTP_PROXY}"
http_proxy="${HTTP_PROXY}"
https_proxy="${HTTPS_PROXY}"
socks_proxy="${SOCKS_PROXY}"
no_proxy="${NO_PROXY}"
EOF

  if [ -d /etc/apt/ ]; then
    mkdir -p /etc/apt/apt.conf.d/
    cat > /etc/apt/apt.conf.d/99proxy <<EOF
Acquire::http::Proxy "$http_proxy";
EOF
    echo "[*] proxy_setup set /etc/apt/apt.conf.d/99proxy"
    # TODO Add mirrors
    # VERSION_CODENAME=bionic
    # Add to /etc/apt/sources.list
    # tee -a /etc/apt/apt.conf.d/99proxy <<EOF
# Acquire::http::Proxy {
#     linux-ftp.jf.intel.com  DIRECT;
# };
# EOF
  fi
  if [ -f /etc/dnf/dnf.conf ]; then
    if [ ! grep -q proxy /etc/dnf/dnf.conf ]; then
      echo "proxy=${http_proxy}" /etc/dnf/dnf.conf
    fi
    echo "[*] proxy_setup set /etc/dnf/dnf.conf"
  fi

  echo "[*] proxy_setup running package manager sync"
  if [ "x${ID}" == "xfedora" ]; then
    dnf updateinfo 1>/dev/null 2>&1
  elif [ "x${ID}" == "xdebian" ]; then
    apt-get -y update 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xdebian" ]; then
    apt-get -y update 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xclear-linux-os" ]; then
    # Search triggers manifest download (on container we must install search)
    swupd bundle-add os-core-search 1>/dev/null 2>&1
    swupd search bash 1>/dev/null 2>&1
  fi

  echo "[+] proxy_setup END"
}

git_setup() {
  echo "[+] git_setup BEGIN"

  echo "[*] git_setup installing required packages"
  if [ "x${ID}" == "xfedora" ]; then
    dnf -y install git nmap-ncat 1>/dev/null 2>&1
  elif [ "x${ID}" == "xdebian" ]; then
    apt-get -y install git netcat-openbsd 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xdebian" ]; then
    apt-get -y install git netcat-openbsd 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xclear-linux-os" ]; then
    swupd bundle-add git ncat 1>/dev/null 2>&1
  else
    echo "[*] git_setup unknown distro required packages not installed"
  fi

  git config --global proxy.http "http://proxy-dmz.intel.com:911/"
  git config --global proxy.https "http://proxy-dmz.intel.com:912/"
  git config --global core.gitproxy "${HOME}/.intel-setup/git-proxy"
  cat >> "${HOME}/.gitconfig" << EOF
[url "ssh://git@gitlab.devtools.intel.com:29418/"]
	insteadOf = https://gitlab.devtools.intel.com/
EOF
# This is a tab indent ^^

  touch "${HOME}/.intel-setup/git-proxy"
  chmod 644 "${HOME}/.intel-setup/git-proxy"
  cat > "${HOME}/.intel-setup/git-proxy"  << 'EOF'
#!/usr/bin/env bash

NC_GNU=$(nc --help 2>&1 | grep '\-\-proxy\-type')

_proxy="proxy-dmz.intel.com"
_proxyport=1080

case $1 in
    *.intel.com|192.168.*|127.0.*|localhost|10.*)
        METHOD=""
    ;;
    *)
        if [ "x${NC_GNU}" != "x" ]; then
          METHOD="--proxy-type socks5 --proxy $_proxy:$_proxyport"
        else
          METHOD="-X 5 -x $_proxy:$_proxyport"
        fi
    ;;
esac

exec nc $METHOD $*
EOF
  chmod 755 "${HOME}/.intel-setup/git-proxy"

  echo "[+] git_setup END"
}

source /usr/lib/os-release
mkdir -p "${HOME}/.intel-setup/"

# Run single command
if [ "x${AUTOPROXY_RUN}" != "x" ]; then
  ${AUTOPROXY_RUN}
else
  proxy_setup
  git_setup
  cert_setup
  kerberos_setup
fi

