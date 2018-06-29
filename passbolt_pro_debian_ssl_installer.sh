#!/usr/bin/env bash

set -euo pipefail

#############################################################
#                                                           #
# Passbolt PRO installation script                          #
#                                                           #
# Requirements:                                             #
# This script must be executed with root permissions        #
#                                                           #
# Passbolt, the open source password manager for teams      #
# (c) 2018 Passbolt SARL                                    #
# https://www.passbolt.com                                  #
#                                                           #
#############################################################
script_path="$(realpath "$0")"
script_directory="$(dirname "$script_path")"
readonly UNDEFINED="_UNDEF_"
readonly PROGNAME="$0"
readonly PASSBOLT_BASE_DIR="/var/www/passbolt"
readonly PASSBOLT_PRO_REPO="https://github.com/TylerDaNerd/PBPFFS"
readonly NGINX_SITE_DIR='/etc/nginx/conf.d'
readonly SSL_CERT_PATH='/etc/ssl/certs/passbolt_certificate.crt'
readonly SSL_KEY_PATH='/etc/ssl/certs/passbolt_private.key'
readonly LETSENCRYPT_LIVE_DIR='/etc/letsencrypt/live'
readonly OS='debian'
readonly OS_SUPPORTED_VERSION="9.0"
readonly OS_VERSION_FILE="/etc/debian_version"
readonly FPM_WWW_POOL="/etc/php/7.0/fpm/pool.d/www.conf"
readonly FPM_SERVICE="php7.0-fpm"
readonly WWW_USER="www-data"
readonly WWW_USER_HOME="/home/www-data"
readonly GNUPG_HOME='/home/www-data/.gnupg'
readonly CRONTAB_DIR='/var/spool/cron/crontabs'
die(){
  echo "$*" 1>&2
  exit 1
}

# require /initializers/_variable_accessor.sh
banner(){
  local message=$1
  local len_message=${#message}
  local len=$((len_message < 80 ? len_message : 80 ))

  printf "%0.s=" $(seq 1 "$len")
  printf "\\n"
  printf "%b" "$message" |fold
  printf "\\n"
  printf "%0.s=" $(seq 1 "$len")
  printf "\\n"
}

installation_complete() {
  local protocol='https'

  if [[ "$(__config_get 'ssl_none')" ]]; then
    protocol='http'
  fi

  banner "Installation is almost complete. Please point your browser to
  $protocol://$(__config_get 'passbolt_hostname') to complete the process"
}

disclaimer() {
  cat <<-'EOF'
===========================================================
           ____                  __          ____
          / __ \____  _____ ____/ /_  ____  / / /_
         / /_/ / __ `/ ___/ ___/ __ \/ __ \/ / __/
        / ____/ /_/ (__  |__  ) /_/ / /_/ / / /_
       /_/    \__,_/____/____/_,___/\____/_/\__/

      The open source password manager for teams
      (c) 2018 Passbolt SARL
      https://www.passbolt.com
===========================================================
IMPORTANT NOTE: This installation scripts are for use only
on FRESH installed debian >= 9.0 or CentOS >= 7.0
===========================================================
EOF
}
# require _os_version_validator.sh
# require _os_permissions_validator.sh
validate_os() {
  __validate_os_permissions
  __validate_os_version "$(cat "$OS_VERSION_FILE")" "$OS_SUPPORTED_VERSION"
}
# require _variable_accessor.sh

__validate_hostname() {
  local _passbolt_hostname="$1"

  if ! [[ "$_passbolt_hostname" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ || \
          "$_passbolt_hostname" =~ ^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$ ]]; then
    echo "false"
  else
    echo "true"
  fi
}
# require ../helpers/utils/errors.sh
__validate_os_permissions() {
  if [[ "$EUID" != "0" ]]; then
    die "This script must be run with root permissions. Try using sudo $PROGNAME"
  fi
}
# require _variable_accessor.sh

__validate_ssl_paths() {
  local _cert_path="$1"

  if [[ -f "$_cert_path" ]]; then
    echo "true"
  else
    echo "false"
  fi
}
# require ../helpers/utils/errors.sh
__compare_versions() {
  local _current="$1"
  local _supported="$2"

  if [ "$_supported" != "$(printf "%b" "$_current\\n$_supported" | sort -V | head -n1)" ];then
    die "Your OS Version is not supported."
  fi
}

__validate_os_version() {
  local current="$1"
  local supported="$2"

  if [ "$current" != "$supported" ]; then
    __compare_versions "$current" "$supported"
  fi
}
# require _variable_accessor.sh
# require /helpers/utils/messages.sh
__prompt_ssl_paths(){
  local _config_ssl_cert="$1"
  local _config_ssl_key="$2"
  local _ssl_cert
  local _ssl_key

  if [[ -z "$(__config_get "$_config_ssl_cert")" ]]; then
    read -rp "Enter the path to the SSL certificate: " _ssl_cert
    while [[ "$(__validate_ssl_paths "$_ssl_cert")" == 'false' ]]; do
      banner "Please introduce a valid path to your ssl certificate"
      read -rp "Enter the path to the SSL certificate: " _ssl_cert
    done
    __config_set "$_config_ssl_cert" "$_ssl_cert"
  fi

  if [[ -z "$(__config_get "$_config_ssl_key")" ]]; then
    read -rp "Enter the path to the SSL privkey: " _ssl_key
    while [[ "$(__validate_ssl_paths "$_ssl_key")" == 'false' ]]; do
      banner "Please introduce a valid path to your ssl key file"
      read -rp "Enter the path to the SSL key: " _ssl_key
    done
    __config_set "$_config_ssl_key" "$_ssl_key"
  fi
}

__prompt_lets_encrypt_details() {
  local _config_ssl_email="$1"
  local _ssl_email

  if [[ -z "$(__config_get "$_config_ssl_email")" ]]; then
    read -rp "Enter a email address to register with Let's Encrypt: " _ssl_email
    __config_set "$_config_ssl_email" "$_ssl_email"
  fi
}

__prompt_ssl(){
  local _options=("manual" "auto" "none")
  local _config_ssl_auto="$1"
  local _config_ssl_manual="$2"
  local _config_ssl_none="$3"
  local _config_ssl_cert="$4"
  local _config_ssl_key="$5"
  local _config_ssl_email="$6"

  if [[ -z "$(__config_get "$_config_ssl_auto")" && \
        -z "$(__config_get "$_config_ssl_manual")" && \
        -z "$(__config_get "$_config_ssl_none")" ]]; then
    banner "Setting up SSL...
    Do you want to setup a SSL certificate and enable HTTPS now?
    - manual: Prompts for the path of user uploaded ssl certificates and set up nginx
    - auto:   Will issue a free SSL certificate with https://www.letencrypt.org and set up nginx
    - none:   Do not setup HTTPS at all"
    select opt in "${_options[@]}"; do
      case $opt in
        "manual")
          __config_set "$_config_ssl_manual" true
          break
          ;;
        "auto")
          __config_set "$_config_ssl_auto" true
          break
          ;;
        "none")
          __config_set "$_config_ssl_none" true
          return
          break
          ;;
        *)
          echo "Wrong option, please choose (1) manual, (2) auto or (3) none"
        ;;
      esac
    done
  fi

  if [[ "$(__config_get "$_config_ssl_manual")" == 'true' ]]; then
    __prompt_ssl_paths "$_config_ssl_cert" "$_config_ssl_key"
  fi

  if [[ "$(__config_get "$_config_ssl_auto")" == 'true' ]]; then
    __prompt_lets_encrypt_details "$_config_ssl_email"
  fi
}
# require _variable_accessor.sh
# require /helpers/utils/messages.sh
__prompt_passbolt_hostname() {
  local _passbolt_hostname
  local _host_config_key="$1"

  _host_config_key="$1"
  if [[ -z "$(__config_get "$_host_config_key")" ]]; then
    banner "Setting hostname...
    Please enter the domain name under which passbolt will run.
    Note this hostname will be used as server_name for nginx
    and as the domain name to register a SSL certificate with
    let's encrypt.
    If you don't have a domain name and you do not plan to use
    let's encrypt please enter the ip address to access this machine"
    read -r -p "Hostname:" _passbolt_hostname
    while [[ "$(__validate_hostname "$_passbolt_hostname")" == 'false' ]]; do
      banner "Please introduce a valid hostname. Valid hostnames are either
      IPv4 addresses or fully qualified domain names"
      read -r -p "Hostname:" _passbolt_hostname
    done
    __config_set "$_host_config_key" "$_passbolt_hostname"
  fi
}
__config_data() {
  declare -gA config
}
__config_set() {
  config[$1]="$2"
  return $?
}

__config_get() {
  if [[ -z "${config[$1]+'test'}" ]]; then
    echo ""
  else
    echo "${config[$1]}"
  fi
}
# require _variable_accessor.sh
init_config() {
  __config_data
}
__copy_ssl_certs() {
  local _config_ssl_cert="$1"
  local _config_ssl_key="$2"

  if [[ -e "$SSL_CERT_PATH" ]]; then
    mv "$SSL_CERT_PATH"{,.orig}
  fi

  if [ -e "$SSL_KEY_PATH" ]; then
    mv "$SSL_KEY_PATH"{,.orig}
  fi

  if [[ -f "$(__config_get "$_config_ssl_cert")"  && -f "$(__config_get "$_config_ssl_key")" ]]; then
    cp "$(__config_get "$_config_ssl_cert")" "$SSL_CERT_PATH"
    cp "$(__config_get "$_config_ssl_key")" "$SSL_KEY_PATH"
  else
    mv "$NGINX_SITE_DIR"/passbolt_ssl.conf{,.orig}
    banner "Unable to locate SSL certificate files."
  fi
}

__setup_letsencrypt() {
  local _config_passbolt_host="$1"
  local _config_email="$2"

  certbot certonly --authenticator webroot \
    -n \
    -w "$PASSBOLT_BASE_DIR" \
    -d "$(__config_get "$_config_passbolt_host")" \
    -m "$(__config_get "$_config_email")" \
    --agree-tos
}
# require utils/messages.sh
# require service_enabler.sh
# require _setup_ssl.sh
__nginx_config(){
  local source_template="$1"
  local nginx_config_file="$2"
  local _config_passbolt_host="$3"

  if [ ! -f "$nginx_config_file" ]; then
    cp "$source_template" "$nginx_config_file"
    sed -i s:_SERVER_NAME_:"$(__config_get "$_config_passbolt_host")": "$nginx_config_file"
  fi
}

__ssl_substitutions(){
    sed -i s:_NGINX_CERT_FILE_:"$SSL_CERT_PATH": "$NGINX_SITE_DIR/passbolt_ssl.conf"
    sed -i s:_NGINX_KEY_FILE_:"$SSL_KEY_PATH": "$NGINX_SITE_DIR/passbolt_ssl.conf"
}

setup_nginx(){
  local passbolt_domain

  passbolt_domain=$(__config_get 'passbolt_hostname')
  banner "Setting up nginx..."

  __nginx_config "$script_directory/conf/nginx/passbolt.conf" "$NGINX_SITE_DIR/passbolt.conf" 'passbolt_hostname'
  enable_service 'nginx'

  if [[ "$(__config_get 'ssl_auto')" == 'true' ]]; then
    if __setup_letsencrypt 'passbolt_hostname' 'letsencrypt_email'; then
      __nginx_config "$script_directory/conf/nginx/passbolt_ssl.conf" "$NGINX_SITE_DIR/passbolt_ssl.conf" 'passbolt_hostname'
      ln -s "$LETSENCRYPT_LIVE_DIR/$passbolt_domain/cert.pem" "$SSL_CERT_PATH"
      ln -s "$LETSENCRYPT_LIVE_DIR/$passbolt_domain/privkey.pem" "$SSL_KEY_PATH"
      __ssl_substitutions
      enable_service 'nginx'
    else
      banner "WARNING: Unable to setup SSL using lets encrypt. Please check the install.log"
    fi
  fi

  if [[ "$(__config_get 'ssl_manual')" == 'true' ]]; then
    __nginx_config "$script_directory/conf/nginx/passbolt_ssl.conf" "$NGINX_SITE_DIR/passbolt_ssl.conf" 'passbolt_hostname'
    __copy_ssl_certs 'ssl_certificate' 'ssl_privkey'
    __ssl_substitutions
    enable_service 'nginx'
  fi
}
enable_service() {
  systemctl enable "$1"
  systemctl restart "$1"
}

stop_service() {
  systemctl stop "$1"
}
main() {
  init_config
  validate_os
  __prompt_passbolt_hostname 'passbolt_hostname'
  __prompt_ssl 'ssl_auto' \
               'ssl_manual' \
               'ssl_none' \
               'ssl_certificate' \
               'ssl_privkey' \
               'letsencrypt_email'
  setup_nginx
}

main "$@" 2>&1 | tee -a ssl_install.log
