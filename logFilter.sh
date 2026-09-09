#!/usr/bin/env bash
#
# ╭───────────────────────────────────────────────────────────────────────────────────────
# ╰── Script 1/2: logFilter.sh 
# 
# - Extrae las IPv4 del archivo Apache/access.log || lee archivo con IPv4 únicas (-i IPv4_únicas.lst)
# ╰─ Divide las consultas en bloques de (Por defecto: 500 IPs) para rotar la IP de Tor
# ╰─ Invoca a torFilter.sh, lanza consultas en paralelo de (Por defecto: 100 hilos) con xargs a listas de reputación de amenazas
# ╰─ torFilter.sh las añade a la lista de baneo si tienen algún positivo
# ╰─ Refresca el circuito de Tor (SIGNAL NEWNYM) al finalizar cada bloque
#
#
# Coded by: ᗪᔕᵉᵛⁱˡˡᵃᑭʳᵒᵍ © 2026
#
#
# VERSION '0.1'	07/07/26
VERSION='0.2'
#
# ╭──────────────────────────────────
# ╰───── TODO
#   *** añadir + nombrar + procesar/limpiar archivos_temporales
#   *** integrar todo con tor
#   *** optimizar flujos
#   **  tabular salidas
# ╰────────────────────────────────── 
#
#
# ╭──────────────────────────────────
# ╰───── CONFIGURACIÓN Y VARIABLES
# --- Control de errores
#set -euo pipefail
#set -x
# Capturar y mostrar errores
test_error() {
    local linea_ERROR=$1
    local codigo_ERROR=$2
    echo -e "\n[!] Error en línea: $linea_ERROR ERROR: $codigo_ERROR\n" >&2
    #** limpiar archivos_temporales
    #exit "$codigo_ERROR"
}
# Registrar con trap para que escuche el evento ERR
trap 'test_error ${LINENO} $?' ERR
# Cierra el programa con Ctrl+c
trap ctrl_c INT
ctrl_c() {
	#echo -e "\n\n$c_roj [*] Cerrando ... $c_bla\n"
	exit 1
}
#
# --- Rutas
RUTA=$(pwd)
SCRIPT_NAME=$( basename -s .sh $0)
# Lista de IPs únicas maliciosas de ejemplo
LOG_FILE="$RUTA/single_ips.txt"
# Log de ejemplo de Apache con peticiones maliciosas
LOG_FILE="$RUTA/apache.log"
LOG_NAME=$( basename "$LOG_FILE")
# Reporte Final
REPORT_FILE="$RUTA/$( date -u '+%Y-%m-%d_%H:%M:%S' )_$SCRIPT_NAME.txt"
# IPs con positivos >=1
BAN_TOR_IP="$RUTA/BAN_TOR_IP.lst"
# IPs con peticiones maliciosas
BAN_REQUEST_FILE="$RUTA/BAN_REQUEST_IP.lst"
# IPs de países restringidos
BAN_LIST_FILE="$RUTA/BAN_COUNTRY_IP.lst"
# IPs alienvault
BAN_OTX_FILE="$RUTA/BAN_ALIEN_IP.lst"
# IPs VirusTotal
BAN_VTOT_FILE="$RUTA/BAN_VTOT_IP.lst"
# IPs torsocks
BAN_DNSBL_FILE="$RUTA/BAN_DNSBL_IP.lst"
#
# --- API_KEYS
# VirusTotal: Crear una cuenta (https://www.virustotal.com/gui/join-us)-> API -> Click en "Get your API key" -> Copiar API_KEY
VT_API_KEY="VIRUSTOTAL_API_KEY"
# Alienvault: Crear una cuenta (https://otx.alienvault.com/)-> API KEY -> Copiar API_KEY
OTX_API_KEY="ALIENVAULT_API_KEY"
#
# --- Filtros
# Países restringidos
WARN_country="^(China|Hong Kong|India|Kazakhstan|Malaysia)$"
# Peticiones maliciosas
regex_maliciosa='(union|select|insert|update|delete|drop|truncate|alter|into[[:space:]]+outfile|load_file|concat|md5|benchmark|sleep\(|order[[:space:]]+by|group[[:space:]]+by|<script|alert\(|confirm\(|prompt\(|javascript:|onerror=|onload=|onmouseover=|document\.cookie|window\.location|eval\(|base64,|svg/onload|<iframe|<object|etc/passwd|etc/shadow|etc/issue|boot\.ini|win\.ini|\.\./|\.\.\\|/bin/sh|/bin/bash|cmd\.exe|wget[[:space:]]|curl[[:space:]]|nc[[:space:]]|netcat|tftp|nmap|chmod|chown|whoami|id[[:space:]]|uname|passwd[[:space:]]|\.env|\.git|\.svn|\.htaccess|\.htpasswd|config\.php|wp-config|web\.config|\.bak|\.old|\.sql|\.zip|\.tar\.gz|O:[0-9]+:[[:space:]]*\"|__reduce__|wp-admin|wp-login|phpmyadmin|pma/|cpanel|xmlrpc\.php|web-acoo|c99shell|r57shell|wso\.php|shell\.php|cmd\.php|upload\.php|\(\)[[:space:]]*\{[[:space:]]*:[[:space:]]*;[[:space:]]*\}|<!ENTITY[[:space:]]+|SYSTEM[[:space:]]+\"|file://|gopher://|dict://|ftp://|http://127\.0\.0\.1|http://localhost|http://169\.254\.169\.254)'
# Filtro DNS y LOCALHOST
regex_exclusion='^(8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9|127\.0\.0\.1|::1)$'
# Status Code
regex_status='[[:space:]](400|401|403|404|500)[[:space:]]'
# Tamaños de bloques e hilos por defecto para torFilter.sh
IP_TOR_BLOCK=500
HILOS_XARGS=100
# Marcador para filtrar: -f access.log || -i ./IPv4.lst
IP_LOG=0
#
# --- Colores
NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
#
#
# ╭───────────────────────────────────────────────────────────────── BANNER
# ╰─────
banner() {
    #clear
    echo -e "${GREEN}${BOLD} ⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘ ${CYAN}${BOLD}"
    echo -e '		    __             ______ _ __ __            
		   / /___  ____ _ / ____/(_) // /_ ___  _____
		  / / __ \/ __ `// /_   / / // __// _ \/ ___/
		 / / /_/ / /_/ // __/  / / // /_ /  __/ /    
		/_/\____/\__, //_/    /_/_/ \__/ \___/_/     
			/____/'
    echo -e "${GREEN}${BOLD} ⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘⫘ ${NC}"
    echo -e "                                                         ${BLUE} ᗪᔕᵉᵛⁱˡˡᵃᑭʳᵒᵍ  𝕧 $VERSION${NC}\n"
}
#
# ╭───────────────────────────────────────────────────────────────── AYUDA
# ╰─────
ayuda() {
    echo -e "  $0 \n"
    echo "   - Extrae direcciones IPv4 del archivo Apache/access.log || lee archivo con IPv4 únicas"
    echo "   ╰─ Filtra por peticiones maliciosas y país"
    echo "    ╰─ Consulta a herramientas online"
    echo "     ╰─ Consulta con Tor en listas de reputación de amenazas (DNSBL)"
    echo ""
    echo "  Usos:"
    echo "      ./logFilter.sh [-f LOGFILE] [-i IPV4LST] [-b IP_BLOCK] [-p HILOS] [-c TOOL] [-m] [-h]"
    echo ""
    echo "      $0 -f <file.log> [-b <IP_TOR_BLOCK>] [-p <HILOS>]"
    echo "      $0 -i <IPv4.lst> -c [api rd dns vt av x]"
    echo "      $0 -f <file.log> -m"
    echo ""
    echo "  Opciones:"
    echo "      -f : Analizar archivo de log de Apache [-f ./access.log]"
    echo "      -i : Analizar archivo con IPv4 únicas [-i ./IPv4.lst]"
    echo ""
    echo '      -c : Consulta herramientas online [-c "api rd dns vt av"] TODAS=[-c x]'
    echo "      -m : Filtra por peticiones maliciosas y las consulta en listas DNSBL (*sólo con -f)"
    echo ""
    echo "      -b : Tamaño del bloque de IPs antes de cambiar de circuito Tor (Por defecto: $IP_TOR_BLOCK)"
    echo "      -p : Número de procesos paralelos concurrentes para xargs (Por defecto: ${HILOS_XARGS})"

    echo '
    Ejemplos:

        - Analizar log de Apache consultando en listas DNSBL y procesando bloques de 1000 IPs con 200 hilos concurrentes:
            ./logFilter.sh -f /var/log/apache2/access.log -b 1000 -p 200 -c dns

        - Analizar log de Apache filtrando por peticiones maliciosas:
            ./logFilter.sh -f /var/log/apache2/access.log -m

        - Analizar log de Apache filtrando por peticiones maliciosas y consultar en listas DNSBL:
            ./logFilter.sh -f ./access.log -m -c dns

        - Analizar archivo con IPv4 únicas y consultar en listas DNSBL:
            ./logFilter.sh -i ./IPv4.lst -c dns


    Herramientas online [-c <herramienta>]: 
         api : ip-api.com
          rd : rdap.org
         dns : DNSBL    [[-b <IP_TOR_BLOCK>] [-p <HILOS>]]
          vt : VirusTotal (*API_KEY)
          av : AlienVault (*API_KEY)
           x : TODAS


    Listas de reputación DNSBL [-c dns]: 
        Spamhaus XBL, Barracuda BRBL, DroneBL, Sorbs, URLhaus


    Dependencias:
       gawk curl dnsutils bind9-host jq netcat-openbsd dnsutils coreutils tor torsocks xclip
'

    echo -e "[?] Ver Listas DNSBL (v)?:"
    read -r ver_listas < /dev/tty
    if [[ "$ver_listas" =~ ^[Vv]$ ]]; then
        echo '
 - Spamhaus XBL:
        xbl.spamhaus.org
        Lista de IPs de servidores o dispositivos hackeados que albergan troyanos, proxies abiertos, herramientas de intrusión maliciosa o botnets activas.
        Por qué usarla: Es el estándar de la industria en detección de infraestructura comprometida. Integrarla te asegura detectar si quien ataca tu Apache es un nodo zombi de una botnet.

 - Barracuda BRBL (Barracuda Reputational Block List):
        b.barraculacentral.org
        Lista de Direcciones IP asociadas a ataques automatizados, escaneos masivos de vulnerabilidades, inyecciones de código y spam industrial.
        Por qué usarla: Es mantenida en tiempo real por Barracuda Networks. Es extremadamente rápida resolviendo y tiene un índice muy bajo de falsos positivos en servidores de producción.

 - DroneBL:
        dnsbl.dronebl.org
        Lista de Redes de bots, bots de IRC, enrutadores vulnerables infectados por malware (como variantes de Mirai), scrapers agresivos y proxies inseguros.
        Por qué usarla: Es una lista enfocada puramente en tráfico automatizado y malicioso (crawlers hostiles). Si una IP está listada aquí, hay un 99% de probabilidad de que sea un script automatizado intentando explotar fallos web.

 - Sorbs DUHL (Dynamic User Host List):
        dul.dnsbl.sorbs.net
        Lista de Rangos de direcciones IP dinámicas (como conexiones domésticas de Fibra/ADSL) que no deberían estar interactuando directamente con servicios críticos de servidores corporativos.
        Por qué usarla: El tráfico legítimo de tu Apache suele venir de IPs estáticas de CDN o proveedores. Si detectas un volumen de tráfico anormal o intentos de inyección desde una IP clasificada en SORBS DUHL, suele tratarse de un atacante residencial lanzando herramientas ofensivas desde su PC personal.

 - Abuse.ch URLhaus (Vía API o Descarga Local):
        curl -X POST https://abuse.ch -d "host=${IP_A_COMPROBAR}"
        Lista de IPs que distribuyen malware de forma activa (ransomware, infostealers, troyanos bancarios).
        Por qué usarla: Es un proyecto comunitario de alta confianza enfocado estrictamente en cibercrimen y distribución de malware activo.

'
    fi
    exit 1
}
#
# ╭───────────────────────────────────────────────────────────────── TEST_LOG
# ╰─────# --- Validar la existencia del archivo de LOG
test_log() {
    if ! [ -s "$LOG_FILE" ] || [ -z "$LOG_FILE" ] || [ ! -f "$LOG_FILE" ]; then
        printf "${CYAN}[?]${NC} Ruta al Archivo de logs: "
        read -r LOG_FILE
        test_log
    fi
    echo -e "\n${GREEN}[+] Archivo de logs:${NC} $LOG_FILE"
    LOG_NAME=$( basename "$LOG_FILE")
}
#
# ╭───────────────────────────────────────────────────────────────── APT-GET / DNF / etc
# ╰─────# --- Detectar gestor de paquetes
detectar_gestor() {
    PKG_MANAGER="Desconocido"
    INSTALL_CMD=""
    UPDATE_CMD=""
    # Binarios a comprobar
    gestores=("apt-get" "dnf" "yum" "pacman" "zypper" "apk" "xbps-install")
    # Asignar comandos según OS
    for gestor in "${gestores[@]}"; do
        # Verificar si el binario existe en ($PATH)
        if command -v "$gestor" >/dev/null 2>&1; then
            case "$gestor" in
                # - Debian / Ubuntu y derivados (Linux Mint, Kali)
                "apt-get")
                    PKG_MANAGER="apt-get"
                    UPDATE_CMD="sudo apt-get update"
                    INSTALL_CMD="sudo apt-get install -y"
                    ;;
                # - Red Hat moderna (Fedora, RHEL 8+, Rocky Linux, AlmaLinux)
                "dnf")
                    PKG_MANAGER="dnf"
                    UPDATE_CMD="sudo dnf check-update"
                    INSTALL_CMD="sudo dnf install -y"
                    ;;
                # - Red Hat heredada (CentOS 7, RHEL 7 y versiones antiguas)
                "yum")
                    PKG_MANAGER="yum"
                    UPDATE_CMD="sudo yum check-update"
                    INSTALL_CMD="sudo yum install -y"
                    ;;
                # - Arch Linux y derivados (Manjaro, EndeavourOS)
                "pacman")
                    PKG_MANAGER="pacman"
                    UPDATE_CMD="sudo pacman -Syy"
                    INSTALL_CMD="sudo pacman -S --noconfirm" # --noconfirm = instalación sin prompts
                    ;;
                # - SUSE (openSUSE Leap, Tumbleweed, SUSE Linux Enterprise)
                "zypper")
                    PKG_MANAGER="zypper"
                    UPDATE_CMD="sudo zypper refresh"
                    INSTALL_CMD="sudo zypper install -y"
                    ;;
                # - Alpine Linux (Sistemas ligeros usados en contenedores Docker)
                "apk")
                    PKG_MANAGER="apk"
                    UPDATE_CMD="sudo apk update"
                    INSTALL_CMD="sudo apk add"
                    ;;
                # - Void Linux (Distribución independiente con gestor nativo XBPS)
                "xbps-install")
                    PKG_MANAGER="xbps"
                    UPDATE_CMD="sudo xbps-install -S"
                    INSTALL_CMD="sudo xbps-install -y"
                    ;;
            esac
            break
        fi
    done
    echo -e "${GREEN}[+]${NC} Gestor de paquetes Detectado: $PKG_MANAGER"
    echo " ╰────────────────────────────────────"
    # Instalar paquetes 
    if [ "$PKG_MANAGER" = "Desconocido" ]; then
        echo -e "\n[!] Error: No se pudo reconocer el gestor de paquetes.\n"
        return 1
    fi
    # Actualizar repositorios primero para:
    if [ "$PKG_MANAGER" = "apt-get" ] || [ "$PKG_MANAGER" = "pacman" ]; then
        echo -e " ╰─[+] Actualizando repositorios ..."
        $UPDATE_CMD >/dev/null 2>&1
    fi
}
#
# ╭───────────────────────────────────────────────────────────────── DEPENDENCIAS
# ╰─────# --- COMPROBAR DEPENDENCIAS
# ** Omitir check_dependencias tras primera ejecución || install()
check_dependencias() {
    local faltan_dependencias=false
    local paquetes_a_instalar=""
    # Comandos y paquetes correspondientes en Debian/Ubuntu
    declare -A dependencias=(
    ["awk"]="gawk"
    ["curl"]="curl"
    ["dig"]="dnsutils"
    ["host"]="bind9-host"
    ["jq"]="jq"
    ["nc"]="netcat-openbsd"
    ["nslookup"]="dnsutils"
    ["timeout"]="coreutils"
    ["tor"]="tor"
    ["torsocks"]="torsocks"
    ["xclip"]="xclip"
    )
    for cmd in "${!dependencias[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            faltan_dependencias=true
            paquetes_a_instalar+="${dependencias[$cmd]} "
        fi
    done
    if [ "$faltan_dependencias" = true ]; then
            echo -e "[!] Error: Faltan las siguientes dependencias: " >&2
            echo -e " ╰─[*] ${paquetes_a_instalar[*]} " >&2
            sleep 2
            detectar_gestor
            echo -e "[>] $INSTALL_CMD $paquetes_a_instalar " >&2
            echo -e " ╰─[?] INTRO para Instalar ..." >&2
            read -p '' goo
            $INSTALL_CMD "$paquetes_a_instalar"
            if [ $? -eq 0 ]; then
                echo -e " ╰─[+] Instalado: $paquetes_a_instalar"
            else
                echo -e "\n[!] Error: Fallo al instalar $paquetes_a_instalar."
            fi
    fi

}
#
# ╭───────────────────────────────────────────────────────────────── ACTUALIZAR PAQUETES
# ╰─────# --- ACTUALIZAR PAQUETES *sin uso
actualizar_paquetes() {
    echo -e "[!] Actualizar Paquetes?" >&2
    detectar_gestor
    echo -e "[>] $UPDATE_CMD" >&2
    echo -e " ╰─[?] INTRO para Instalar ..." >&2
    read -p '' goo
    $UPDATE_CMD
    if [ $? -eq 0 ]; then
        return 0
    else
        echo -e "\n[!] Error: Fallo al Actualizar paquetes."
    fi
}
#
# ╭───────────────────────────────────────────────────────────────── LOCALHOST
# ╰─────# --- FILTRO DE RANGOS INTERNOS O DIRECCIONES LOCALES
is_local_ip() {
    local ip="$1"
    # Doble validación para mitigar cualquier residuo de IPs de loopback, links-local IPv6 o subredes privadas RFC 1918
    if [[ "$ip" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]] || [[ "$ip" == "::1" ]] || [[ "$ip" =~ ^fe80: ]]; then
        return 0
    fi
    return 1
}
#
# ╭───────────────────────────────────────────────────────────────── FILTRO_OWASP
# ╰─────# --- FILTRO DE EXTRACCIÓN ALINEADO CON OWASP
extract_malicious_ips() {
    echo -e "\n${YELLOW}[*] Filtrando y abstrayendo IPs sospechosas de:${NC} $LOG_NAME"
    {
        grep -Ei "$regex_maliciosa" "$LOG_FILE" || true
        grep -E "$regex_status" "$LOG_FILE" || true
    } | awk '{print $1}' | grep -vE "$regex_exclusion" | sort -u > "$BAN_REQUEST_FILE"

    local ip_count
    ip_count=$(wc -l < "$BAN_REQUEST_FILE" | tr -d ' ')
    if [ "$ip_count" -eq 0 ]; then
        echo -e " ╰─${GREEN}[-] No se detectaron IPs con patrones de amenaza ${NC}\n"
        exit 0
    else
        echo -e " ╰─${RED}${BOLD}[+]${NC}${YELLOW} Encontradas${NC}${BOLD} $ip_count ${NC}${YELLOW}IPs sospechosas en:${NC} `basename $BAN_REQUEST_FILE`\n"
        #echo -e " ╰─${GREEN}${BOLD}[!]${NC} COPIADO: $0 -i $BAN_REQUEST_FILE\n"
        #echo "$0 -i $BAN_REQUEST_FILE" | xclip -sel clip
    fi
}
#
# ╭───────────────────────────────────────────────────────────────── IP-API
# ╰─────# --- ANÁLISIS CON ip-api
enrich_network() {
    local ip="$1"
    echo "╭──────────────────────────────────"
    echo "$ip"
    echo "╰──────────────────────────────────"
    echo ""
    
    if is_local_ip "$ip"; then
        echo "Aviso: IP Identificada como rango local/loopback privado."
        echo "[-]: Omitiendo consultas externas."
        echo ""
        return
    fi

    # ip-api.com no requiere API KEY y responde en milisegundos con ASN y País.
    local network_data
    network_data=$(torsocks curl --max-time 4 --silent "http://ip-api.com/json/$ip" || echo "TIMEOUT")
    
    local asn="No detectado"
    local country="No detectado"
    
    if [ "$network_data" != "TIMEOUT" ]; then
        asn=$(echo "$network_data" | jq -r '.as // "No detectado"' 2>/dev/null || echo "No detectado")
        country=$(echo "$network_data" | jq -r '.country // "No detectado"' 2>/dev/null || echo "No detectado")
	    touch "$BAN_LIST_FILE"
        # Filtro por Países restringidos
	    if [[ "$country" =~ $WARN_country ]]; then
	        echo -e "${RED} ╰──[!] ALERTA País:${NC}${RED} Actividad sospechosa:${NC}${BOLD} $country ${NC}" >&2
	        echo -e "${YELLOW} ╰──[+] Añadiendo IP a la lista de baneo:${NC}${BOLD}  $ip ${NC}" >&2
	        
	        # Guarda la IP en el Listado de IPs de países restringidos
	        echo "$ip:$country" >> "$BAN_LIST_FILE"
	    fi
    fi
    
    echo "[+] ANÁLISIS DE RED ip-api.com"
    echo " ╰──────────────────────────────────"
    echo "ASN:            $asn"
    echo "Origen:         $country"
    
    #*** TODO *optimizar
    # Herramientas de DNS protegidas con timeouts
    # DIG: respuesta del servidor DNS
    local dig_ptr
    dig_ptr=$(timeout 2 torsocks dig -4 -x "$ip" +tcp +short +time=1 +tries=1 2>/dev/null | sed 's/\.$//' || true)

    echo "Dig_PTR:        ${dig_ptr:-Sin resolución / Timeout}"
    
	# HOST: Verificación de resolución inversa
    local host_info
    host_info=$(timeout 2 torsocks host -4 -T -W 1 "$ip" 2>/dev/null || echo "Timeout")
    if [[ "$host_info" =~ "not found" || "$host_info" =~ "NXDOMAIN" ]]; then
        host_info="Sin resolución inversa (NXDOMAIN)"
    fi

    echo "Host_info:      $host_info"
    
    # NSLOOKUP: 
    local ns_info
    ns_info=$(timeout 2 torsocks nslookup -timeout=1 "$ip" 2>/dev/null | grep -i 'name =' | awk '{print $4}' | sed 's/\.$//' | head -n 1 || true)

    echo "Nslookup:       ${ns_info:-Sin resolución / Timeout}"
    echo ""
}
#
# ╭───────────────────────────────────────────────────────────────── RDAP
# ╰─────# --- ANÁLISIS CON RDAP
enrich_rdap() {
    local ip="$1" 
    if is_local_ip "$ip"; then
        return
    fi
    # Descarga del JSON (-L para seguir redirecciones de rdap.org)
    JSON_DATA=$(torsocks curl -Ls --max-time 4 "https://rdap.org/ip/$ip" 2>/dev/null || echo "")

    # Validar que la respuesta contenga datos y no un error HTTP o bloqueo
    if [ -n "$JSON_DATA" ] || echo "$JSON_DATA" | grep -q "errorCode"; then
        echo "[!] RDAP: Omitido (Sin datos válidos en rdap)"
        echo ""
        return
    fi
    echo "[+] ANÁLISIS CON RDAP (rdap.org)"
    echo " ╰──────────────────────────────────"
    # Extracción de Datos de Red Generales
    echo ""
    echo "$JSON_DATA" | jq -r '
      "Rango CIDR:      " + (.startAddress // "") + " - " + (.endAddress // "") +
      "\nNombre:            " + (.name // "No disponible") +
      "\nOrigen:            " + (.country // "No disponible") +
      "\nTipo:          " + (.type // "No disponible") +
      "\nEstado:            " + ((.status | join(", ")) // "No disponible")
    '
    # Extracción de FECHAS DE REGISTRO EN EL RIR
    echo "$JSON_DATA" | jq -r '
      .events[]? 
      | .eventAction + ":   " + .eventDate
    '
    # Extracción Completa de Contactos y Entidades (vCards)
    # Procesa la estructura jCard de RDAP para extraer roles y datos limpios
    echo "$JSON_DATA" | jq -r '
      .entities[]? | 
      . as $entidad |
      "" +
      "\nEntidad/ID:        " + ($entidad.handle // "Anon") + 
      "\nRoles:         " + ($entidad.roles | join(", ")) +
      (
        if $entidad.vcardArray then
          [
            $entidad.vcardArray[1][] | 
            if .[0] == "fn" then "\nNombre:         " + .[3]
            elif .[0] == "email" then "\nEmail:     " + .[3]
            elif .[0] == "tel" then "\nTeléfono:    " + .[3]
            elif .[0] == "adr" then "\nDirección:       " + (.[3] | join(", "))
            else empty end
          ] | join("")
        else "" end
      )
    '
    #*** add if ! [ email || entidad || ...]
    ABUSE_EMAIL=$(echo "$JSON_DATA" | jq -r '
      .entities[]? 
      | select(.roles[]? == "abuse") 
      | .vcardArray[1][]? 
      | select(.[0] == "email") 
      | .[3]
    ' | head -n 1)

    # Extracción de Entidades Anidadas (Sub-contactos ocultos deep)
    if [ -z "$ABUSE_EMAIL" ] || [ "$ABUSE_EMAIL" == "null" ]; then
        echo "$JSON_DATA" | jq -r '
          .. | .entities? // empty | .[]? |
          "Sub-Entidad: " + (.handle // "") + " [Roles: " + (.roles | join(", ")) + "]" +
          (
            if .vcardArray then
              [
                .vcardArray[1][] | 
                if .[0] == "email" then " | Email: " + .[3]
                elif .[0] == "fn" then " | Nombre: " + .[3]
                else empty end
              ] | join("")
            else "" end
          )
        '
    fi
    echo ""
}
#
# ╭───────────────────────────────────────────────────────────────── VIRUSTOTAL
# ╰─────# --- ANÁLISIS CON VIRUSTOTAL
enrich_virustotal() {
    local ip="$1"
    if is_local_ip "$ip"; then
        return
    fi
    if [ -z "$VT_API_KEY" ]; then
        echo "[!] VIRUSTOTAL: Omitido (Falta API KEY: https://www.virustotal.com/gui/join-us)"
        echo ""
        return
    fi

    local response
    response=$(torsocks curl --max-time 4 --silent --request GET \
        --url "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
        --header "x-apikey: $VT_API_KEY" || echo "TIMEOUT")
        
    if [ "$response" == "TIMEOUT" ]; then
        echo "[-] Error: La consulta HTTP a VirusTotal superó el tiempo límite de espera."
        echo ""
        return
    fi

    local error_msg
    error_msg=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null || true)
    if [ -n "$error_msg" ]; then
        echo "[-] Error de API VirusTotal: $error_msg"
        echo ""
        return
    fi
    
    local reputation=0 malicious=0 suspicious=0 harmless=0 undetected=0
    reputation=$(echo "$response" | jq -r '.data.attributes.reputation // 0' 2>/dev/null || echo "0")
    malicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0' 2>/dev/null || echo "0")
    suspicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0' 2>/dev/null || echo "0")
    harmless=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.harmless // 0' 2>/dev/null || echo "0")
    undetected=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.undetected // 0' 2>/dev/null || echo "0")
    
    touch "$BAN_VTOT_FILE"

    # Extracción con jq
    local parsed_stats
    parsed_stats=$(echo "$response" | jq -r '
        .data.attributes | 
        "\(.reputation // 0) \(.last_analysis_stats.malicious // 0) \(.last_analysis_stats.suspicious // 0) \(.last_analysis_stats.harmless // 0) \(.last_analysis_stats.undetected // 0)"
    ' 2>/dev/null || echo "0 0 0 0 0")

    # Asignación en memoria de Bash
    read -r reputation malicious suspicious harmless undetected <<< "$parsed_stats"

    # Evaluación de (Malicious >= 1 OR Suspicious >= 1)
    #*** separar y añadir/filtrar valores
    if (( malicious >= 1 || suspicious >= 1 )); then
        echo "[+] ANÁLISIS CON VIRUSTOTAL (API v3)"
        echo " ╰──────────────────────────────────"
        echo -e "${RED} ╰──[!] ALERTA VT: IP Amenaza activa (Maliciosos:${NC}${BOLD} $malicious ${NC}${RED} Sospechosos:${NC}${BOLD} $suspicious ${NC}${RED})${NC}" >&2
        echo -e "${YELLOW} ╰──[+]${NC}${YELLOW} Registrando IP en:${NC} BAN_VTOT_IP.lst ${BOLD}  $ip ${NC}" >&2

        echo "Reputación Global (Score): $reputation"
        echo "Análisis - Maliciosos (Malicious): $malicious"
        echo "Análisis - Sospechosos (Suspicious): $suspicious"
        echo "Análisis - Inofensivos (Harmless): $harmless"
        echo "Análisis - No detectados (Undetected): $undetected"
        echo ""
        
	    # Guarda la IP en el Listado de IPs de VirusTotal
        echo "$ip" >> "$BAN_VTOT_FILE"
    fi
}
#
# ╭───────────────────────────────────────────────────────────────── ALIENVAULT
# ╰─────# --- ANÁLISIS CON ALIENVAULT
enrich_alienvault() {
    local ip="$1"
    if is_local_ip "$ip"; then
        return
    fi

    if [ -z "${OTX_API_KEY:-}" ]; then
        echo "[!] ALIENVAULT: Omitido (Falta OTX_API_KEY: https://otx.alienvault.com)"
        echo ""
        return
    fi

    touch "$BAN_OTX_FILE"

    local response
    response=$(timeout 3 torsocks curl --silent --request GET \
        --url "https://alienvault.com/indicators/IPv4/$ip/general" \
        --header "X-OTX-API-KEY: $OTX_API_KEY" || echo "TIMEOUT")
        
    if [ "$response" == "TIMEOUT" ]; then
        echo "[-] Error: La consulta HTTP a AlienVault superó el tiempo límite."
        echo ""
        return
    fi

    # Extraemos reputación, cantidad de pulsos de amenazas activos y malware asociado con jq
    local parsed_stats
    parsed_stats=$(echo "$response" | jq -r '
        if .error then "ERROR" else
        "\(.reputation // 0) \(.pulse_info.count // 0) \(.false_positive | length)"
        end
    ' 2>/dev/null || echo "0 0 0")

    if [ "$parsed_stats" == "ERROR" ]; then
        echo "[-] Error de API ALIENVAULT: Credenciales inválidas o recurso no encontrado."
        echo ""
        return
    fi

    local reputation=0 pulse_count=0 false_positive_count=0
    read -r reputation pulse_count false_positive_count <<< "$parsed_stats"

    # Añadir a lista de Baneo Si tiene reputación positiva de amenaza || está en al menos 1 campaña/pulso activo
    if (( reputation > 0 || pulse_count >= 1 )); then
        # Excluir Si la comunidad lo ha marcado explícitamente como falso positivo
        if (( false_positive_count == 0 )); then
            echo "[+] ANÁLISIS CON ALIENVAULT (API v1)"
            echo " ╰──────────────────────────────────"
            echo -e "${RED} ╰──[!] ALERTA ALIEN: IP listada en indicadores de compromiso de ciberseguridad${NC}" >&2
            echo -e "${YELLOW} ╰──[+]${NC}${YELLOW} Registrando IP en:${NC} BAN_ALIEN_IP.lst ${BOLD}  $ip ${NC}" >&2
            echo "Reputación de Amenaza: $reputation"
            echo "Campañas Activas:      $pulse_count"
            echo "Falsos Positivos:      $false_positive_count"
            echo ""
            
            # Guarda la IP en el Listado de IPs de Alienvault
            echo "$ip" >> "$BAN_OTX_FILE"
        else
            echo -e "${GREEN} ╰──[*] Omitiendo baneo automático: IP con reporte activo de Falso Positivo ${NC}" >&2
        fi
    fi
    echo ""
}
#
# ╭───────────────────────────────────────────────────────────────── TOR_DNSBL
# ╰─────# --- Análisis con Tor a Listas DNSBL
# - Extrae las IPv4 del archivo Apache/access.log || lee archivo con IPv4 únicas (-i IPv4_únicas.lst)
# ╰─ divide las IPs en bloques de (Por defecto: bloques de 500 IPs)
# ╰─ invoca a torFilter.sh, este lanza consultas en paralelo de (Por defecto: 100 hilos) con xargs -P a listas de reputación de amenazas
# ╰─ torFilter.sh las añade a la lista de baneo si tienen algún positivo
# ╰─ refresca el circuito de Tor (SIGNAL NEWNYM) al finalizar cada bloque.
enrich_tor_dnsbl() {
    # Asegurar que el puerto de control de Tor esté abierto
    if ! grep -q "^ControlPort 9051" /etc/tor/torrc 2>/dev/null; then
        echo -e "${YELLOW}[*] Configurando puerto de control de Tor para permitir SIGNAL NEWNYM ...${NC}"
        echo -e " ╰─${GRENN}[+]${YELLOW} Modificando /etc/tor/torrc (requiere privilegios temporales) ...${NC}"
        echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc > /dev/null
        echo "CookieAuthentication 0" | sudo tee -a /etc/tor/torrc > /dev/null
        echo -e " ╰─${GREEN}[+]${NC} Reiniciando servicio de Tor ..."
        sudo systemctl restart tor
    fi

    ARCH_TEMPORAL=$(mktemp)
    #trap 'rm -f "$ARCH_TEMPORAL"' EXIT SIGINT SIGTERM SIGHUP

    # Extrae IPs de archivo de log o lee archivo con IPv4 únicas
    if [[ "$IP_LOG" == 0 ]]; then
        awk '{
            for(i=1; i<=NF; i++) {
                if($i ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
                    print $i
                    next
                }
            }
        }' "$LOG_FILE" | sort -u > "$ARCH_TEMPORAL"
    else
        cat "$LOG_FILE" | sort -u > "$ARCH_TEMPORAL"
    fi

    TOTAL_IPS=$(wc -l < "$ARCH_TEMPORAL")
    if [ "$TOTAL_IPS" -eq 0 ]; then
        echo -e "\n${RED}[-]${NC} Análisis finalizado. No se detectaron IPs con patrones de amenaza.${NC}"
        exit 0
    fi
    echo -e " ╰─${GREEN}[+] Se han encontrado${NC} $TOTAL_IPS ${GREEN}direcciones IP para consultar${NC}"
    echo -e " ╰─${CYAN}${BOLD}[?]${NC} Consultar IPs en listas DNSBL? (Y/n)v:${NC}"
    read -r proceed < /dev/tty
    if [[ "$proceed" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}[!] Operación cancelada${NC}"
        exit 0
    fi
    if [[ "$proceed" =~ ^[Vv]$ ]]; then
        cat "$ARCH_TEMPORAL" | sort -n
        echo -e "\n${YELLOW}${BOLD}[>]${NC} Consultar IPs? (Y/n):${NC}"
        read -r proced < /dev/tty
        if [[ "$proced" =~ ^[Nn]$ ]]; then
            echo -e "${YELLOW}[!] Operación cancelada${NC}"
            exit 0
        fi    
    fi

    # Iniciar bloque de IPs
    echo -e "${YELLOW}[>]${NC} - Iniciando procesamiento por bloques paralelos con rotación de circuito Tor"
    CONTADOR=0
    BLOQUE_ACTUAL=()
    while IFS= read -r ip; do
        BLOQUE_ACTUAL+=("$ip")
        CONTADOR=$((CONTADOR + 1))
        # Cuando el bloque alcanza el tamaño límite o se llega al final del archivo
        if [ "${#BLOQUE_ACTUAL[@]}" -eq "$IP_TOR_BLOCK" ] || [ "$CONTADOR" -eq "$TOTAL_IPS" ]; then
            echo -e "${CYAN} ╰─[+] Procesando bloque${NC} ($CONTADOR/$TOTAL_IPS)${CYAN} |${NC} ${#BLOQUE_ACTUAL[@]} ${CYAN}Consultas${NC} ${HILOS_XARGS} ${CYAN}Hilos en paralelo ${NC}"
            
            # Inyectar el bloque en (xargs -P ${HILOS_XARGS}) para la ejecución en paralelo
            printf "%s\n" "${BLOQUE_ACTUAL[@]}" | xargs -I {} -P "${HILOS_XARGS}" ./torFilter.sh "{}"

            # Vaciar el bloque para la siguiente iteración
            BLOQUE_ACTUAL=()

            # Forzar cambio de circuito de Tor (SIGNAL NEWNYM) a través del puerto de control 9051
            echo -e "${GREEN}[*] Rotando circuito de Tor para refrescar IP de salida ...${NC}"
            echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT" | nc 127.0.0.1 9051 > /dev/null
            
            # Pausa de 2 segundos para permitir que Tor termine de construir los nuevos túneles
            sleep 2
        fi
    done < "$ARCH_TEMPORAL"

    echo -e ""
    echo -e "${GREEN}[+] Análisis de logs completado${NC}"
    echo -e "${GREEN}[+] Archivo de IPv4 únicas en:${NC} $BAN_TOR_IP"
    echo -e " ╰─${GREEN}${BOLD}[+] Ruta Copiada!${NC}"
    echo "$BAN_TOR_IP" | xclip -sel clip
    LOG_FILE=$BAN_TOR_IP
}
#
# ╭───────────────────────────────────────────────────────────────── MAIN
# ╰─────# --- PROCESO INICIAL logFilter.sh
main() {
    ARCH_TEMPORAL=$(mktemp)
    #trap 'rm -f "$ARCH_TEMPORAL"' EXIT SIGINT SIGTERM SIGHUP
    # Extraer IPv4 de archivo de log / leer archivo de IPs únicas
    if [[ "$IP_LOG" == 0 ]]; then
        awk '{
            for(i=1; i<=NF; i++) {
                if($i ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
                    print $i
                    next
                }
            }
        }' "$LOG_FILE" | sort -u > "$ARCH_TEMPORAL"
    else
        cat "$LOG_FILE" | sort -u > "$ARCH_TEMPORAL"
    fi

    TEMP_IP_LIST=$ARCH_TEMPORAL

    local ip_count
    ip_count=$(wc -l < "$TEMP_IP_LIST" | tr -d ' ')
    if [ "$ip_count" -eq 0 ]; then
        echo -e "\n${GREEN}[*] Análisis finalizado. No se detectaron IPv4 con patrones de amenaza${NC}"
        exit 0
    fi
    
    echo -e "${GREEN}[+] Encontradas${NC} $ip_count ${GREEN}IPv4 sospechosas${NC}"
    echo -e " ╰─${CYAN}${BOLD}[?]${NC} Analizar IPs? (Y/n)v:${NC}"
    
    read -r proceed < /dev/tty
    if [[ "$proceed" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}[!] Operación cancelada${NC}"
        exit 0
    fi
    if [[ "$proceed" =~ ^[Vv]$ ]]; then
        cat "$TEMP_IP_LIST" | sort -n
        echo -e "\n${YELLOW}${BOLD}[>]${NC} Analizar IPs? (Y/n):${NC}"
        read -r proced < /dev/tty
        if [[ "$proced" =~ ^[Nn]$ ]]; then
            echo -e "${YELLOW}[!] Operación cancelada${NC}"
            exit 0
        fi    
    fi
    echo -e "\n${YELLOW}[>] Procesando IPs ...${NC}\n"
    {
        echo ""
        echo ""
        echo "╭─────────────────────────────────────────────────────────────────"
        echo "| REPORTE:  $0"
        echo "| Usuario:  $USER"
        echo "| Fecha:    $fecha"
        echo "| Archivo:  $LOG_FILE"
        echo "╰─────────────────────────────────────────────────────────────────"
        echo ""
        
        # Descriptor de archivos 3 (<&3) para alimentar el bucle = Evita que curl, host o nslookup intercepten o vacíen la lista de IPs
        while IFS= read -r ip <&3; do
            if [ -n "$ip" ]; then
                echo -e "${CYAN}[*] Analizando IP: $ip ${NC}" >&2
                # Filtra IPs por Países
                enrich_network "$ip"
                # Obtiene Datos de Red 
                enrich_rdap "$ip"
                #** add condicionales de enrich_network || enrich_rdap
                # Filtra IPs con Reputación en VirusTotal
                enrich_virustotal "$ip"
                # Filtra IPs con +1 Campaña/Pulso Activo en Alienvault
                enrich_alienvault "$ip"
            fi
            # Control de tasa para la API pública de VirusTotal (4 peticiones/minuto) VERSION PRO: ~20000$USD/año < "Google"
            #sleep 16
        done 3< "$TEMP_IP_LIST"
        
    } > "$REPORT_FILE"
    
    echo -e "\n${GREEN}[+] Completado ${NC}"
    echo -e "${GREEN}[+] Reporte guardado en:${NC} $REPORT_FILE\n"
    echo -e " ╰─${GREEN}${BOLD}[+] Ruta Copiada!${NC}"
    echo "$REPORT_FILE" | xclip -sel clip
    LOG_FILE=$REPORT_FILE
}
#
# ╭───────────────────────────────────────────────────────────────── INICIO
# ╰───── 
#
banner
#
check_dependencias

# Parsear argumentos de la CLI
while getopts "f:i:b:p:mc:h" opt; do
    case "$opt" in
        f) LOG_FILE="$OPTARG" ;;
        i) LOG_FILE="$OPTARG"; IP_LOG=1 ;;
        b) IP_TOR_BLOCK="$OPTARG" ;;
        p) HILOS_XARGS="$OPTARG" ;;
        m) extract_malicious_ips; LOG_FILE="$BAN_REQUEST_FILE"; IP_LOG=1; enrich_tor_dnsbl; exit ;;
        c)
            SCAN_OPT=1
            for SCAN_TOOL in $OPTARG; do
                test_log
                case "${SCAN_TOOL[@]}" in
                    api)
                        # Obtiene Datos de Red y Filtra IPs por Países
                        enrich_network "$ip"
                    ;;
                    rd)
                        # Obtiene Datos de Red, Entidades, Roles y abuse-email
                        enrich_rdap "$ip"
                    ;;
                    dns) 
                        # Análisis con Tor a Listas DNSBL
                        enrich_tor_dnsbl; exit
                    ;;
                    vt)
                        # Filtra IPs con Reputación en VirusTotal
                        enrich_virustotal "$ip"
                    ;;
                    av)
                        # Filtra IPs con +1 Campaña/Pulso Activo en Alienvault
                        enrich_alienvault "$ip"
                    ;;
                    x)
                        # Consulta IPs en TODAS las listas 
                        enrich_tor_dnsbl
                        main; exit
                    ;;
                    *)
                        ayuda
                    ;;
                esac
            done
        ;;
        h)
            ayuda
        ;;
    esac
    #test_log
    #main
done
#test_log; extract_malicious_ips; LOG_FILE="$BAN_REQUEST_FILE"; IP_LOG=1; enrich_tor_dnsbl
#
enrich_tor_dnsbl
#main
exit

