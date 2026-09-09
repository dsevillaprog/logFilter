#!/usr/bin/env bash
#
# ╭───────────────────────────────────────────────────────────────────────────────────────
# ╰── Script 2/2: torFilter.sh << Invocado desde logFilter.sh mediante (xargs -I {$LOTE_IPs} -P $HILOS_PARALELOS)
#
# - Consulta una sola dirección IP de forma aislada a través de la red Tor a Listas DNSBL
# ╰─ Si la IP ha sido reportada en alguna lista, imprime el reporte y la añade a lista de IPs con positivos
#
# Coded by: ᗪᔕᵉᵛⁱˡˡᵃᑭʳᵒᵍ © 2026
#
# ╭──────────────────────────────────
# ╰───── CONFIGURACIÓN Y VARIABLES
#
# Control de errores
set -euo pipefail
#set -x

# Cierra el programa con Ctrl+c
trap ctrl_c INT
ctrl_c() {
	#echo -e "\n\n$c_roj [*] Cerrando ... $c_bla\n"
	exit 1
}

# --- Rutas
RUTA=$(pwd)

# Lista de IPs con positivos >= 1
BAN_TOR_IP="${RUTA}/BAN_TOR_IP.lst"

# --- Filtros
# Validar que se pasa una IP como argumento
if [ -z "${1:-}" ]; then
    exit 0
fi

IP_A_COMPROBAR="$1"

# Filtro de rangos internos, direcciones locales y DNS
regex_exclusion='^(8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9|127\.0\.0\.1|::1)$'
if [[ "${IP_A_COMPROBAR}" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]] || 
   [[ "${IP_A_COMPROBAR}" == "::1" ]] || 
   [[ "${IP_A_COMPROBAR}" =~ ^fe80: ]] || 
   [[ "${IP_A_COMPROBAR}" =~ $regex_exclusion ]]; then
    exit 0
fi

# IP invertida para la consulta DNSBL
IP_INVERTIDA=$(echo "${IP_A_COMPROBAR}" | awk -F. '{print $4"."$3"."$2"."$1}')

# --- Variables para almacenar resultados
RES_SPAMHAUS=""
RES_BARRACUDA=""
RES_DRONEBL=""
RES_SORBS=""
RES_URLHAUS=""
POSITIVOS=0

# --- Colores
NC='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'

#
# ╭───────────────────────────────────────────────────────────────── INICIO
# ╰─────
#
## --- Consultas a listas DNSBL a través de Tor
RES_SPAMHAUS=$(torsocks dig +short "${IP_INVERTIDA}.xbl.spamhaus.org" +tcp 2>/dev/null || echo "")
[ -n "$RES_SPAMHAUS" ] && POSITIVOS=$((POSITIVOS + 1))

RES_BARRACUDA=$(torsocks dig +short "${IP_INVERTIDA}.b.barracudacentral.org" +tcp 2>/dev/null || echo "")
[ -n "$RES_BARRACUDA" ] && POSITIVOS=$((POSITIVOS + 1))

RES_DRONEBL=$(torsocks dig +short "${IP_INVERTIDA}.dnsbl.dronebl.org" +tcp 2>/dev/null || echo "")
[ -n "$RES_DRONEBL" ] && POSITIVOS=$((POSITIVOS + 1))

RES_SORBS=$(torsocks dig +short "${IP_INVERTIDA}.dul.dnsbl.sorbs.net" +tcp 2>/dev/null || echo "")
[ -n "$RES_SORBS" ] && POSITIVOS=$((POSITIVOS + 1))

RES_URLHAUS=$(torsocks curl -s --max-time 4 -X POST https://abuse.ch -d "host=${IP_A_COMPROBAR}" 2>/dev/null | grep -o '"host_status": "malicious"' 2>/dev/null || echo "")
[ -n "$RES_URLHAUS" ] && POSITIVOS=$((POSITIVOS + 1))

# Si la IP tiene reportes, imprime la alerta y la añade a la lista de IPs con positivos
if [ "$POSITIVOS" -gt 0 ]; then
    echo -e "${RED} ╰─[!] ALERTA DNSBL:${NC} $POSITIVOS  ${RED}positivos para:${NC} ${IP_A_COMPROBAR}" & echo "${IP_A_COMPROBAR}" >> "${BAN_TOR_IP}"
fi

