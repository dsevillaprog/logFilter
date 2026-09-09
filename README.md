### <img src="../../../CURSO-CSS/blob/main/img/cmd-g.png" alt="Script" width="auto" height="25"> &MediumSpace; <img src="../../../CURSO-CSS/blob/main/img/gnu-g.png" alt="Linux" width="auto" height="25"> <img src="../../../CURSO-CSS/blob/main/Ejercicio4/img/tor.png" alt="Tor" width="auto" height="25"> &MediumSpace; logFilter.sh
##  

##### ⓘ  Descripción

  - Filtra y consulta direcciones IPv4 con herramientas online y en listas de reputación de amenazas (DNSBL)


##### ⚙  Características

    ╰─ Extrae las IPv4 del archivo Apache/access.log || lee archivo de IPv4 únicas (-i IPv4_únicas.lst)
    ╰─ Filtra por peticiones maliciosas y país
    ╰─ Consulta a Herramientas Online
    ╰─ Divide las consultas en bloques de (Por defecto: 500 IPs) para rotar la IP con Tor
    ╰─ Lanza consultas en paralelo con xargs/Tor de (Por defecto: 100 hilos) a listas de reputación de amenazas (DNSBL)
    ╰─ Se añaden a listas de baneo si obtienen algún positivo
    ╰─ Refresca a IP de Tor al finalizar cada bloque de IPs


###### ☰  Dependencias:
   ```bash
   gawk curl dnsutils bind9-host jq netcat-openbsd dnsutils coreutils tor torsocks xclip
   ```

##  
##### 🛠  Instalación
1. Clonar el repositorio:
   ```bash
   git clone https://github.com/dsevillaprog/logFilter.git
   ```
   
2. Dar permisos de ejecución:
   ```bash
   cd logFilter
   chmod +x *.sh
   ```

3. Ejecutar el script:
   ```bash
   ./logFilter.sh h
   ```


##### ⚙  API Keys:
VirusTotal:
  * Crear una cuenta (https://www.virustotal.com/gui/join-us)-> API -> Click en "Get your API key" -> Copiar API_KEY
  * Pegar en logFilter.sh `VT_API_KEY="VIRUSTOTAL_API_KEY"`

Alienvault:
  * Crear una cuenta (https://otx.alienvault.com/)-> API KEY -> Copiar API_KEY
  * Pegar en logFilter.sh `OTX_API_KEY="ALIENVAULT_API_KEY"`
    

##  
##### »  Uso:
   `./logFilter.sh -f LOGFILE] [-i IPV4LST] [-b IP_BLOCK] [-p HILOS] [-c TOOL] [-m] ]`

##  
###### »  Ejemplos de uso:

   ```bash
   ./logFilter.sh -f apache.log [-b <IP_TOR_BLOCK>] [-p <HILOS>]
   ./logFilter.sh -i IPv4_u.lst [-b <IP_TOR_BLOCK>] [-p <HILOS>]
   ./logFilter.sh -f apache.log -c [api rd dns vt av x]
   ./logFilter.sh -i IPv4_u.lst -c [api rd dns vt av x]
   ./logFilter.sh -f apache.log -m
   ```
    
  
##  
###### logFilter.sh
![logFilter](../../../CURSO-CSS/blob/main/Ejercicio2/img/logFilter.png?raw=true)
##  
![logFilter](../../../CURSO-CSS/blob/main/Ejercicio2/img/logFilter-1.png?raw=true)
##  
