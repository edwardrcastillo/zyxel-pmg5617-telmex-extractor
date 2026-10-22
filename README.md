# 📡 Zyxel PMG5617-T20B (Telmex) — Extractor Forense de Credenciales y Telemetría

Herramienta autónoma en Python diseñada para interactuar con la API criptográfica interna de la ONT GPON **Zyxel PMG5617-T20B** (distribuida ampliamente por **Telmex** en servicios de fibra óptica Infinitum). 

Permite la identificación automática de la pasarela y la extracción transparente de credenciales críticas de red, cuentas VoIP SIP y telemetría óptica de enlace GPON.

---

## ⚡ ¿Qué hace este script?

El módem Zyxel PMG5617-T20B implementa un esquema de autenticación web de dos capas para proteger sus endpoints de configuración:
1. **Handshake Asimétrico RSA-2048:** El script consulta el endpoint `/getRSAPublickKey` para obtener la clave pública del router.
2. **Cifrado Simétrico AES-256-CBC de Sesión:** Genera una clave AES efímera y un vector de inicialización (IV) criptográficamente seguros (`os.urandom`), cifra las credenciales de acceso y cifra la clave AES con la clave pública RSA para enviarla a `/UserLogin`.
3. **Detección Automática de Pasarela Multiplataforma:** Identifica de forma nativa la IP local del router en **Windows**, **macOS** y **Linux** sin requerir intervención del usuario.
4. **Consulta al Data Access Layer (DAL):** Una vez autenticado, interroga los descriptores de objetos (`DAL?oid=...`) descifrando las respuestas dinámicas para extraer la configuración completa.
5. **Cierre de Sesión Limpio (`UserLogout`):** Garantiza la liberación inmediata de la sesión mediante un bloque `finally`, evitando que el router bloquee accesos posteriores con el error de protección *"Duplicated login"*.

---

## 🎯 ¿Qué se puede hacer con la información extraída?

La extracción de estos datos desbloquea el control total de la infraestructura de red sin depender de las restricciones del firmware del ISP:

### 1. Configuración de Router Neutro en Modo Puente (Bridge)
* **Objetivo:** Delegar las funciones de NAT, cortafuegos y ruteo perimetral a routers profesionales como **pfSense**, **OPNsense**, **OpenWrt**, **MikroTik RouterOS** o gateways personalizados como **PuertaOS**.
* **Parámetros extraídos necesarios:**
  * **Usuario PPPoE:** `88ACC0LZXYGXXXXXXXX@prodigyweb.com.mx`
  * **Contraseña PPPoE:** Clave en texto claro de 30 caracteres.
  * **VLAN Tagging (802.1Q):** Subinterfaz WAN etiquetada en **VLAN ID 881** con prioridad CoS `0` y MTU `1492`.

### 2. Sustitución Completa de la ONT por un Módulo SFP GPON Stick
* **Objetivo:** Eliminar el módem físico del operador y conectar la fibra óptica directamente a una tarjeta SFP+ en un servidor o switch administrado.
* **Parámetros extraídos necesarios:**
  * **GPON Serial Number (ASCII / HEX):** Para autenticación en la OLT Telmex.
  * **Manufacturer OUI:** Prefijo MAC registrado en la cabecera OLT (`88ACC0`).
  * **Modo de Operación OMCI:** Estado operacional sincronizado (**O5**).

### 3. Telefonía Fija en Computadora o Smartphone (VoIP SIP IMS)
* **Objetivo:** Desviar o contestar llamadas de la línea fija directamente desde un softphone en PC (MicroSIP, Zoiper, Linphone) o registrar la línea en una centralita PBX local (**Asterisk**, **FreePBX**, **3CX**).
* **Parámetros extraídos necesarios:**
  * **Directorio Telefónico:** Número a 10 dígitos (ej. `+5255XXXXXXXX`).
  * **Usuario SIP / Digest:** `+5255XXXXXXXX@vims-h.telmex.com`
  * **Contraseña SIP:** Secret de autenticación SIP del núcleo IMS.
  * **Proxy / Registrar:** `vims-h.telmex.com:5060` (UDP) y Outbound Proxy regional.
  * **Códecs:** Compatibilidad con `G.711A`, `G.711U` y `G.729`.

### 4. Monitoreo y Diagnóstico Continuo de Salud Óptica
* **Objetivo:** Supervisar la calidad de la señal de fibra óptica en tiempo real para anticipar cortes o degradaciones de enlace.
* **Parámetros extraídos:**
  * **Potencia de Recepción (Rx dBm):** Nivel de luz recibido (rango óptimo: -14 dBm a -24 dBm).
  * **Potencia de Transmisión (Tx dBm):** Potencia emitida por el láser del transceptor.
  * **Temperatura y Voltaje:** Condiciones térmicas del módulo óptico interno.

---

## 💻 Requisitos Previos

* **Python:** Versión 3.8 o superior.
* **Librería de Criptografía:**
  ```bash
  pip install cryptography
  ```

---

## 🚀 Ejemplos de Uso por Sistema Operativo

### 🪟 1. Windows (PowerShell o Símbolo del Sistema CMD)

El script detecta automáticamente la IP del router mediante `route print`, `ipconfig` (en español o inglés) o PowerShell.

#### Modo Interactivo (Solo solicita la contraseña de forma segura):
```powershell
python zyxel_pmg5617_extractor.py
```
*Salida en PowerShell:*
```text
[+] IP del router identificada automáticamente: 192.168.1.254
🔑 Ingrese el password del router (192.168.1.254): ********
[*] Conectando con el router e iniciando handshake criptográfico...
[✔] Extracción completada exitosamente.
```

#### Modo Desatendido (Especificando contraseña por parámetro):
```powershell
python zyxel_pmg5617_extractor.py -p TuPasswordDeEtiqueta
```

#### Exportar datos a un archivo JSON estructurado:
```powershell
python zyxel_pmg5617_extractor.py -p TuPasswordDeEtiqueta --json -o credenciales_extraidas.json
```

---

### 🍎 2. macOS (Terminal / zsh)

El script utiliza la tabla de enrutamiento del kernel Darwin (`route -n get default`) para determinar la IP del módem al instante.

#### Ejecución Directa:
```zsh
python3 zyxel_pmg5617_extractor.py
```

#### Ejecución con tubería (Piped input):
```zsh
echo "TuPasswordDeEtiqueta" | python3 zyxel_pmg5617_extractor.py
```

#### Especificar una IP personalizada (en caso de subredes no estándar):
```zsh
python3 zyxel_pmg5617_extractor.py --host 192.168.100.254 -p TuPasswordDeEtiqueta
```

---

### 🐧 3. Linux (Ubuntu / Debian / Arch / Fedora)

Compatible con `iproute2` (`ip route show default`) y entornos sin entorno gráfico (servidores headless / Raspberry Pi).

#### Dar permisos de ejecución y correr:
```bash
chmod +x zyxel_pmg5617_extractor.py
./zyxel_pmg5617_extractor.py
```

#### Exportar informe completo para documentación técnica:
```bash
./zyxel_pmg5617_extractor.py -p TuPasswordDeEtiqueta -o reporte_enlace.md
```

---

## 📋 Ejemplo de Salida en Consola *(Datos Simulados)*

> [!NOTE]
> La siguiente salida presenta valores ficticios con fines ilustrativos. Tus datos reales reflejarán la información de tu circuito y línea contratada.

```text
======================================================================
      REPORTE FORENSE DE CREDENCIALES — ROUTER TELMEX ZYXEL         
======================================================================
Dirección IP Pasarela:   192.168.1.254
Fabricante:              Zyxel Communications Corp.
Modelo Detectado:        PMG5617-T20B
Plataforma SoC:          ECONET (MediaTek)
Versión de Firmware:     V541ABYR0b15
Número de Serie GPON:    ZXYG99999999
Estado GPON:             O5 (O5 = Sincronizado Operativo)
Potencia Óptica Rx:      -18.45 dBm
Potencia Óptica Tx:      2.30 dBm
Temperatura Interna:     58.20 °C
----------------------------------------------------------------------
🌐 [INTERNET / WAN PPPoE]
Usuario PPPoE:           88ACC0LZXYG99999999@prodigyweb.com.mx
Contraseña PPPoE:        3a819769xxxxxxxxxxxxxxxxxxxxxx
VLAN ID:                 881 (Prioridad 802.1p: 0)
IP WAN Asignada:         10.140.85.12
Gateway Concentrador:    200.38.193.1
Servidores DNS IPv4:     201.144.126.229, 200.33.148.213
Dirección IPv6 WAN:      fc00:1090:9:f234::1/64
Servidores DNS IPv6:     2806:1080:ffff:3::e, 2806:1090:ffff:102::e
----------------------------------------------------------------------
📞 [TELEFONÍA FIJA VOIP / SIP IMS]
Número Telefónico Fijo:  +525512345678
Usuario Autenticación:   +525512345678@vims-h.telmex.com
Contraseña SIP:          e5a9ecxxxxxx
Estado de la Línea:      Up
Proxy / Registrar IMS:   vims-h.telmex.com:5060 (UDP)
Outbound Proxy:          nir8.norte.telmex.net:5060 (UDP)
----------------------------------------------------------------------
📶 [REDES WI-FI]
SSID 2.4 GHz:            INFINITUM_DEMO_2.4 (Canal: 6)
BSSID 2.4 GHz (MAC):     10:71:B3:00:AA:01
Contraseña WPA2 2.4 GHz: WpaPass_Simulada_123!
SSID 5.0 GHz:            INFINITUM_DEMO_5.0 (Canal: 149, 80MHz)
BSSID 5.0 GHz (MAC):     10:71:B3:00:AA:02
Contraseña WPA2 5.0 GHz: WpaPass_Simulada_123!
======================================================================
```

---

## 🔒 Consideraciones de Seguridad y Privacidad

* **Nunca compartas tus credenciales reales:** El archivo generado contiene identificadores unívocos de tu servicio de fibra óptica y claves de registro telefónico.
* **Uso Legítimo:** Esta herramienta está destinada a labores de auditoría de seguridad defensiva, migración de infraestructura propia, optimización de redes domésticas/empresariales e investigación técnica.

---

## 📄 Licencia

Este proyecto está bajo la Licencia [MIT](LICENSE).
