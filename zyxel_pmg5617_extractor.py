#!/usr/bin/env python3
"""
Zyxel PMG5617-T20B (Telmex) - Extractor Automatizado de Credenciales y Telemetría
Detección automática de IP de pasarela + Handshake Criptográfico Híbrido (RSA-2048 + AES-256-CBC)
"""

import sys
import os
import re
import json
import base64
import getpass
import argparse
import subprocess
import urllib.request
import urllib.error
from datetime import datetime

# Dependencias criptográficas nativas
try:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import serialization, padding as sym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("\n[!] Error: Se requiere el paquete 'cryptography'.")
    print("    Instálalo ejecutando: pip install cryptography\n")
    sys.exit(1)


def detectar_ip_router():
    """Detecta de forma autónoma la IP del gateway predeterminado en Windows, macOS y Linux."""
    # 1. Métodos específicos para Windows
    if sys.platform.startswith('win'):
        # 1.1 Intentar comando nativo 'route print 0.0.0.0'
        try:
            salida = subprocess.check_output(['route', 'print', '0.0.0.0'], stderr=subprocess.DEVNULL, text=True)
            m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', salida)
            if m and m.group(1).strip() != "0.0.0.0":
                return m.group(1).strip()
        except Exception:
            pass

        # 1.2 Intentar 'ipconfig' (soporta interfaces en Español e Inglés)
        try:
            salida = subprocess.check_output(['ipconfig'], stderr=subprocess.DEVNULL, text=True, errors='ignore')
            matches = re.findall(
                r'(?:Default Gateway|Puerta de enlace predeterminada)[^\r\n:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
                salida,
                re.IGNORECASE
            )
            for ip in matches:
                ip = ip.strip()
                if ip and ip != "0.0.0.0":
                    return ip
        except Exception:
            pass

        # 1.3 Intentar PowerShell Get-NetRoute
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop"]
            salida = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
            ips = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', salida)
            for ip in ips:
                if ip and ip != "0.0.0.0":
                    return ip
        except Exception:
            pass

    # 2. Método específico para macOS
    if sys.platform == 'darwin':
        try:
            salida = subprocess.check_output(['route', '-n', 'get', 'default'], stderr=subprocess.DEVNULL, text=True)
            m = re.search(r'gateway:\s*(\S+)', salida)
            if m:
                return m.group(1).strip()
        except Exception:
            pass

    # 3. Método específico para Linux
    try:
        salida = subprocess.check_output(['ip', 'route', 'show', 'default'], stderr=subprocess.DEVNULL, text=True)
        m = re.search(r'default via\s*(\S+)', salida)
        if m:
            return m.group(1).strip()
    except Exception:
        pass

    # 4. Fallback universal Unix/BSD
    try:
        salida = subprocess.check_output(['netstat', '-rn'], stderr=subprocess.DEVNULL, text=True)
        m = re.search(r'(?:default|0\.0\.0\.0)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', salida)
        if m:
            return m.group(1).strip()
    except Exception:
        pass

    # 5. Fallback estándar para routers Telmex
    return "192.168.1.254"



class ZyxelPMG5617Extractor:
    def __init__(self, host, password, username="TELMEX"):
        self.host = host
        self.password = password
        self.username = username
        self.session_cookie = None
        self.session_key = None
        self.aes_key = None

    def _decrypt_payload(self, data):
        """Descifra la respuesta cifrada en AES-256-CBC devuelta por el router."""
        if isinstance(data, dict) and "content" in data and "iv" in data and self.aes_key:
            dec_iv = base64.b64decode(data["iv"])[:16]
            ciphertext = base64.b64decode(data["content"])
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(dec_iv))
            decryptor = cipher.decryptor()
            padded_pt = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            pt = unpadder.update(padded_pt) + unpadder.finalize()
            return json.loads(pt.decode('utf-8'))
        return data

    def login(self):
        """Realiza el handshake RSA y la autenticación cifrada en AES-256-CBC."""
        # 1. Obtener la clave pública RSA del router
        url_rsa = f"http://{self.host}/getRSAPublickKey"
        try:
            req = urllib.request.urlopen(url_rsa, timeout=8)
            rsa_resp = json.loads(req.read().decode('utf-8'))
            rsa_pem = rsa_resp.get("RSAPublicKey")
            if not rsa_pem:
                raise ValueError("No se recibió la clave pública RSA del router.")
            pub_key = serialization.load_pem_public_key(rsa_pem.encode('utf-8'))
        except Exception as e:
            raise RuntimeError(f"Error conectando con el router en {self.host}: {e}")

        # 2. Generar llaves efímeras AES-256 (32 bytes) y vector IV (16 bytes)
        self.aes_key = os.urandom(32)
        aes_key_b64 = base64.b64encode(self.aes_key).decode('utf-8')
        iv = os.urandom(16)
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        # 3. Preparar credenciales cifradas en Base64
        pass_b64 = base64.b64encode(self.password.encode('utf-8')).decode('utf-8')
        auth_payload = json.dumps({
            "Input_Account": self.username,
            "Input_Passwd": pass_b64,
            "currLang": "sp",
            "RememberPassword": 0,
            "SHA512_password": False
        })

        # Cifrar payload con AES-256-CBC (PKCS7)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(auth_payload.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        enc_content = encryptor.update(padded_data) + encryptor.finalize()
        enc_content_b64 = base64.b64encode(enc_content).decode('utf-8')

        # Cifrar la clave AES con la clave pública RSA (PKCS1 v1.5)
        enc_key = pub_key.encrypt(aes_key_b64.encode('utf-8'), asym_padding.PKCS1v15())
        enc_key_b64 = base64.b64encode(enc_key).decode('utf-8')

        # 4. Enviar solicitud de autenticación a /UserLogin
        body_login = json.dumps({
            "content": enc_content_b64,
            "key": enc_key_b64,
            "iv": iv_b64
        }).encode('utf-8')

        req_login = urllib.request.Request(
            f"http://{self.host}/UserLogin",
            data=body_login,
            headers={"Content-Type": "text/plain;charset=UTF-8"}
        )

        try:
            resp = urllib.request.urlopen(req_login, timeout=10)
            raw_cookie = resp.headers.get("Set-Cookie", "")
            if raw_cookie:
                self.session_cookie = raw_cookie.split(";")[0]

            login_raw = json.loads(resp.read().decode('utf-8'))
            login_data = self._decrypt_payload(login_raw)

            if login_data.get("result") == "Duplicated login":
                raise PermissionError("Existe otra sesión activa en el módem. Espera un minuto o ciérrala en el navegador.")

            if login_data.get("result") != "ZCFG_SUCCESS":
                raise PermissionError("Contraseña incorrecta o acceso rechazado por el router.")

            self.session_key = login_data.get("sessionkey")
            return login_data
        except urllib.error.HTTPError as e:
            if e.code == 401:
                try:
                    err_json = json.loads(e.read().decode('utf-8'))
                    if err_json.get("result") == "Duplicated login":
                        raise PermissionError("Sesión duplicada: Ya hay una sesión abierta en el módem.")
                except Exception:
                    pass
                raise PermissionError("Contraseña incorrecta o permisos insuficientes.")
            raise

    def query_cgi(self, path):
        """Consulta endpoints del Data Access Layer (DAL) descifrando la respuesta."""
        sep = "&" if "?" in path else "?"
        url = f"http://{self.host}{path}{sep}sessionkey={self.session_key}"
        headers = {}
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return self._decrypt_payload(data)

    def logout(self):
        """Cierra la sesión limpiamente para no bloquear futuros accesos."""
        if self.session_key and self.session_cookie:
            try:
                url = f"http://{self.host}/cgi-bin/UserLogout?sessionkey={self.session_key}"
                req = urllib.request.Request(url, data=b'', headers={"Cookie": self.session_cookie})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

    def extract_full_profile(self):
        """Extrae la totalidad de credenciales, red WAN, SIP, Wi-Fi y estado GPON."""
        self.login()
        results = {}
        try:
            # Bandera de interfaz gráfica
            try:
                with urllib.request.urlopen(f"http://{self.host}/getWebGuiFlag", timeout=5) as r:
                    results["gui_flags"] = json.loads(r.read().decode('utf-8'))
            except Exception:
                results["gui_flags"] = {}

            results["basic"] = self.query_cgi("/cgi-bin/getBasicInformation")
            results["status"] = self.query_cgi("/cgi-bin/DAL?oid=status")
            results["wan"] = self.query_cgi("/cgi-bin/DAL?oid=wan")
            results["sip_account"] = self.query_cgi("/cgi-bin/DAL?oid=sip_account")
            results["wlan"] = self.query_cgi("/cgi-bin/DAL?oid=wlan")
            results["tr69"] = self.query_cgi("/cgi-bin/DAL?oid=tr69")
            results["lanhosts"] = self.query_cgi("/cgi-bin/DAL?oid=lanhosts")
        finally:
            self.logout()

        return results


def imprimir_reporte(data, host):
    """Presenta el informe técnico estructurado con estética profesional."""
    basic = data.get("basic", {})
    status_obj = (data.get("status", {}).get("Object") or [{}])[0]
    gpon = (status_obj.get("GponStatsInfo") or {}).get("gponStatusObj") or {}
    wan = (data.get("wan", {}).get("Object") or [{}])[0]
    sip = (data.get("sip_account", {}).get("Object") or [{}])[0]
    wlan_list = data.get("wlan", {}).get("Object") or []
    gui_flags = data.get("gui_flags", {})

    wlan_24 = next((w for w in wlan_list if w.get("band") == "2.4GHz" and w.get("MainSSID")), {})
    wlan_50 = next((w for w in wlan_list if w.get("band") == "5GHz" and w.get("MainSSID")), {})

    print("\n" + "=" * 70)
    print("      REPORTE FORENSE DE CREDENCIALES — ROUTER TELMEX ZYXEL         ")
    print("=" * 70)
    print(f"Dirección IP Pasarela:   {host}")
    print(f"Fabricante:              Zyxel Communications Corp.")
    print(f"Modelo Detectado:        {basic.get('ModelName') or gui_flags.get('ModelName', 'PMG5617-T20B')}")
    print(f"Plataforma SoC:          {gpon.get('Platform', 'EcoNet EN75XX')} (MediaTek)")
    print(f"Versión de Firmware:     {basic.get('SoftwareVersion', 'N/A')}")
    print(f"Número de Serie GPON:    {gpon.get('SerialNumber', wan.get('SerialNumber', 'N/A'))}")
    print(f"Estado GPON:             {gpon.get('GPONStatus', 'N/A')} (O5 = Sincronizado Operativo)")
    print(f"Potencia Óptica Rx:      {(gpon.get('rxPower') or '').strip()} dBm")
    print(f"Potencia Óptica Tx:      {(gpon.get('txPower') or '').strip()} dBm")
    print(f"Temperatura Interna:     {gpon.get('temperature', 'N/A')} °C")
    print("-" * 70)

    print("🌐 [INTERNET / WAN PPPoE]")
    print(f"Usuario PPPoE:           {wan.get('pppUsername', 'N/A')}")
    print(f"Contraseña PPPoE:        {wan.get('pppPassword', 'N/A')}")
    print(f"VLAN ID:                 {wan.get('VLANID', 881)} (Prioridad 802.1p: {wan.get('VLANPriority', 0)})")
    print(f"IP WAN Asignada:         {wan.get('IPAddress', 'N/A')}")
    print(f"Gateway Concentrador:    {wan.get('GatewayIPAddress', 'N/A')}")
    print(f"Servidores DNS IPv4:     {wan.get('DNSServer', 'N/A')}")
    print(f"Dirección IPv6 WAN:      {wan.get('IP6Address', 'N/A')}")
    print(f"Servidores DNS IPv6:     {wan.get('DNS6Server', 'N/A')}")
    print("-" * 70)

    print("📞 [TELEFONÍA FIJA VOIP / SIP IMS]")
    print(f"Número Telefónico Fijo:  {sip.get('DirectoryNumber', 'N/A')}")
    print(f"Usuario Autenticación:   {sip.get('AuthUserName', 'N/A')}")
    print(f"Contraseña SIP:          {sip.get('AuthPassword', 'N/A')}")
    print(f"Estado de la Línea:      {sip.get('Status', 'N/A')}")
    print(f"Proxy / Registrar IMS:   vims-h.telmex.com:5060 (UDP)")
    print(f"Outbound Proxy:          nir8.norte.telmex.net:5060 (UDP)")
    print("-" * 70)

    print("📶 [REDES WI-FI]")
    print(f"SSID 2.4 GHz:            {wlan_24.get('SSID', 'N/A')} (Canal: {wlan_24.get('channel', 'Auto')})")
    print(f"BSSID 2.4 GHz (MAC):     {wlan_24.get('BSSID', 'N/A')}")
    print(f"Contraseña WPA2 2.4 GHz: {wlan_24.get('PskDisplay', 'N/A')}")
    print(f"SSID 5.0 GHz:            {wlan_50.get('SSID', 'N/A')} (Canal: {wlan_50.get('channel', 'Auto')}, 80MHz)")
    print(f"BSSID 5.0 GHz (MAC):     {wlan_50.get('BSSID', 'N/A')}")
    print(f"Contraseña WPA2 5.0 GHz: {wlan_50.get('PskDisplay', 'N/A')}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Extractor forense de credenciales y telemetría para módem Telmex Zyxel PMG5617-T20B."
    )
    parser.add_argument(
        "-p", "--password",
        help="Contraseña del router. Si no se especifica, se solicitará de forma segura e interactiva.",
        default=None
    )
    parser.add_argument(
        "--host",
        help="Dirección IP del módem (opcional, se auto-detecta por defecto).",
        default=None
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Muestra la salida cruda en formato JSON."
    )
    parser.add_argument(
        "-o", "--output",
        help="Guarda el informe en el archivo especificado (.json o .md)."
    )

    args = parser.parse_args()

    # 1. Identificar la IP del router
    if args.host:
        ip_router = args.host
    else:
        ip_router = detectar_ip_router()

    print(f"\n[+] IP del router identificada automáticamente: {ip_router}")

    # 2. Solicitar únicamente la contraseña si no fue provista por parámetro
    password = args.password
    if not password:
        try:
            if sys.stdin.isatty():
                password = getpass.getpass(f"🔑 Ingrese el password del router ({ip_router}): ")
            else:
                sys.stdout.write(f"🔑 Ingrese el password del router ({ip_router}): ")
                sys.stdout.flush()
                password = sys.stdin.readline().strip()
        except (KeyboardInterrupt, EOFError):
            print("\nOperación cancelada por el usuario.")
            sys.exit(0)


    if not password.strip():
        print("[!] Error: La contraseña no puede estar vacía.")
        sys.exit(1)

    print("[*] Conectando con el router e iniciando handshake criptográfico...")

    extractor = ZyxelPMG5617Extractor(host=ip_router, password=password)

    try:
        data = extractor.extract_full_profile()
    except Exception as e:
        print(f"\n[❌] Error durante la extracción: {e}\n")
        sys.exit(1)

    print("[✔] Extracción completada exitosamente.\n")

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        imprimir_reporte(data, ip_router)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                if args.output.endswith(".json"):
                    json.dump(data, f, indent=2)
                else:
                    f.write(f"# Reporte de Extracción - {ip_router}\nFecha: {datetime.now()}\n\n```json\n")
                    f.write(json.dumps(data, indent=2))
                    f.write("\n```\n")
            print(f"[💾] Archivo guardado correctamente en: {args.output}")
        except Exception as e:
            print(f"[!] No se pudo guardar el archivo: {e}")


if __name__ == "__main__":
    main()
