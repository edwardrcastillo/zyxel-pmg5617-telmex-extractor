#!/usr/bin/env python3
"""
Zyxel PMG5617-T20B (Telmex) - Gestor de Estado y Desactivación de Cuenta SIP / VoIP
Permite desregistrar, desactivar o reactivar la cuenta SIP del módem para
liberar la línea hacia Asterisk, FreePBX o clientes SIP externos.
"""

import sys
import os
import json
import base64
import argparse
import urllib.request
import urllib.error

# Dependencias criptográficas nativas
try:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import serialization, padding as sym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("[!] Error: Se requiere 'cryptography'. Ejecuta: pip install cryptography")
    sys.exit(1)

# Importar extractor base para reutilizar detección de IP
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from zyxel_pmg5617_extractor import detectar_ip_router


class ZyxelSIPManager:
    def __init__(self, host="192.168.1.254", password=""):
        self.host = host
        self.password = password
        self.username = "TELMEX"
        self.session_cookie = None
        self.session_key = None
        self.aes_key = None

    def _decrypt_payload(self, data):
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

    def _encrypt_payload(self, obj):
        raw_json = json.dumps(obj)
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(raw_json.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        enc_content = encryptor.update(padded_data) + encryptor.finalize()
        return json.dumps({
            "content": base64.b64encode(enc_content).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }).encode('utf-8')

    def login(self):
        url_rsa = f"http://{self.host}/getRSAPublickKey"
        req = urllib.request.urlopen(url_rsa, timeout=8)
        rsa_resp = json.loads(req.read().decode('utf-8'))
        rsa_pem = rsa_resp.get("RSAPublicKey")
        pub_key = serialization.load_pem_public_key(rsa_pem.encode('utf-8'))

        self.aes_key = os.urandom(32)
        aes_key_b64 = base64.b64encode(self.aes_key).decode('utf-8')
        iv = os.urandom(16)
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        pass_b64 = base64.b64encode(self.password.encode('utf-8')).decode('utf-8')
        auth_payload = json.dumps({
            "Input_Account": self.username,
            "Input_Passwd": pass_b64,
            "currLang": "sp",
            "RememberPassword": 0,
            "SHA512_password": False
        })

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(auth_payload.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        enc_content = encryptor.update(padded_data) + encryptor.finalize()

        enc_key = pub_key.encrypt(aes_key_b64.encode('utf-8'), asym_padding.PKCS1v15())

        body_login = json.dumps({
            "content": base64.b64encode(enc_content).decode('utf-8'),
            "key": base64.b64encode(enc_key).decode('utf-8'),
            "iv": iv_b64
        }).encode('utf-8')

        req_login = urllib.request.Request(
            f"http://{self.host}/UserLogin",
            data=body_login,
            headers={"Content-Type": "text/plain;charset=UTF-8"}
        )

        resp = urllib.request.urlopen(req_login, timeout=10)
        raw_cookie = resp.headers.get("Set-Cookie", "")
        if raw_cookie:
            self.session_cookie = raw_cookie.split(";")[0]

        login_raw = json.loads(resp.read().decode('utf-8'))
        login_data = self._decrypt_payload(login_raw)

        if login_data.get("result") != "ZCFG_SUCCESS":
            raise PermissionError(f"Error de acceso al router: {login_data.get('result')}")

        self.session_key = login_data.get("sessionkey")
        return login_data

    def query_dal(self, oid):
        url = f"http://{self.host}/cgi-bin/DAL?oid={oid}&sessionkey={self.session_key}"
        headers = {}
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return self._decrypt_payload(data)

    def put_dal(self, oid, obj):
        url = f"http://{self.host}/cgi-bin/DAL?oid={oid}&sessionkey={self.session_key}"
        body = self._encrypt_payload(obj)
        headers = {
            "Content-Type": "application/json;charset=UTF-8"
        }
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        req = urllib.request.Request(url, data=body, headers=headers, method="PUT")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return self._decrypt_payload(data)

    def logout(self):
        if self.session_key and self.session_cookie:
            try:
                url = f"http://{self.host}/cgi-bin/UserLogout?sessionkey={self.session_key}"
                req = urllib.request.Request(url, data=b'', headers={"Cookie": self.session_cookie})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

    def get_status(self):
        vstatus = self.query_dal("VOIP_Status")
        sip_acc = self.query_dal("sip_account")
        sip_sp = self.query_dal("sip_sp")
        
        line_info = ((vstatus.get("Object") or [{}])[0].get("LineInfo") or [{}])[0]
        acc_info = (sip_acc.get("Object") or [{}])[0]
        sp_info = (sip_sp.get("Object") or [{}])[0]
        
        return {
            "line_enable": acc_info.get("Enable", "Unknown"),
            "provider_enable": sp_info.get("ProfleEnable", "Unknown"),
            "status": line_info.get("Status", "Unknown"),
            "call_state": line_info.get("CallState", "Unknown"),
            "directory_number": line_info.get("DirectoryNumber", acc_info.get("DirectoryNumber")),
            "auth_user": acc_info.get("AuthUserName"),
            "proxy": sp_info.get("ProxyServer")
        }

    def unregister(self):
        """Envía desregistro inmediato (SIP REGISTER Expires: 0) a Telmex IMS."""
        obj = {"idx0": 1, "idx1": 1, "idx2": 1, "X_ZYXEL_DoRegister": 2}
        return self.put_dal("VOIP_Status", obj)

    def register(self):
        """Envía comando para forzar re-registro en Telmex IMS."""
        obj = {"idx0": 1, "idx1": 1, "idx2": 1, "X_ZYXEL_DoRegister": 1}
        return self.put_dal("VOIP_Status", obj)

    def set_sip_enabled(self, enable=True):
        """Habilita o deshabilita el perfil de proveedor SIP en el router."""
        val = "Enabled" if enable else "Disabled"
        sip_sp = self.query_dal("sip_sp")
        sp = (sip_sp.get("Object") or [{}])[0]
        sp["ProfleEnable"] = val
        sp["EditPath"] = f"VoiceProfile.{sp.get('profileIdx', 1)}"
        return self.put_dal("sip_sp", sp)


import getpass

def main():
    parser = argparse.ArgumentParser(description="Gestor de Estado y Desactivación SIP Zyxel PMG5617-T20B")
    parser.add_argument("--host", default=detectar_ip_router(), help="IP del router")
    parser.add_argument("--password", "-p", default=None, help="Contraseña web del router")
    parser.add_argument("action", choices=["status", "unregister", "register", "disable", "enable"], help="Acción a realizar")
    args = parser.parse_args()

    password = args.password
    if not password:
        if not sys.stdin.isatty():
            password = sys.stdin.readline().strip()
        else:
            password = getpass.getpass(f"🔑 Ingrese el password del router ({args.host}): ")

    mgr = ZyxelSIPManager(host=args.host, password=password)
    try:
        mgr.login()
        if args.action == "status":
            st = mgr.get_status()
            print("\n" + "=" * 55)
            print("        ESTADO ACTUAL DE VOIP / SIP EN EL ROUTER        ")
            print("=" * 55)
            print(f"Número Telefónico:     {st['directory_number']}")
            print(f"Usuario SIP IMS:       {st['auth_user']}")
            print(f"Servidor IMS:          {st['proxy']}")
            print(f"Cuenta Habilitada:     {st['line_enable']}")
            print(f"Proveedor Perfil:      {st['provider_enable']}")
            print(f"Estado de Registro:    {st['status']} (Up = Registrado)")
            print(f"Estado de Llamada:     {st['call_state']}")
            print("=" * 55 + "\n")
        elif args.action == "unregister":
            res = mgr.unregister()
            print(f"[+] Desregistro enviado al router: {res.get('result')}")
        elif args.action == "register":
            res = mgr.register()
            print(f"[+] Comando de registro enviado: {res.get('result')}")
        elif args.action == "disable":
            res = mgr.set_sip_enabled(enable=False)
            print(f"[+] Perfil SIP deshabilitado en el módem: {res.get('result')}")
        elif args.action == "enable":
            res = mgr.set_sip_enabled(enable=True)
            print(f"[+] Perfil SIP rehabilitado en el módem: {res.get('result')}")
    finally:
        mgr.logout()


if __name__ == "__main__":
    main()
