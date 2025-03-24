import re
import os
import glob
import base64
import tempfile
import lxml.etree
import subprocess

from pathlib import Path
from zipfile import ZipFile
from datetime import datetime

import pyaxml

from ppadb.client import Client as AdbClient
from ppadb.device import Device

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

client = AdbClient()

SHARED_ID = "seola.patcher.abcde.shared"
PATCHER_SIG_NAME = "dev.seola.apppatcher.sig.orig"
KEY_PASSWORD = "aaaaaa"


def main():
    check_file()

    dev = client.devices()
    if not dev:
        raise Exception("연결된 디바이스가 존재하지 않습니다")

    dev: Device = dev[0]

    print(dev.get_serial_no(), "로 진행합니다.")
    package_name = input("패키지 명을 입력해주세요 > ").strip()
    apks = get_apks(dev, package_name)

    with tempfile.TemporaryDirectory() as dir:
        extract(dev, dir, apks)

        base_path = os.path.join(dir, "base.apk")
        out_path = os.path.join(dir, "patched.apk")

        patch(base_path, out_path, get_signature(base_path))
        os.remove(base_path)

        align(dir)
        sign(dir)

        outdir = os.path.join(get_base_path(), f"patched-{generate_date_time()}")
        os.mkdir(outdir)

        for name in glob.glob("*-aligned.apk", root_dir=dir):
            os.rename(os.path.join(dir, name), os.path.join(outdir, name))

    print(outdir, "에 성공적으로 패치되었습니다")


def extract(dev: Device, dir: str, apks: list[str]):
    for apk in apks:
        name = os.path.basename(apk)
        print("Extract", name)
        dev.pull(apk, os.path.join(dir, name))


def check_file():
    if not os.path.isfile(get_key_path()):
        print("KEY.jks가 존재하지 않습니다.")
        print(
            "keytool -genkey -v -keystore KEY.jks -keyalg RSA -keysize 2048 -validity 10000"
        )
        print(
            f"위 명령어를 이용하여 생성해주세요. 비밀번호는 {KEY_PASSWORD}으로 해주세요. (java가 설치되어있어야 합니다)"
        )
        exit(1)


def patch(base_path: str, out_path: str, signature: str):
    print("패치 중...")

    already_patched = False
    dex_list = []

    with ZipFile(base_path) as zf:
        with ZipFile(out_path, "w") as zf2:
            max_dex = 1
            for info in zf.infolist():
                if info.filename == PATCHER_SIG_NAME:
                    already_patched = True
                    continue

                if info.filename == "AndroidManifest.xml":
                    axml, _ = pyaxml.AXML.from_axml(zf.read(info))
                    manifest: lxml.etree.ElementBase = axml.to_xml()

                    changed = {
                        "{http://schemas.android.com/apk/res/android}sharedUserId": SHARED_ID,
                        **manifest.attrib,
                    }

                    manifest.attrib.clear()

                    for k, v in changed.items():
                        manifest.attrib[k] = v

                    application: lxml.etree.ElementBase = manifest.find("./application")
                    application.attrib[
                        "{http://schemas.android.com/apk/res/android}appComponentFactory"
                    ] = "dev.seola.apppatcher.stub.PatcherAppComponentFactory"

                    axml = pyaxml.axml.AXML()
                    axml.from_xml(manifest)

                    zf2.writestr(
                        zinfo_or_arcname=info,
                        data=axml.pack(),
                        compress_type=info.compress_type,
                    )

                    print("manifest patched")
                    continue

                m = re.match("classes(\d+)\.dex", info.filename)
                if m:
                    max_dex = max(max_dex, int(m.group(1)))
                    dex_list.append(info.filename)
                    continue

                zf2.writestr(
                    zinfo_or_arcname=info,
                    data=zf.read(info),
                    compress_type=info.compress_type,
                )

            if already_patched:
                signature = zf.read(PATCHER_SIG_NAME).decode()
                dex_list.remove(f"classes{max_dex}.dex")
                max_dex -= 1

            for name in dex_list:
                zf2.writestr(name, zf.read(name))

            with open(get_asset_path("patcher.dex"), "rb") as f:
                zf2.writestr(f"classes{max_dex + 1}.dex", f.read())
            zf2.writestr(PATCHER_SIG_NAME, signature)


def sign(dir: str):
    for name in glob.glob("*-aligned.apk", root_dir=dir):
        print("Sign", name)

        name = os.path.join(dir, name)

        res = subprocess.call(
            args=[
                "java",
                "-jar",
                get_asset_path("apksigner.jar"),
                "sign",
                "--ks",
                get_key_path(),
                "--v2-signing-enabled",
                "true",
                "--ks-pass",
                f"pass:{KEY_PASSWORD}",
                name,
            ]
        )

        if res != 0:
            raise Exception("Sign 실패")


def align(dir: str):
    for apk in os.listdir(dir):
        print("Align", os.path.basename(apk))

        res = subprocess.call(
            args=[
                "java",
                "-jar",
                get_asset_path("zipalign-java.jar"),
                os.path.join(dir, apk),
                os.path.join(dir, apk.rsplit(".", 1)[0] + "-aligned.apk"),
            ]
        )

        if res != 0:
            raise Exception("Align 실패")


def generate_date_time():
    now = datetime.now()
    return now.strftime("%Y%m%d%H%M%S")


def get_apks(dev: Device, package_name: str):
    res: str = dev.shell(f"pm path {package_name}").strip()
    if not res:
        raise Exception("경로를 가져오지 못했습니다")

    apks = []
    for line in res.split("\n"):
        if line.startswith("package:"):
            apks.append(line[8:])

    if not apks:
        raise Exception("경로를 가져오지 못했습니다")

    return apks


def get_signature(apk_path: str):
    res = subprocess.check_output(
        args=[
            "java",
            "-jar",
            get_asset_path("apksigner.jar"),
            "verify",
            "--print-certs-pem",
            apk_path,
        ],
        text=True,
    )

    cert = base64.b64decode(
        res.split("-----END CERTIFICATE-----")[0]
        .split("-----BEGIN CERTIFICATE-----")[1]
        .replace("\n", "")
        .strip()
    )

    cert = x509.load_der_x509_certificate(cert)
    return cert.public_bytes(Encoding.DER).hex()


def get_base_path():
    return str(Path(__file__).parent)


def get_key_path():
    return str(Path(__file__).parent / "KEY.jks")


def get_asset_path(name: str):
    return str(Path(__file__).parent / "assets" / name)


if __name__ == "__main__":
    main()
