#!/usr/bin/python3
import sys
import os
import subprocess
import time
import shutil
import glob

from multiprocessing import Process
from urllib.request import urlretrieve
from dataclasses import dataclass


# Where to store library files of each appimage, will be organized 
# via subdirectories of the appimage's name
OUTPUT_DIR = "/tmp/appimage-libs"

# temporary directory used for downloads
TEMP_DIR = "/tmp/appimage-extractor"


@dataclass
class AppImage:
    url: str
    output_path: str # contains all extracted libs
    executable_path: str
    directory_path: str
    mount_path: str
    executable_hash: str
    iso_offset: str


APPIMAGES = [
    AppImage("https://getsession.org/linux", f"{OUTPUT_DIR}/session", f"{TEMP_DIR}/session/session.AppImage", f"{TEMP_DIR}/session", f"{TEMP_DIR}/session/mount", "", 0),
    # AppImage("https://github.com/felipefacundes/okular-appimage/releases/download/v22.08.1-Full_All_LIBS/Okular.full-libs-22.08.1-2-x86_64.AppImage", f"{TEMP_DIR}/okular/okular.AppImage", f"{TEMP_DIR}/okular", ""),

]


def extract_lib(appimage):
    appimage.iso_offset = subprocess.run([appimage.executable_path, "--appimage-offset"], stdout=subprocess.PIPE).stdout.decode('utf-8').split(" ")[0].strip()
    print(f">> Found offset of {appimage.iso_offset} for appimage: {appimage.executable_path}")
    
    subprocess.run(["sudo", "mount", appimage.executable_path, appimage.mount_path, "-o", f"offset={appimage.iso_offset}"])
    print(f">> mounted at {appimage.mount_path}")

    for file in glob.glob(f"{appimage.mount_path}/*.so"):
        shutil.copy(file, appimage.output_path)

    for file in glob.glob(f"{appimage.mount_path}/lib/*"):
        shutil.copy(file, appimage.output_path)

    for file in glob.glob(f"{appimage.mount_path}/lib64/*"):
        shutil.copy(file, appimage.output_path)

    for file in glob.glob(f"{appimage.mount_path}/usr/lib/*"):
        shutil.copy(file, appimage.output_path)

    for file in glob.glob(f"{appimage.mount_path}/usr/lib64/*"):
        shutil.copy(file, appimage.output_path)

    for file in glob.glob(f"{appimage.mount_path}/usr/local/lib/*"):
        shutil.copy(file, appimage.output_path)

    print(f">> copied libraries to {appimage.output_path}")

    subprocess.run(["sudo", "umount", appimage.mount_path])

def download_appimage(appimage):
    if os.path.exists(appimage.directory_path):
        print(f"skipping {appimage.directory_path} already exists")
        return

    print(f"Downloading {appimage.url} to {appimage.directory_path}")
    os.mkdir(appimage.output_path)
    os.mkdir(appimage.directory_path)
    os.mkdir(appimage.mount_path)
    

    subprocess.run(["wget", "-q", "-O", appimage.executable_path, appimage.url])
    appimage.executable_hash = subprocess.run(["sha1sum", appimage.executable_path], stdout=subprocess.PIPE).stdout.decode('utf-8').split(" ")[0]
    subprocess.run(["chmod", "+x", appimage.executable_path])
    appimage.iso_offset = subprocess.run([appimage.executable_path, "--appimage-offset"], stdout=subprocess.PIPE).stdout.decode('utf-8').split(" ")[0]



def run(appimage):
    download_appimage(appimage)
    extract_lib(appimage)



def check_user():
    if not os.geteuid() == 0:
        sys.exit("\nUtility must be run as root, with sudo\n")


def main():
    check_user()

    if not os.path.isdir(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)

    if not os.path.isdir(TEMP_DIR):
        os.mkdir(TEMP_DIR)

    # Using process to make downloads + extractions concurrent
    processes = []
    for appimage in APPIMAGES:
        processes.append(Process(target=run, args=(appimage,)))

    for p in processes:
        p.start()
    
    for p in processes:
        p.join()

    print("--- Done ---")

if __name__ == "__main__":
    main()
