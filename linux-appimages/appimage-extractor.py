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
    AppImage("https://getsession.org/linux", f"{OUTPUT_DIR}/session", f"{TEMP_DIR}/session/session.AppImage", f"{TEMP_DIR}/session", f"{TEMP_DIR}/session/mount", "", ""),
    AppImage("https://github.com/Acreom/releases/releases/download/v1.20.1/acreom-1.20.1.AppImage", f"{OUTPUT_DIR}/acreom", f"{TEMP_DIR}/acreom/acreom.AppImage", f"{TEMP_DIR}/acreom", f"{TEMP_DIR}/acreom/mount", "", ""),
    AppImage("https://github.com/bugbakery/audapolis/releases/download/v0.3.0/audapolis-linux-x86_64-0.3.0_4.AppImage", f"{OUTPUT_DIR}/audapolis", f"{TEMP_DIR}/audapolis/audapolis.AppImage", f"{TEMP_DIR}/audapolis", f"{TEMP_DIR}/audapolis/mount", "", ""),
    AppImage("https://github.com/AppFlowy-IO/AppFlowy/releases/download/0.5.8/AppFlowy-0.5.8-linux-x86_64.AppImage", f"{OUTPUT_DIR}/appflowy", f"{TEMP_DIR}/appflowy/appflowy.AppImage", f"{TEMP_DIR}/appflowy", f"{TEMP_DIR}/appflowy/mount", "", ""),
    AppImage("https://github.com/allusion-app/Allusion/releases/download/v1.0.0-rc.10/Allusion-1.0.0-rc.10.AppImage", f"{OUTPUT_DIR}/allusion", f"{TEMP_DIR}/allusion/allusion.AppImage", f"{TEMP_DIR}/allusion", f"{TEMP_DIR}/allusion/mount", "", ""),
    AppImage("https://github.com/Beaver-Notes/Beaver-Notes/releases/download/3.2.0/Beaver-notes-3.2.0.AppImage", f"{OUTPUT_DIR}/beavernotes", f"{TEMP_DIR}/beavernotes/beavernotes.AppImage", f"{TEMP_DIR}/beavernotes", f"{TEMP_DIR}/beavernotes/mount", "", ""),
    AppImage("https://github.com/bdTechies/book-manager/releases/download/v1.0.1/book-manager-1.0.1-x86_64.AppImage", f"{OUTPUT_DIR}/bookmanager", f"{TEMP_DIR}/bookmanager/bookmanager.AppImage", f"{TEMP_DIR}/bookmanager", f"{TEMP_DIR}/bookmanager/mount", "", ""),
    AppImage("https://github.com/KushagraKarira/calibre-appimage/releases/download/main-0ccac329/Calibre-7.11.0-x86_64.AppImage", f"{OUTPUT_DIR}/calibre", f"{TEMP_DIR}/calibre/calibre.AppImage", f"{TEMP_DIR}/calibre", f"{TEMP_DIR}/calibre/mount", "", ""),
    AppImage("https://github.com/Bin-Huang/chatbox/releases/download/v1.3.10/Chatbox-1.3.10-x86_64.AppImage", f"{OUTPUT_DIR}/chatbox", f"{TEMP_DIR}/chatbox/chatbox.AppImage", f"{TEMP_DIR}/chatbox", f"{TEMP_DIR}/chatbox/mount", "", ""),
    AppImage("https://github.com/giuspen/cherrytree/releases/download/v1.1.2/CherryTree-1.1.2-x86_64.AppImage", f"{OUTPUT_DIR}/cherrytree", f"{TEMP_DIR}/cherrytree/cherrytree.AppImage", f"{TEMP_DIR}/cherrytree", f"{TEMP_DIR}/cherrytree/mount", "", ""),
    AppImage("https://github.com/SZinedine/DeepTags/releases/download/0.8.0/DeepTags_0.8.0-x86_64.AppImage", f"{OUTPUT_DIR}/deeptags", f"{TEMP_DIR}/deeptags/deeptags.AppImage", f"{TEMP_DIR}/deeptags", f"{TEMP_DIR}/deeptags/mount", "", ""),
    AppImage("https://github.com/hkdb/Densify/releases/download/v0.3.1/Densify-v0.3.1-x86_64.AppImage", f"{OUTPUT_DIR}/densify", f"{TEMP_DIR}/densify/densify.AppImage", f"{TEMP_DIR}/densify", f"{TEMP_DIR}/densify/mount", "", ""),
    AppImage("https://github.com/jimevins/glabels-qt/releases/download/glabels-3.99-master564/glabels-3.99-master564-x86_64.AppImage", f"{OUTPUT_DIR}/glabels", f"{TEMP_DIR}/glabels/glabels.AppImage", f"{TEMP_DIR}/glabels", f"{TEMP_DIR}/glabels/mount", "", ""),
    AppImage("https://github.com/laurent22/joplin/releases/download/v2.14.22/Joplin-2.14.22.AppImage", f"{OUTPUT_DIR}/joplin", f"{TEMP_DIR}/joplin/joplin.AppImage", f"{TEMP_DIR}/joplin", f"{TEMP_DIR}/joplin/mount", "", ""),
    AppImage("https://github.com/IgKh/katvan/releases/download/v0.3.0/Katvan-0.3.0-linux-x86_64.AppImage", f"{OUTPUT_DIR}/katvan", f"{TEMP_DIR}/katvan/katvan.AppImage", f"{TEMP_DIR}/katvan", f"{TEMP_DIR}/katvan/mount", "", ""),
    AppImage("https://github.com/artoh/kitupiikki/releases/download/v5.5.2/Kitsas-5.5.2-x86_64.AppImage", f"{OUTPUT_DIR}/kitsas", f"{TEMP_DIR}/kitsas/kitsas.AppImage", f"{TEMP_DIR}/kitsas", f"{TEMP_DIR}/kitsas/mount", "", ""),
    AppImage("https://github.com/digimezzo/knowte/releases/download/v3.0.0/Knowte-3.0.0.AppImage", f"{OUTPUT_DIR}/knowte", f"{TEMP_DIR}/knowte/knowte.AppImage", f"{TEMP_DIR}/knowte", f"{TEMP_DIR}/knowte/mount", "", ""),
    AppImage("https://github.com/koreader/koreader/releases/download/v2024.04/koreader-appimage-x86_64-linux-gnu-v2024.04.AppImage", f"{OUTPUT_DIR}/koreader", f"{TEMP_DIR}/koreader/koreader.AppImage", f"{TEMP_DIR}/koreader", f"{TEMP_DIR}/koreader/mount", "", ""),
    AppImage("https://github.com/logseq/logseq/releases/download/0.10.9/Logseq-linux-x64-0.10.9.AppImage", f"{OUTPUT_DIR}/logseq", f"{TEMP_DIR}/logseq/logseq.AppImage", f"{TEMP_DIR}/logseq", f"{TEMP_DIR}/logseq/mount", "", ""),
    AppImage("https://github.com/wardellbagby/lyricistant/releases/download/v3.4.3/lyricistant-linux_x86_64.AppImage", f"{OUTPUT_DIR}/lyricistant", f"{TEMP_DIR}/lyricistant/lyricistant.AppImage", f"{TEMP_DIR}/lyricistant", f"{TEMP_DIR}/lyricistant/mount", "", ""),
    AppImage("https://github.com/MarkMindCkm/Mark-Mind/releases/download/v1.3.1/Mark.Mind-1.3.1.AppImage", f"{OUTPUT_DIR}/markmind", f"{TEMP_DIR}/markmind/markmind.AppImage", f"{TEMP_DIR}/markmind", f"{TEMP_DIR}/markmind/mount", "", ""),
    AppImage("https://github.com/m59peacemaker/mupdf-appimage/releases/download/1.18.0/MuPDF-1.18.0-x86_64.AppImage", f"{OUTPUT_DIR}/mupdf", f"{TEMP_DIR}/mupdf/mupdf.AppImage", f"{TEMP_DIR}/mupdf", f"{TEMP_DIR}/mupdf/mount", "", ""),
    AppImage("https://github.com/notable/notable/releases/download/v1.8.4/Notable-1.8.4.AppImage", f"{OUTPUT_DIR}/notable", f"{TEMP_DIR}/notable/notable.AppImage", f"{TEMP_DIR}/notable", f"{TEMP_DIR}/notable/mount", "", ""),
    AppImage("https://github.com/LiamRiddell/NoteMaster/releases/download/v0.3.1/NoteMaster-0.3.1.AppImage", f"{OUTPUT_DIR}/notemaster", f"{TEMP_DIR}/notemaster/notemaster.AppImage", f"{TEMP_DIR}/notemaster", f"{TEMP_DIR}/notemaster/mount", "", ""),
    AppImage("https://github.com/dail8859/NotepadNext/releases/download/v0.7/NotepadNext-v0.7-x86_64.AppImage", f"{OUTPUT_DIR}/notepadnext", f"{TEMP_DIR}/notepadnext/notepadnext.AppImage", f"{TEMP_DIR}/notepadnext", f"{TEMP_DIR}/notepadnext/mount", "", ""),
    AppImage("https://github.com/streetwriters/notesnook/releases/download/v3.0.8/notesnook_linux_x86_64.AppImage", f"{OUTPUT_DIR}/notesnook", f"{TEMP_DIR}/notesnook/notesnook.AppImage", f"{TEMP_DIR}/notesnook", f"{TEMP_DIR}/notesnook/mount", "", ""),
    AppImage("https://github.com/vkbo/novelWriter/releases/download/v2.5b1/novelWriter-2.5b1.AppImage", f"{OUTPUT_DIR}/novelwriter", f"{TEMP_DIR}/novelwriter/novelwriter.AppImage", f"{TEMP_DIR}/novelwriter", f"{TEMP_DIR}/novelwriter/mount", "", ""),
    AppImage("https://github.com/Lunarequest/NightPDF/releases/download/v3.0.0-beta4/NightPDF-3.0.0-beta4-x86_64.AppImage", f"{OUTPUT_DIR}/nightpdf", f"{TEMP_DIR}/nightpdf/nightpdf.AppImage", f"{TEMP_DIR}/nightpdf", f"{TEMP_DIR}/nightpdf/mount", "", ""),
    AppImage("https://github.com/felipefacundes/okular-appimage/releases/download/v22.08.1-Full_All_LIBS/Okular.full-libs-22.08.1-2-x86_64.AppImage", f"{OUTPUT_DIR}/okular", f"{TEMP_DIR}/okular/okular.AppImage", f"{TEMP_DIR}/okular", f"{TEMP_DIR}/okular/mount", "", ""),
    AppImage("https://github.com/bgallois/OpenJournal/releases/download/v1.3.4/OpenJournal-x86_64.AppImage", f"{OUTPUT_DIR}/openjournal", f"{TEMP_DIR}/openjournal/openjournal.AppImage", f"{TEMP_DIR}/openjournal", f"{TEMP_DIR}/openjournal/mount", "", ""),
    AppImage("https://github.com/GlitterWare/Passy/releases/download/v1.8.0/Passy-v1.8.0-x86-64.AppImage", f"{OUTPUT_DIR}/passy", f"{TEMP_DIR}/passy/passy.AppImage", f"{TEMP_DIR}/passy", f"{TEMP_DIR}/passy/mount", "", ""),
    AppImage("https://github.com/dragotin/pdfquirk/releases/download/v0.95/PDFQuirk-continuous-x86_64.AppImage", f"{OUTPUT_DIR}/pdfquirk", f"{TEMP_DIR}/pdfquirk/pdfquirk.AppImage", f"{TEMP_DIR}/pdfquirk", f"{TEMP_DIR}/pdfquirk/mount", "", ""),
    AppImage("https://github.com/pulsar-edit/pulsar/releases/download/v1.117.0/Linux.Pulsar-1.117.0.AppImage", f"{OUTPUT_DIR}/pulsar", f"{TEMP_DIR}/pulsar/pulsar.AppImage", f"{TEMP_DIR}/pulsar", f"{TEMP_DIR}/pulsar/mount", "", ""),
    AppImage("https://github.com/thgier/PotatoPresenter/releases/download/v1.0.2/PotatoPresenter-v1.0.2.AppImage", f"{OUTPUT_DIR}/potatopresenter", f"{TEMP_DIR}/potatopresenter/potatopresenter.AppImage", f"{TEMP_DIR}/potatopresenter", f"{TEMP_DIR}/potatopresenter/mount", "", ""),
    AppImage("https://github.com/pbek/QOwnNotes/releases/download/v24.6.0/QOwnNotes-x86_64.AppImage", f"{OUTPUT_DIR}/qownnotes", f"{TEMP_DIR}/qownnotes/qownnotes.AppImage", f"{TEMP_DIR}/qownnotes", f"{TEMP_DIR}/qownnotes/mount", "", ""),
    AppImage("https://github.com/qpdf/qpdf/releases/download/v11.9.0/qpdf-11.9.0-x86_64.AppImage", f"{OUTPUT_DIR}/qpdf", f"{TEMP_DIR}/qpdf/qpdf.AppImage", f"{TEMP_DIR}/qpdf", f"{TEMP_DIR}/qpdf/mount", "", ""),
    AppImage("https://github.com/harshkhandeparkar/rainbow-board/releases/download/v0.8.1/Rainbow-Board-0.8.1.AppImage", f"{OUTPUT_DIR}/rainbowboard", f"{TEMP_DIR}/rainbowboard/rainbowboard.AppImage", f"{TEMP_DIR}/rainbowboard", f"{TEMP_DIR}/rainbowboard/mount", "", ""),
    AppImage("https://recollectr.io/download/linux/", f"{OUTPUT_DIR}/recollectr", f"{TEMP_DIR}/recollectr/recollectr.AppImage", f"{TEMP_DIR}/recollectr", f"{TEMP_DIR}/recollectr/mount", "", ""),
    AppImage("https://github.com/saber-notes/saber/releases/download/v0.23.2/Saber-0.23.2-x86_64.AppImage", f"{OUTPUT_DIR}/saber", f"{TEMP_DIR}/saber/saber.AppImage", f"{TEMP_DIR}/saber", f"{TEMP_DIR}/saber/mount", "", ""),
    AppImage("https://github.com/rhaberkorn/sciteco/releases/download/nightly/sciteco-gtk_nightly_x86_64.AppImage", f"{OUTPUT_DIR}/sciteco", f"{TEMP_DIR}/sciteco/sciteco.AppImage", f"{TEMP_DIR}/sciteco", f"{TEMP_DIR}/sciteco/mount", "", ""),
    AppImage("https://github.com/standardnotes/desktop/releases/download/v3.22.11/standard-notes-3.22.11-linux-x86_64.AppImage", f"{OUTPUT_DIR}/standardnotes", f"{TEMP_DIR}/standardnotes/standardnotes.AppImage", f"{TEMP_DIR}/standardnotes", f"{TEMP_DIR}/standardnotes/mount", "", ""),
    AppImage("https://github.com/josippapez/StoRadit/releases/download/v1.0.5/StoRadit-1.0.5.AppImage", f"{OUTPUT_DIR}/storadit", f"{TEMP_DIR}/storadit/storadit.AppImage", f"{TEMP_DIR}/storadit", f"{TEMP_DIR}/storadit/mount", "", ""),
    AppImage("https://github.com/SimonBrandner/TaskizerDesktop/releases/download/v2.0.0-rc.2/taskizer-2.0.0-rc.2-linux-x86_64.AppImage", f"{OUTPUT_DIR}/taskizer", f"{TEMP_DIR}/taskizer/taskizer.AppImage", f"{TEMP_DIR}/taskizer", f"{TEMP_DIR}/taskizer/mount", "", ""),
    AppImage("https://github.com/edrlab/thorium-reader/releases/download/latest-linux-intel/Thorium-3.0.0-alpha.1.9330013266.AppImage", f"{OUTPUT_DIR}/thorium", f"{TEMP_DIR}/thorium/thorium.AppImage", f"{TEMP_DIR}/thorium", f"{TEMP_DIR}/thorium/mount", "", ""),
    AppImage("https://github.com/michaelpb/whiteboard/releases/download/v0.0.48/whiteboard-app-0.0.48-x86_64.AppImage", f"{OUTPUT_DIR}/whiteboard", f"{TEMP_DIR}/whiteboard/whiteboard.AppImage", f"{TEMP_DIR}/whiteboard", f"{TEMP_DIR}/whiteboard/mount", "", ""),
    AppImage("https://github.com/XilinJia/Xilinota/releases/download/v2.15.1/Xilinota-2.15.1.AppImage", f"{OUTPUT_DIR}/xilinota", f"{TEMP_DIR}/xilinota/xilinota.AppImage", f"{TEMP_DIR}/xilinota", f"{TEMP_DIR}/xilinota/mount", "", ""),
    AppImage("https://github.com/jyannick/yaka/releases/download/v0.7.0/Yaka-0.7.0.AppImage", f"{OUTPUT_DIR}/yaka", f"{TEMP_DIR}/yaka/yaka.AppImage", f"{TEMP_DIR}/yaka", f"{TEMP_DIR}/yaka/mount", "", ""),
    AppImage("https://github.com/Zettlr/Zettlr/releases/download/v3.1.1/Zettlr-3.1.1-x86_64.AppImage", f"{OUTPUT_DIR}/zettlr", f"{TEMP_DIR}/zettlr/zettlr.AppImage", f"{TEMP_DIR}/zettlr", f"{TEMP_DIR}/zettlr/mount", "", ""),
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
