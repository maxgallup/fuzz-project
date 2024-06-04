# Linux Desktop Apps bundled as AppImages

Linux AppImages are a binary format that bundle all of the dependencies of the 
app into a single binary for cross-distro compatibility. This allows us to automate
the scanning process of points of interest across multiple Linux apps due to the 
AppImages' common format which lets us extract symbol information in a uniform way.

The AppImage binary is made of an executable wrapper followed by the compressed image
of all executable code that gets mounted to the Linux host at runtime.


### Automated Lib Extraction

``` bash
python3 appimage-extractor.py
```

Will download the following list of app-images and extract all of their dependencies into `/tmp/appimage-libs/`. 
Target linux office and messenger app-images  were found from [https://appimagehub.com](https://appimagehub.com).

* acreom https://github.com/Acreom/releases/releases/download/v1.20.1/acreom-1.20.1.AppImage
* audapolis https://github.com/bugbakery/audapolis/releases/download/v0.3.0/audapolis-linux-x86_64-0.3.0_4.AppImage
* appflowy https://github.com/AppFlowy-IO/AppFlowy/releases/download/0.5.8/AppFlowy-0.5.8-linux-x86_64.AppImage
* allusion https://github.com/allusion-app/Allusion/releases/download/v1.0.0-rc.10/Allusion-1.0.0-rc.10.AppImage
* beavernotes https://github.com/Beaver-Notes/Beaver-Notes/releases/download/3.2.0/Beaver-notes-3.2.0.AppImage
* bookmanager https://github.com/bdTechies/book-manager/releases/download/v1.0.1/book-manager-1.0.1-x86_64.AppImage
* calibre https://github.com/KushagraKarira/calibre-appimage/releases/download/main-0ccac329/Calibre-7.11.0-x86_64.AppImage
* chatbox https://github.com/Bin-Huang/chatbox/releases/download/v1.3.10/Chatbox-1.3.10-x86_64.AppImage
* cherrytree https://github.com/giuspen/cherrytree/releases/download/v1.1.2/CherryTree-1.1.2-x86_64.AppImage
* deeptags https://github.com/SZinedine/DeepTags/releases/download/0.8.0/DeepTags_0.8.0-x86_64.AppImage
* densify https://github.com/hkdb/Densify/releases/download/v0.3.1/Densify-v0.3.1-x86_64.AppImage
* glabels https://github.com/jimevins/glabels-qt/releases/download/glabels-3.99-master564/glabels-3.99-master564-x86_64.AppImage
* joplin https://github.com/laurent22/joplin/releases/download/v2.14.22/Joplin-2.14.22.AppImage
* katvan https://github.com/IgKh/katvan/releases/download/v0.3.0/Katvan-0.3.0-linux-x86_64.AppImage
* kitsas https://github.com/artoh/kitupiikki/releases/download/v5.5.2/Kitsas-5.5.2-x86_64.AppImage
* knowte https://github.com/digimezzo/knowte/releases/download/v3.0.0/Knowte-3.0.0.AppImageh
* koreader https://github.com/koreader/koreader/releases/download/v2024.04/koreader-appimage-x86_64-linux-gnu-v2024.04.AppImage
* logseq https://github.com/logseq/logseq/releases/download/0.10.9/Logseq-linux-x64-0.10.9.AppImage
* lyricistant https://github.com/wardellbagby/lyricistant/releases/download/v3.4.3/lyricistant-linux_x86_64.AppImage
* markmind https://github.com/MarkMindCkm/Mark-Mind/releases/download/v1.3.1/Mark.Mind-1.3.1.AppImage
* mupdf https://github.com/m59peacemaker/mupdf-appimage/releases/download/1.18.0/MuPDF-1.18.0-x86_64.AppImage
* notable https://github.com/notable/notable/releases/download/v1.8.4/Notable-1.8.4.AppImage
* notemaster https://github.com/LiamRiddell/NoteMaster/releases/download/v0.3.1/NoteMaster-0.3.1.AppImage
* notepadnext https://github.com/dail8859/NotepadNext/releases/download/v0.7/NotepadNext-v0.7-x86_64.AppImage
* notesnook https://github.com/streetwriters/notesnook/releases/download/v3.0.8/notesnook_linux_x86_64.AppImage
* novelwriter https://github.com/vkbo/novelWriter/releases/download/v2.5b1/novelWriter-2.5b1.AppImage
* nightpdf https://github.com/Lunarequest/NightPDF/releases/download/v3.0.0-beta4/NightPDF-3.0.0-beta4-x86_64.AppImage
* okular https://github.com/felipefacundes/okular-appimage/releases/download/v22.08.1-Full_All_LIBS/Okular.full-libs-22.08.1-2-x86_64.AppImage
* openjournal https://github.com/bgallois/OpenJournal/releases/download/v1.3.4/OpenJournal-x86_64.AppImage
* passy https://github.com/GlitterWare/Passy/releases/download/v1.8.0/Passy-v1.8.0-x86-64.AppImage
* pdfquirk https://github.com/dragotin/pdfquirk/releases/download/v0.95/PDFQuirk-continuous-x86_64.AppImage
* pulsar https://github.com/pulsar-edit/pulsar/releases/download/v1.117.0/Linux.Pulsar-1.117.0.AppImage
* potatopresenter https://github.com/thgier/PotatoPresenter/releases/download/v1.0.2/PotatoPresenter-v1.0.2.AppImage
* qownnotes https://github.com/pbek/QOwnNotes/releases/download/v24.6.0/QOwnNotes-x86_64.AppImage
* qpdf https://github.com/qpdf/qpdf/releases/download/v11.9.0/qpdf-11.9.0-x86_64.AppImage
* rainbowboard https://github.com/harshkhandeparkar/rainbow-board/releases/download/v0.8.1/Rainbow-Board-0.8.1.AppImage
* recollectr https://recollectr.io/download/linux/
* saber https://github.com/saber-notes/saber/releases/download/v0.23.2/Saber-0.23.2-x86_64.AppImage
* sciteco https://github.com/rhaberkorn/sciteco/releases/download/nightly/sciteco-gtk_nightly_x86_64.AppImage
* standardnotes https://github.com/standardnotes/desktop/releases/download/v3.22.11/standard-notes-3.22.11-linux-x86_64.AppImage
* storadit https://github.com/josippapez/StoRadit/releases/download/v1.0.5/StoRadit-1.0.5.AppImage
* taskizer https://github.com/SimonBrandner/TaskizerDesktop/releases/download/v2.0.0-rc.2/taskizer-2.0.0-rc.2-linux-x86_64.AppImage
* thorium https://github.com/edrlab/thorium-reader/releases/download/latest-linux-intel/Thorium-3.0.0-alpha.1.9330013266.AppImage
* whiteboard https://github.com/michaelpb/whiteboard/releases/download/v0.0.48/whiteboard-app-0.0.48-x86_64.AppImage
* xilinota https://github.com/XilinJia/Xilinota/releases/download/v2.15.1/Xilinota-2.15.1.AppImage
* yaka https://github.com/jyannick/yaka/releases/download/v0.7.0/Yaka-0.7.0.AppImage
* zettlr https://github.com/Zettlr/Zettlr/releases/download/v3.1.1/Zettlr-3.1.1-x86_64.AppImage



### failed:
* okular
* saber
* cherrytree
* appyflow
* sciteo
* recollectr



<!-- 
* https://github.com/KDE/okular
* https://github.com/pwmt/zathura
* https://github.com/GNOME/evince
* https://github.com/gajim/gajim
* https://github.com/signalapp/Signal-Desktop
* https://github.com/element-hq/element-desktop
* https://github.com/KDE/neochat
* https://gitlab.gnome.org/World/fractal
* https://gitlab.freedesktop.org/poppler/poppler
 -->
