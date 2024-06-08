# fuzz-project 


The following is a list of notes for deciding on a target.

* open type format otf
* true type format (ttf)
    * standard: https://en.wikipedia.org/wiki/OpenType
    * library: freetype linux implementation (shipped with most distros) https://en.wikipedia.org/wiki/FreeType
    * library: gltt opengl https://directory.fsf.org/wiki/GLTT
    * library: sdl_ttf for games https://github.com/libsdl-org/SDL_ttf
    * library: tool https://github.com/fonttools/fonttools
    * closed source lib: Apple CoreGraphics implementation
    * the following formats build on top of ttf by adding their own optimization:
        * .woff, .woff2, .eot
    * obsolete file formats (replaced by ttf and otf)
        * .fnt, 
    * font embedding (into pdfs, word documents...) https://en.wikipedia.org/wiki/Font_embedding
    * existing research:
        * https://github.com/googleprojectzero/BrokenType
        * https://immunityproducts.blogspot.com/2013/03/infiltrate-preview-truetype-font.html
        * https://googleprojectzero.blogspot.com/2016/06/a-year-of-windows-kernel-font-fuzzing-1_27.html
        * https://googleprojectzero.blogspot.com/2016/07/a-year-of-windows-kernel-font-fuzzing-2.html
        * https://github.com/signalsec/kirlangic-ttf-fuzzer
        * https://www.fortinet.com/blog/threat-research/a-14-day-journey-through-embedded-open-type-font-fuzzing

* other font types
    * .bdf and .pcf are used in XOrg Window server
    * .pfa printer specific fonts
    * .pf2 could be interesting: used by grub-mkfont (part of grub) https://elixir.bootlin.com/grub/2.00/source/util/grub-mkfont.c
    * .abf a binary format used by Adobe applications.
    * .sfd a database representation Used by FontForge, an open-source font editor
    * .VFB (FontLab Studio Font File): Specific to FontLab Studio, a professional font editing software.
    * .VLW (Processing Font File): Used in Processing, a flexible software sketchbook and a language for learning how to code within the context of visual arts.
    * .JFPROJ (JSON Font Project File): A JSON-based format for storing font projects.
    * .GLIF (Glyph Interchange Format File): Designed for exchanging vector graphics between applications.
    * .UFO (Unified Font Object File): Used by Glyphs, a popular font editor.
    

* android IMs
@    * LINE

* linux IMs and office apps


# Current Approach and Reasoning
* interested in software that performs parsing like fonts, images, audio, etc...
* enumerated an android IMs, automated library traversal for linux apps
* researching TTF and OTF implementations
* looking at how we can build on top of existing ttf research
* enumerating other font type targets




### Adobe Acrobat
    * Create a harness: Fuzz ttf input -> Alex script 
    * Fuzz other parser?


# Papers
* https://www.cs.ru.nl/~erikpoll/papers/inefficiency.pdf
* https://www.sciencedirect.com/science/article/pii/S0167404822003388?via%3Dihub
* https://ieeexplore.ieee.org/ielx7/52/9407245/09166552.pdf?tag=1

### Stateful Fuzzing
* https://dl.acm.org/doi/pdf/10.1145/3648468
* https://wcventure.github.io/FuzzingPaper/Paper/FSE17_Steelix.pdf
* https://dl.acm.org/doi/10.1007/s10664-022-10233-3
* https://dl.acm.org/doi/10.1145/3460319.3469077
