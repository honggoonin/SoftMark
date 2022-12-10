# SoftMark: Software Watermarking via a Binary Function Relocation

## Overview
**SoftMark** is a software watermarking system that leverages 
a function relocation where the order of functions implicitly encodes a hidden identifier. 
To implement SoftMark, we employ **CCR**, a special compiler toolchain 
that emits metadata for instrumenting a variant with a watermark.
 
For more details, please refer to our ACSAC 2021
[paper](https://dandylife.net/docs/softmark.acsac21.pdf).

For more details about CCR, please refer to [Kevin Koo](https://www.github.com/kevinkoo001)'s 
IEEE S&P 2018 
[paper](http://www3.cs.stonybrook.edu/~mikepo/papers/ccr.sp18.pdf).

## How to build SoftMark
We provide a handy build script (`build.sh`) to automate the entire toolchain installation which includes:
* CCR installation
* required packages installation
* python packages (`protobuf`, `pyelftools`, `capstone`, `r2pipe`, and `pathlib`) installation

### Notes for SofMark build
The CCR build script:
* requires at least 8GB memory and 30GB HDD space
* Installs `protoc`, `shuffleInfo.so`, and other necessary packages on your system
* Does not install the compiler and linker, but creates symbolic links instead
* Changes the default linker to `ld.gold` at build time, and to `ld-new` at the end

### Build with Docker
A Docker script is available for easily testing SoftMark within a Docker container. 
The following commands show how to install Docker and how to generate the SoftMark container.
```
$ curl -fsSL https://get.docker.com/ | sudo sh
$ sudo usermod -aG docker [user_id]

$ docker run ubuntu:16.04
Unable to find image 'ubuntu:16.04' locally
16.04: Pulling from library/ubuntu
... (omitted)
Status: Downloaded newer image for ubuntu:16.04

$ docker build -t softmark .
... (omitted)
CCR C Compiler    : /usr/local/bin/ccr
CCR C++ Compiler  : /usr/local/bin/ccr++
CCR Gold Linker   : /SoftMark/binutils-2.27/gold/ld-new
SoftMark Embedder : /SoftMark/randomizer/prander.py
SoftMark Extractor: /SoftMark/extractor/pextractor.py

$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
softmark            latest              b96f145a6e83        29 minutes ago      30.3GB
ubuntu              16.04               b6f507652425        15 months ago       112MB
```

Once the build has been successful, launch the Docker image 
to test out SoftMark.
```
$ docker run --rm -it softmark:latest /bin/bash
root@cd8dead1de94:/SoftMark# 
```

Or you can just download the images that everything is ready to use.
```
$ docker pull honggoonin/softmark:1.0
$ docker run --rm -it honggoonin/softmark:1.0 /bin/bash
```

For more information about Docker, visit [here](https://docs.docker.com/)


The following command generates a program variant with the randomizer, 
`prander.py`, which takes the binary to be transformed as its only argument.
The default option (`-f`) creates a transformed binary at the function level
(Use the `-b` option for basic block level randomization). The name of the variant is 
`[filename]_shuffled` by default.

```
$ cd ./examples && tar -zxvf vsftpd-2.3.4.tar.gz
$ cd ./vsftpd-2.3.4 && make
$ cp vsftpd ..
$ cd ../..
```

```
$ python ./randomizer/prander.py -b ./examples/vsftpd


                          ,...
     .M'''bgd           .d' ""mm   `7MMM.     ,MMF'                `7MM
    ,MI    "Y           dM`   MM     MMMb    dPMM                    MM
    `MMb.      ,pW"Wq. mMMmmmmMMmm   M YM   ,M MM   ,6"Yb.  `7Mb,od8 MM  ,MP'
      `YMMNq. 6W'   `Wb MM    MM     M  Mb  M' MM  8)   MM    MM' "' MM ;Y
    .     `MM 8M     M8 MM    MM     M  YM.P'  MM   ,pm9MM    MM     MM;Mm
    Mb     dM YA.   ,A9 MM    MM     M  `YM'   MM  8M   MM    MM     MM `Mb.
     "Ybmmd"   `Ybmd9'.JMML.  `Mbmo.JML. `'  .JMML.`Moo9^Yo..JMML. .JMML. YA.

                    * Watermark Embedder based on CCR *

 Software Watermarking via a Binary Function Relocation
 (In the Annual Computer Security Applications Conference 2021)

[INFO   ] Reading the metadata from the .rand section... (shuffleInfoReader.py:164)
[INFO   ]       Offset to the object  : 0x100 (shuffleInfoReader.py:165)
[INFO   ]       Offset to the main()  : 0x20 (shuffleInfoReader.py:166)
[INFO   ]       Total Emitted Bytes   : 0x10920 (shuffleInfoReader.py:167)
[INFO   ]       Number of Objects     : 38 (shuffleInfoReader.py:168)
[INFO   ]       Number of Functions   : 510 (shuffleInfoReader.py:169)
[INFO   ]       Number of Basic Blocks: 3474 (shuffleInfoReader.py:170)
[INFO   ]       Fixups in .text : 6753  (shuffleInfoReader.py:56)
[INFO   ]       Fixups in .rodata       : 334  (shuffleInfoReader.py:56)
[INFO   ]       Number of Jump Tables : 5 (shuffleInfoReader.py:200)
[INFO   ] Building up the layout... (prander.py:47)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ] Sanity check for examples/vsftpd...  (reorderInfo.py:593)
[INFO   ]       All sanity checks have been PASSED!! (reorderInfo.py:618)
[INFO   ] Performing reordering (@BBL)... (prander.py:52)
[INFO   ]       # of Function Constraints: 8 (reorderEngine.py:273)
[INFO   ] Reanalyzing the usable functions... (reorderEngine.py:298)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ]       # of small unusable functions: 346 (reorderEngine.py:597)
[INFO   ]       # of not unique functions: 21 (reorderEngine.py:598)
[INFO   ] Shuffling at the BBL granularity... (reorderEngine.py:302)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ]       # of Usable Functions: 143 (reorderEngine.py:382)
[INFO   ]       # of Functions with iCFT: 9 (reorderEngine.py:383)
[INFO   ]       # of Unused Functions: 367 (reorderEngine.py:384)
[INFO   ] Instrumenting the binary... (prander.py:70)
[INFO   ]       Processing section [.dynsym] (binaryBuilder.py:874)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ]       Processing section [.rela.dyn] (binaryBuilder.py:874)
[INFO   ]       Processing section [.text] (binaryBuilder.py:874)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ]       Processing section [.rodata] (binaryBuilder.py:874)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ]       Processing section [.eh_frame] (binaryBuilder.py:874)
[INFO   ]       Processing section [.eh_frame_hdr] (binaryBuilder.py:874)
[INFO   ]       Processing section [.init_array] (binaryBuilder.py:874)
[INFO   ]       Processing section [.data] (binaryBuilder.py:874)
[INFO   ] Summary of Binary Instrumentation (report.py:84)
[INFO   ]       Binary Name       : examples/vsftpd_shuffled (report.py:85)
[INFO   ]       Main() Addr       : 0x402920 -> 0x40e170 (report.py:88)
[INFO   ]       Symbol Patches    : 1 (.dynsym|.symtab) (report.py:95)
[INFO   ]       InitArray Patches : 0 (.init_array) (report.py:96)
[INFO   ]       CIE / FDE         : 2 / 514 (.eh_frame) (report.py:97)
[INFO   ]       FDE Patches       : 510 (.eh_frame) (report.py:98)
[INFO   ]       Pair Patches      : 510 (.eh_frame_hdr) (report.py:99)
[INFO   ]       Original MD5      : c21e555b028b730d43c932f4edd10f06 (report.py:101)
[INFO   ]       Shuffled MD5      : fd0edfdda0e73de0bba108c1abab5e67 (report.py:102)
[INFO   ]       Shuffled Size     : 0x010920 (report.py:103)
[INFO   ]       Metadata size     : 0x006131 (report.py:104)
[INFO   ]       Total Size        : 0x01ccd0 (report.py:105)
[INFO   ]       File Inc Rate     : 21.079% (report.py:106)
[INFO   ]       Entropy [LB, UB]  : [10^1131.39, 10^1210.39] possible versions (report.py:80)
[INFO   ] Total elapsed time: 13.098 sec(s) (prander.py:81)
[INFO   ] Success!! The log has been saved to examples/vsftpd_read.log (prander.py:177)
```


```
$ python ./extractor/pextractor.py ./examples/vsftpd_shuffled ./examples/vsftpd_watermarkingData/vsftpd_wm1_extractData.txt


                          ,...
     .M'''bgd           .d' ""mm   `7MMM.     ,MMF'                `7MM
    ,MI    "Y           dM`   MM     MMMb    dPMM                    MM
    `MMb.      ,pW"Wq. mMMmmmmMMmm   M YM   ,M MM   ,6"Yb.  `7Mb,od8 MM  ,MP'
      `YMMNq. 6W'   `Wb MM    MM     M  Mb  M' MM  8)   MM    MM' "' MM ;Y
    .     `MM 8M     M8 MM    MM     M  YM.P'  MM   ,pm9MM    MM     MM;Mm
    Mb     dM YA.   ,A9 MM    MM     M  `YM'   MM  8M   MM    MM     MM `Mb.
     "Ybmmd"   `Ybmd9'.JMML.  `Mbmo.JML. `'  .JMML.`Moo9^Yo..JMML. .JMML. YA.

                    * Watermark Extractor based on CCR *

 Software Watermarking via a Binary Function Relocation
 (In the Annual Computer Security Applications Conference 2021)


[INFO   ] Reading data for extraction... (pextractor.py:30)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ] Finding Functions by BBLcodes... (pextractor.py:40)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ] Check Watermark from function permutation... (pextractor.py:56)
                                        100% [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
[INFO   ] Watermark Extracted (pextractor.py:59)
[INFO   ]       0x67556b58703273357638782f413f4428472b4b6250655368566d597133743677L (pextractor.py:60)
[INFO   ] Total elapsed time: 2.746 sec(s) (pextractor.py:64)
[INFO   ] Finish!! The log has been saved to examples/vsftpd_watermarkingData/vsftpd_wm1.log (pextractor.py:134)
```


In general, you may want to set the default compilers as `ccr` and `ccr++` when running the `configure` script  to generate the `Makefile`. 


## Citation
If your research employs our SoftMark prototype, please cite the following papers:

```
@INPROCEEDINGS{softmark,
  author={Kang, Honggoo and Kwon, Yonghwi and Lee, Sangjin and Koo, Hyungjoon},
  title={SoftMark: Software Watermarking via a Binary Function Relocation},
  booktitle={ACSAC '21: Annual Computer Security Applications Conference},
  pages={169--181},
  month = dec,
  year={2021}
}
```
```
@INPROCEEDINGS{ccr,
  author = {Hyungjoon Koo and Yaohui Chen and Long Lu and Vasileios~P. Kemerlis and Michalis Polychronakis},
  title = {Compiler-assisted Code Randomization},
  booktitle = {Proceedings of the 39th IEEE Symposium on Security \& Privacy (S\&P)},
  pages = {472--488},
  month = {May},
  year = {2018},
  location = {San Francisco, CA}
}
```
