# Uncovering Linux Desktop Malware

This repository contains code related to the DFRWS US 25 paper [Uncovering Linux Desktop Espionage](https://dfrws.org/presentation/uncovering-linux-desktop-espionage/).

## Usage
As part of our research, we implemented several Volatility3 plugins to uncover spy attacks on Linux desktop users, e.g., keylogging or audio capturing. 
Further details on the techniques utilized by malware can be found in our paper.

**folder list**
* [/plugins](/plugins) contains the source code of the volatility plugins
* [plugins/symbols](/plugins/symbols) contains both linux kernel and application symbols
* [/attacks](/attacks) implementations of the spy attacks that were examined
* [/dumps](/dumps) the folder for the memory dumps of infected systems

To reproduce the results, first download the memory dumps infected systems at [download link](https://fh-muenster.sciebo.de/s/tfaMyfkrWAs2XmZ) and place them in the *dumps* folder.
Then install Volatility3 and use the following commands.

| Plugin | Description | Command |
|--------|-------------|---------|
| xevents | Extracts clients that capture events using X core events | `vol -r pretty -f dumps/xkeylogger_dump.lime -s plugins/symbols/ -p plugins/ -v xevents --name Xorg` |
| xinputextensions | Extracts clients that capture events using X input extensions | `vol -r pretty -f dumps/xkeylogger_ext_dump.lime -s plugins/symbols/ -p plugins/ -v xinputextensions --name Xorg` |
| xclients | Lists X11 client connections and window information | `vol -r pretty -f dumps/xkeylogger_xkb_dump.lime -s plugins/symbols/ -p plugins/ -v xclients --name Xorg` |
| v4l2 | Extracts processes that record camera and video streams using V4L2 | `vol -r pretty -f dumps/cam_dump.lime -s plugins/symbols/ -p plugins/ -v v4l2` |
| pipewire | Extracts PipeWire clients that record audio | `vol -r pretty -f dumps/mic_pulse_dump.lime -s plugins/symbols/ -p plugins/ -v pipewire --name pipewire` |
