# AVStreamLens

Interactive CLI that can detect, monitor, analyse and debug your AV streams on any network.
Currently supports AES67, AVB, Dante, NDI and ST2110.

AVStreamLens passively read your network using pcap, tries to identify potential problems monitoring PTP clock presence, IGMP, jitter, packet loss, dead streams... and reports/logs usefull human readable informations to the user every 5 seconds.