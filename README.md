# Steam Pipes

*Final Project for CS 445: Internet-Scale Experimentation*

This code accompanies our report, entitled ["Steam Pipes - An Analysis of Steam’s Content Delivery Strategy" ](https://jnbaldwin.com/assets/files/steam_pipes_report.pdf)

## Abstract

> Our research delves into Steam, the leading digital distribution platform for PC games, examining its content delivery strategy amidst the exponential growth of gaming. We analyze Steam's approach to handling massive file sizes and global demand, investigating implications for content delivery optimization. Employing simulated user interactions and network analysis tools, we dissect Steam's CDN architecture to unravel its dependency mechanisms. We find that Steam utilizes a network of cache servers to speed up data downloads, with the Steam client preferring downloading from these cache servers over third party CDNs. Our findings contribute insights into network dynamics and offer implications for content delivery systems beyond gaming platforms.

## Usage

See `capture.bash` for our simple script to initate a download and save all network traffic

See `analysis.py` and `extract_hosts.py` for the core analysis of network packets using PyShark and Scapy

See `visualization.ipynb` for code responsible for all visualizations in the final report

### Example Visual

![Timeline visualization of packets during Steam download](https://raw.githubusercontent.com/icemoon97/steam-pipes/assets/images/download_timeline.png)