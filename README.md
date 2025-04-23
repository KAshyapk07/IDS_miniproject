# 🔐 Host-Based Intrusion Detection System (HIDS) – SYN Flood Detector

A simple yet effective **Host-Based Intrusion Detection System (HIDS)** that detects **SYN flood attacks** on a single PC using packet sniffing and analysis. Built using Python and the `scapy` library.

---

## 📌 Project Overview

This project is focused on identifying **SYN flood attacks**, a type of Denial of Service (DoS) where an attacker sends a large number of TCP SYN packets to a host, overwhelming it with half-open connections.

By monitoring and analyzing incoming packets, this system alerts the user when the threshold of unacknowledged SYN packets is crossed — indicating a potential SYN flood.

---

## 🎯 Features

- ✅ Detects SYN flood attacks in real-time
- ✅ Works on individual machines (Host-Based IDS)
- ✅ Uses raw packet capture and analysis
- ✅ Lightweight and customizable threshold values

---

## 🛠️ Technologies Used

- **Python 3**
- [`scapy`](https://scapy.readthedocs.io/en/latest/) – for packet sniffing and analysis
- **Socket programming**
- Basic **TCP/IP networking**

---
