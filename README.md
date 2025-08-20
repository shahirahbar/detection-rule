# Threat Detection Rules & IOCs Repository

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](https://github.com/your_username/your_repository/issues)

A curated collection of detection rules and Indicators of Compromise (IOCs) designed for proactive threat hunting and automated security monitoring. This repository provides detections in multiple formats to empower security teams across different SIEM and EDR platforms.

## 📦 What's Inside

This repository contains rules and queries in the following formats:

*   **Sigma Rules:** Open, generic, and vendor-agnostic signature format for SIEM systems. Use [Sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) to convert them to your target platform.
*   **Elastic EQL Rules:** Native detection rules for the **Elastic Stack** (Elastic Security, Elasticsearch). EQL (Event Query Language) allows for sophisticated correlation across events based on process lineage, DNS queries, and more.
*   **Splunk SPL Searches:** Ready-to-run Splunk Processing Language (SPL) queries for direct use in **Splunk Enterprise Security (ES)** or Splunk Enterprise.

Each detection is paired with its corresponding raw search query, allowing for immediate deployment, testing, and customization.

## 🚀 Quick Start

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your_username/your_repository.git
    cd your_repository
    ```

2.  **Navigate to the Desired Directory**
    The rules are organized by format and threat category (e.g., `sigma/`, `eql/`, `spl/`).

3.  **Deploy a Rule**
    *   **For Sigma:** Convert a `.yml` rule to your SIEM's syntax using Sigmac and then deploy.
    *   **For Elastic:** Import an EQL rule directly into your Elastic Security detection rules list.
    *   **For Splunk:** Copy the SPL query from a `.spl` or `.txt` file and paste it into a new Splunk alert or dashboard panel.

## 📁 Repository Structure
