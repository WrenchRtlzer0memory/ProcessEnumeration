# Process Enumeration Tool

## Introduction

This tool is designed for advanced Windows users and developers to enumerate processes and their associated modules in real-time. Leveraging the Windows Native API (`NtQuerySystemInformation`) and standard system libraries, the program provides comprehensive information about a specific process by its Process ID (PID).

## Features

- Retrieve detailed information about a process, including:
  - **PID**
  - **Session ID**
  - **Image Name**
  - **Number of Handles and Threads**
  - **Virtual Memory Usage Statistics**
- Enumerate and display all loaded modules for the specified process.
- Built using system libraries like `Psapi` and `Ntdll` for deep system insights.

## Usage

- Enter the PID of the process you want to analyze.
- View the detailed process information and the list of associated modules.

---

This tool is particularly useful for debugging, reverse engineering, or gaining insights into running processes on a Windows system.
