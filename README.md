# `simple-pe-parser`
### A simple PE(Portable Executable) parser written in C using WINAPI
This project parses multiple sections of Windows executable data format(PE) for educational purposes. It was purely written in C language with WINAPI.
You can build the project with Visual Studio(by "cloning GitHub repository feature". For my case, Visual Studio Community 2022) in a Windows environment, and easily modify or suggest(by pull request) new stuff to the project!

### Which sections can be parsed?
- DOS Header
- NT Header (file and optional headers, for both 32-bit and 64-bit architecture)
- NT File Directory Header
- NT File Section Header
- NT IAT(Import Address Table)
- Relocation table (`.reloc`)
  
(Feel free to contribute to this project to parse more information from more parts of PE format/fix incorrectly parsed sections in this project/...!)

### Preview
![image](https://github.com/user-attachments/assets/63da78d7-22ab-4d58-b989-d972af83aca2)
![image](https://github.com/user-attachments/assets/cabc1f54-721c-4f29-be8a-f80b31ab8467)
![image](https://github.com/user-attachments/assets/1dbe055c-1987-42de-8b74-85a649a1397b)
