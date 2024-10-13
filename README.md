# `simple-pe-parser`
### A simple PE(Portable Executable) parser written in C using WINAPI
This project parses multiple sections of Windows executable data format(PE) for educational purposes. It was purely written in C language with WINAPI.
You can build the project with Visual Studio(by "cloning GitHub repository feature". For my case, Visual Studio Community 2022) in a Windows environment, and easily modify or suggest(by pull request) new stuff to the project!

### Which sections can be parsed?
- DOS Header
- Rich header (and the interpretation of `@comp.Id` values)
- NT Header (file and optional headers, for both 32-bit and 64-bit architecture)
- NT File Directory Header
- NT File Section Header
- NT IAT(Import Address Table)
- NT Export Directory
- NT EAT(Export Function Table)
- Relocation table (`.reloc`)
  
(Feel free to contribute to this project to parse more information from more parts of PE format/fix incorrectly parsed sections in this project/...!)

### Preview
![image](https://github.com/user-attachments/assets/8e64d08c-04a6-4db2-ac51-d3716fed0247)
![image](https://github.com/user-attachments/assets/c4cea1ed-0144-4495-8885-295e3b12e1e8)
![image](https://github.com/user-attachments/assets/59f7bfba-4163-4863-9b08-d82d4d5d0c0e)
![image](https://github.com/user-attachments/assets/0368d968-8f4e-46fb-8b48-2fb55e91975a)
![image](https://github.com/user-attachments/assets/348fa55b-f844-48e2-90f2-8235e008878c)
