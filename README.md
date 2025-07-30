# HyperVinject

This PoC injects a shellcode inside a user-mode process running in a Hyper-V child partition. The injection is performed from the root partition, and it requires admin privileges. 

Note that the root partition already has complete control over the running child partition; as a result, HyperVinject does not break any security boundary.

## Building the PoC

Build using VisualStudio. There are no external dependencies.

## Running the PoC

On the host (root partition), simply run the `vminject.exe` executable with the following arguments:
* the name of the target VM
* the ID of the target process running inside the VM

Example:
```console
vminject "Windows 11 24H2" 1280
```

The `vminjectdll.dll` DLL creates a log inside `D:\hypervinject\hypervinject.log`. This location can be changed by modifying `LOG_FILE` defined in `log.c`.

## Kernel shellcode

The assembly source code for the kernel-mode loader can be found in `loader\loader.asm`.

## User shellcode

Any user-mode shellcode can be used, but none is provided by default. Add your favorite user-mode shellcode in `shellcode.h`.


## Mitigations

While HyperVinject requires administrative privileges within the root partition (i.e., full control of the host), the following mitigations can effectively prevent or detect its use:

- **Enable Shielded VMs** (VM Settings → Security → Enable Shielding). When running a Shielded VM, the associated `vmwp.exe` process runs as a **Protected Process Light (PPL)**. This protection prevents unauthorized user-mode access, including memory injections, even from other administrative processes on the host.
- **Use memory encryption technologies**. Technologies such as **Intel TDX** or **AMD SEV-SNP** encrypt guest memory, making it inaccessible to the hypervisor or host, effectively preventing this type of injection.
- **Deploy EDR or anti-malware solutions in the root partition**. Since the injection begins in the `vmwp.exe` process on the host, well-instrumented security solutions running in the root partition are likely to detect or block the initial step of HyperVinject.

# Disclaimer
This work is intended for educational and research purposes only. The techniques and information described herein are provided to promote awareness and improve security practices. The author does not endorse or condone malicious activity and expressly disclaims any responsibility for misuse of the information, including any activity that violates applicable laws, regulations, or terms of service. Use of the information is at the reader’s own risk and discretion. It is your responsibility to ensure that any actions taken using this information are lawful and ethical in your jurisdiction. It is also worth mentioning from the beginning that this is not a 0-day or an exploit of any kind. Injecting code inside a running Hyper-V VM requires that the attacker already has admin access to the root partition, so no security boundaries are broken, since the HV, and by extension the root partition, already have full control over the child partition.

# License
This project is licensed under the [BSD 3-Clause License](./LICENSE).
