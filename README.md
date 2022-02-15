# KillDefender_BOF  
Beacon Object File implementation of pwn1sher's KillDefender.  
Original POC: https://github.com/pwn1sher/KillDefender  

**Features:**  
CobaltStrike command checks to make sure beacon is Elevated or System and won't run if it isn't.  
BOF enumerates username and elevates token to System if the beacon isn't already running as it.  This is necessary in order to get a handle to MsMpEng.exe  
Otherwise works the same as the original KillDefender  
Tested on Win10, Win11, and Server 2019  

**Limitations:**  
Have not tested on x86 (mostly because I don't have ready access to a x86 win10 box)  
Unlike Cerbersec's implementation (https://github.com/Cerbersec/KillDefenderBOF), no direct syscalls or other fanciness is used here.  
Opens handles to Winlogon and MsMpEng.exe.  Further work could duplicate already open handles to Winlogon to avoid that IOC.  
**No low-vis way to revert! The only way to revert these changes is to restart MsMpEng.exe and short of installing a malicious driver you are going to need to restart the machine.**  

**Cobaltstrike command:**  
killdefender check - Check MsMpEng.exe's token in order to determine if KillDefender has already been run.  
killdefender kill - Remove privileges and set MsMpEng.exe token to untrusted rendering Defender useless (but still running).  

**Check:**  
![image](https://user-images.githubusercontent.com/91164728/153992668-290f25d2-4669-4217-85c1-4819d968f160.png)

**Kill:**  
![image](https://user-images.githubusercontent.com/91164728/153992698-e8b03168-18d0-45d5-a65a-5babb8588968.png)

**Check after kill:**  
![image](https://user-images.githubusercontent.com/91164728/153992720-8519bcbe-d7ab-4dbc-99d1-20af5c893a14.png)


**Compile using VS Native x64 prompt:** 
````
cl.exe /c /GS- /TP kdbof.cpp /FoKillDefender.x64.o
````
