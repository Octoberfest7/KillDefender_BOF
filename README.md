# KillDefender_BOF
Beacon Object File implementation of pwn1sher's KillDefender.

**Features:**  
CobaltStrike command checks to make sure beacon is Elevated or System and won't run if it isn't.  
BOF enumerates username and elevates token to System if the beacon isn't already running as it.  This is necessary in order to get a handle to MsMpEng.exe  
Otherwise works the same as the original KillDefender  

**Have not tested on x86**  

**Cobaltstrike command:**  
killdefender check - Check MsMpEng.exe's token in order to determine if KillDefender has already been run.  
killdefender kill - Remove privileges and set MsMpEng.exe token to untrusted rendering Defender useless (but still running).  

**Check:**  
![image](https://user-images.githubusercontent.com/91164728/153991748-eb00a6a8-b5ac-4c35-8077-c55190f6269e.png)

**Kill:**  
![image](https://user-images.githubusercontent.com/91164728/153991778-2bbe9880-f373-4472-826e-80b88f428d4c.png)




Compile using VS Native x64 prompt:  
````
cl.exe /c /GS- /TP BOF.cpp /FoBOF.x64.o
````
