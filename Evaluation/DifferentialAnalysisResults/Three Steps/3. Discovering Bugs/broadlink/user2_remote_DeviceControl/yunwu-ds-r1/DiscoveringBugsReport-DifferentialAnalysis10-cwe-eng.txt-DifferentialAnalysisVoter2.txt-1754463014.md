
### Base model
*   **Issue Description:** Unauthorized ScanQRCode Success Without Permissions  
    **Problematic State(s):**  
        *   `s11`: Performed **user2|remote|ScanQRCode**, received **Success**, transitioned to **State s10**, causing **user2 to gain scan capability without permissions**.  
*   **Issue Description:** AcceptInvite Success Without Device Present  
    **Problematic State(s):**  
        *   `s14`: Performed **user2|remote|AcceptInvite**, received **Success**, transitioned to **State s6**, causing **user2 to become family member without device present**.  
*   **Issue Description:** Permissions Not Revoked After Device Removal  
    **Problematic State(s):**  
        *   `s11`: Performed **user1|local|RemoveDevice**, received **Success**, transitioned to **State s3**, causing **user2's permissions to remain active despite device reset**.  
        *   `s8`: Performed **user2|local|DeviceControl**, received **Success**, causing **unauthorized control when permissions should have been invalidated after device reset**.

### Divergent model
*   **Vulnerability 1: Unauthorized Device Control After Permission Revocation or During Invalid States**  
    **Impact:** Attackers retain or gain unauthorized device control permissions after quitting the family, during pending invitations, or after device resets. This violates access control principles, allowing persistent manipulation of critical device functions despite revoked permissions or incomplete authorization workflows.  
    **Problematic State(s):**  
        *   `s19`: Performed **user2|remote|DeviceControl**, received **Success (CLS_1)**, transitioned to **State s19**, causing **unauthorized control despite quitting family**.  
        *   `s20`: Performed **user2|remote|DeviceControl**, received **Success (CLS_1)**, transitioned to **State s19**, causing **unauthorized control after quitting family or with no permissions**.  
        *   `s25`: Performed **user2|remote|DeviceControl**, received **Success (CLS_1)**, transitioned to **State s19**, causing **unauthorized control during pending invitation without accepting**.  
        *   `s31`: Performed **user2|remote|DeviceControl**, received **Success (CLS_1)**, transitioned to **State s31**, causing **unauthorized control after quitting family**.  
*   **Vulnerability 2: Information Leakage via Error Messages and Differential Responses**  
    **Impact:** Error messages and response patterns reveal internal device state, including reset status, device presence/absence, and membership information. This violates confidentiality by enabling attackers to infer system states for reconnaissance and escalation.  
    **Problematic State(s):**  
        *   `s5`: Performed **user2|remote|ScanQRCode**, received **error:-2010 (CLS_1)**, transitioned to **State s5**, causing **leakage of state differences for membership/device inference**.  
        *   `s16`: Performed **user2|remote|DeviceControl**, received **Empty response**, causing **leakage of device absence**.  
        *   `s18`: Performed **user2|remote|DeviceControl**, received **ErrorResponse: 'device reset, please rebind' (CLS_3)**, transitioned to **State s18**, causing **leakage of device reset state and presence to non-family users**.  
        *   `s21`: Performed **user2|remote|DeviceControl**, received **'device reset, please rebind' error**, transitioned to **State s21**, causing **leakage of device reset state and presence**.  
        *   `s24`: Performed **user2|remote|DeviceControl**, received **'device reset, please rebind' error**, causing **leakage of device reset state and presence despite 'absent' state description**.  
        *   `s28`: Performed **user2|remote|DeviceControl**, received **ErrorResponse: 'device reset, please rebind' (CLS_3)**, transitioned to **State s28**, causing **leakage of device reset state after re-addition**.  
*   **Vulnerability 3: Improper Permission Inheritance After Device Re-Addition**  
    **Impact:** Device re-addition automatically grants control permissions without re-authorization, allowing attackers to regain access after device resets. This bypasses security workflows for permission validation.  
    **Problematic State(s):**  
        *   `s29`: Performed **user1|local|AddDevice**, received **Success**, transitioned from **s16 to s29**, causing **automatic control grant to user2 without re-authorization after reset**.  
        *   `s32`: Performed **user2|remote|DeviceControl**, received **Success (CLS_1)**, causing **unauthorized control after device re-add without re-authorization**.  
*   **Vulnerability 4: Privilege Escalation via ScanQRCode-AcceptInvite Path**  
    **Impact:** Combining ScanQRCode with the AcceptInvite path allows attackers to bypass invitation acceptance steps, granting unauthorized control permissions through workflow exploitation.  
    **Problematic State(s):**  
        *   `s10`: Performed **user2|remote|ScanQRCode**, received **Success**, transitioned to **State s8** via AcceptInvite path, causing **bypass of invitation acceptance to gain permissions**.  
        *   `s20`: Performed **user2|remote|ScanQRCode**, received **Success**, transitioned to **State s30** via AcceptInvite path, causing **privilege escalation after quitting family**.