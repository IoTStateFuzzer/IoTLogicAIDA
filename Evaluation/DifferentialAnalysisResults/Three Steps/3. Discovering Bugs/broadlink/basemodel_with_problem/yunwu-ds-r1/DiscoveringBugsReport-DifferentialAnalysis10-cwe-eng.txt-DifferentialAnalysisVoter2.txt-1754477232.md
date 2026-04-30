

### Base model
*   **Vulnerability 1: Unauthorized Device Control After Family Membership Removal**
    *   **Impact:** User2 retains persistent device control privileges after being removed from the family by User1, violating authorization principles. This allows unauthorized device manipulation and privilege escalation, as revoked permissions are not properly enforced across multiple system states.
    *   **Problematic State(s):**
        *   `s13`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s13**, causing **retention of control privileges after explicit removal from family**.
        *   `s14`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s14**, causing **unauthorized device manipulation post-removal**.
        *   `s18`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s18**, causing **unauthorized control through post-removal invitation without acceptance**.
        *   `s30`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s30**, causing **exploitation of residual permissions after removal**.

*   **Vulnerability 2: Information Leakage via Differential Error Codes**
    *   **Impact:** Distinct error codes and response patterns enable attackers to infer sensitive system states including invitation validity, device reset status, family membership lifecycle, and invitation multiplicity. This violates confidentiality through differential inference attacks across multiple state transitions.
    *   **Problematic State(s):**
        *   `s5` vs `s6`: Performed **ScanQRCode**, received **CLS_0 (Success)** vs **CLS_1 (error -2010)**, enabling inference of invitation acceptance status.
        *   `s6` vs `s7`: Performed **ScanQRCode**, received **CLS_1 (error -2010)** vs **CLS_2 (error -2011)**, revealing invitation multiplicity (single vs multiple).
        *   `s16` vs `s19`: Performed **ScanQRCode**, received **CLS_1 (error -2010)** vs **CLS_0 (Success)**, exposing family membership lifecycle changes.
        *   `s21`: Performed **DeviceControl**, received **CLS_3 ("device reset, please rebind")**, revealing device reset state.
        *   `s22`: Performed **DeviceControl**, received **CLS_5**, indicating rebind requirements.
        *   `s8` vs `s9`: Performed **ScanQRCode**, received distinct CLS patterns, leaking invitation history post-removal.
        *   `s21` vs `s15`: Performed **DeviceControl**, received **CLS_3** vs **CLS_NoResponse**, differentiating between device reset and full unbind states.
