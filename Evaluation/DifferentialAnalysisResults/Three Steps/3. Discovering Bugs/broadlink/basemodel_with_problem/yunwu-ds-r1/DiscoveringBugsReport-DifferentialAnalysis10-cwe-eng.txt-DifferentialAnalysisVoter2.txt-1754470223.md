

### Base model
*   **Issue 1: Unauthorized Device Control After Permission Revocation**  
    **Impact:** User2 retains device control privileges after being removed from family membership, violating permission revocation mechanisms. This enables privilege escalation and unauthorized access to smart home devices through multiple persistence vectors including historical permissions and QR code scanning post-removal.  
    **Problematic State(s):**  
        *   `s13`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s13**, causing **retention of device control after family membership removal**.  
        *   `s14`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s14**, causing **permanent control retention post-explicit removal by User1**.  
        *   `s18`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s18**, causing **unauthorized control through invitation scanning without valid membership**.  
        *   `s30`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, transitioned to **State s30**, causing **persistent access after family removal**.

*   **Issue 2: Information Leakage via Differential Error Patterns**  
    **Impact:** Distinct error codes and response patterns enable attackers to infer system states including invitation validity, device status (reset/removed), and historical permissions. This violates differential inference principles by exposing:  
    1) Invitation lifecycle status through QR code errors (-2010/-2011)  
    2) Device operational state through response presence/absence  
    3) Historical membership status through CLS symbol variations.  
    **Problematic State(s):**  
        *   `s5/s6`: Performed **user2|remote|ScanQRCode**, received **CLS_0 (Success)** vs **CLS_1 (-2010)**, allowing inference of **invitation acceptance status**.  
        *   `s6/s7`: Performed **user2|remote|ScanQRCode**, received **-2010** vs **-2011**, exposing **invitation validity state (pending vs invalid)**.  
        *   `s8/s9`: Performed **user2|remote|ScanQRCode**, received **CLS_1/CLS_2 errors**, revealing **historical invitation patterns**.  
        *   `s15`: Performed **user2|remote|DeviceControl**, received **CLS_NoResponse**, enabling detection of **device removal state**.  
        *   `s16/s19`: Performed **user2|remote|ScanQRCode**, received **-2010** vs **CLS_0**, exposing **re-invitation status**.  
        *   `s21/s22`: Performed **user2|remote|DeviceControl**, received **CLS_3 ("device reset") errors**, leaking **device operational state**.  

### Divergent model
*   No issues found.