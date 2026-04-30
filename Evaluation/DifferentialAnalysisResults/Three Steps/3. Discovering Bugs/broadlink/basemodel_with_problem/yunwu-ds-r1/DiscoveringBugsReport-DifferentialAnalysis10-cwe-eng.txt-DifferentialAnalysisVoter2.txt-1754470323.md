
### Base model
*   **Vulnerability 1: Unauthorized Device Control After Family Removal**  
    **Impact:** User2 retains successful device control (CLS_1) across multiple states after being removed from the family, violating authorization checks and enabling persistent unauthorized access to device functions. This failure to revoke permissions creates a privilege escalation vector.  
    **Problematic State(s):**  
        *   `s13`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, causing **retained control post-family removal**.
        *   `s14`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, causing **privilege retention after membership revocation**.
        *   `s18`: Performed **user2|remote|DeviceControl**, received **CLS_1 (Success)**, causing **unauthorized control without valid permissions**.

*   **Vulnerability 2: Information Leakage via ScanQRCode Error Differentiation**  
    **Impact:** Differential error codes (-2010/CLS_1 vs -2011/CLS_2) during ScanQRCode operations allow User2 to infer invitation system states (e.g., validity of invitations, existence of pending requests), violating confidentiality principles through observable response patterns.  
    **Problematic State(s):**  
        *   `s6`: Performed **user2|remote|ScanQRCode**, received **CLS_1 (Error -2010)**, causing **disclosure of invalid invitation state**.
        *   `s7`: Performed **user2|remote|ScanQRCode**, received **CLS_2 (Error -2011)**, causing **leakage of invitation history data**.

*   **Vulnerability 3: Device State Exposure via Error Response Patterns**  
    **Impact:** Distinct DeviceControl responses (CLS_NoResponse, CLS_3, CLS_5) reveal sensitive device status information to unauthorized users, including reset states and UDP traffic patterns, enabling attackers to infer internal device conditions.  
    **Problematic State(s):**  
        *   `s15`: Performed **user2|remote|DeviceControl**, received **CLS_NoResponse**, causing **inference of device state through response absence**.
        *   `s21`: Performed **user2|remote|DeviceControl**, received **CLS_3 ("device reset")**, causing **exposure of reset status**.
        *   `s22`: Performed **user2|remote|DeviceControl**, received **CLS_3 ("device reset")**, causing **continued leakage of reset state**.

### Divergent model
*   No issues found.