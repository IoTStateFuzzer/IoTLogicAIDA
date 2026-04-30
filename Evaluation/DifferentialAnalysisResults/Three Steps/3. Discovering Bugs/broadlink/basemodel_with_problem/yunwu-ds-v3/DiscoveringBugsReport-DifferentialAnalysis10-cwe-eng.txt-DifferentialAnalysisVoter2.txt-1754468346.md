### Base model
*   **Issue Description:** Inconsistent device control permissions after family membership removal. User2 retains device control permissions in certain states despite being removed from the family, violating the intended permission revocation logic.
    *   **Problematic State(s):**
        *   `s13`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 13**, causing **user2 retains control despite being removed from family**.
        *   `s14`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 14**, causing **user2 retains control despite being removed from family**.
        *   `s18`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 13/18**, causing **user2 retains control despite being removed from family**.

*   **Issue Description:** Information leakage through differential error responses in ScanQRCode operations. Different error codes (-2010 vs. -2011) reveal whether user2 was previously a family member or not.
    *   **Problematic State(s):**
        *   `s6`: Performed **user2|remote|ScanQRCode**, received **Failed with error -2010**, transitioned to **State 6**, causing **leakage of user2's previous family membership status**.
        *   `s7`: Performed **user2|remote|ScanQRCode**, received **Failed with error -2011**, transitioned to **State 7**, causing **leakage of user2's previous family membership status**.
        *   `s20`: Performed **user2|remote|ScanQRCode**, received **Failed**, transitioned to **State 20**, causing **user2 loses family membership but device control is not explicitly revoked**.

*   **Issue Description:** Improper error handling in QuitHome operation. The same garbled error message appears regardless of context, potentially masking important security states.
    *   **Problematic State(s):**
        *   `s11`: Performed **user2|remote|QuitHome**, received **Garbled error message**, transitioned to **State 11**, causing **masking of actual security state**.
        *   `s12`: Performed **user2|remote|QuitHome**, received **Garbled error message**, transitioned to **State 12**, causing **masking of actual security state**.
        *   `s13`: Performed **user2|remote|QuitHome**, received **Garbled error message**, transitioned to **State 13**, causing **masking of actual security state**.

### Divergent model
*   No issues found.