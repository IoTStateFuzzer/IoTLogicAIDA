
### Base model
*   **Issue Description:** Unauthorized device control by removed family member due to improper access control persistence, allowing user2 to retain device control privileges after revocation of family membership. This violates permission timeliness rules and compromises system integrity by enabling unauthorized device manipulation.  
    **Problematic State(s):**  
        *   `s13`: Performed **user2|remote|DeviceControl**, received **CLS_1 Success response**, transitioned to **s13**, causing **user2 to maintain control despite explicit removal from family**.  
        *   `s14`: Performed **user2|remote|DeviceControl**, received **CLS_1 Success response**, transitioned to **s14**, causing **persistent unauthorized control after permission revocation**.  
        *   `s18`: Performed **user2|remote|DeviceControl**, received **CLS_1 Success response**, transitioned to **s18**, causing **unauthorized control after post-removal scan without acceptance**.  
        *   `s24`: Performed **user2|remote|DeviceControl**, received **CLS_1 Success response**, transitioned to **s24**, causing **control retention after family removal and device re-addition**.  
        *   `s30`: Performed **user2|local|DeviceControl** and **user2|remote|DeviceControl**, received **CLS_0/CLS_1 Success responses**, transitioned to **s30**, causing **unauthorized control despite prior removal from family**.

*   **Issue Description:** Improper family membership acquisition through orphaned permissions after device re-addition, allowing user2 to gain control of re-added devices without fresh invitation. This violates ownership management rules and enables unauthorized access.  
    **Problematic State(s):**  
        *   `s17`: Performed **AcceptInvite**, received **not specified**, transitioned to **s6**, causing **user2 to gain permanent control of re-added devices without fresh invitation**.  
        *   `s23`: Performed **AcceptInvite**, received **not specified**, transitioned to **s6**, causing **user2 to control re-added device despite prior removal**.

*   **Issue Description:** Information leakage via differential error codes in ScanQRCode operations, where distinct error responses (-2010 vs -2011) reveal invitation status and violate confidentiality.  
    **Problematic State(s):**  
        *   `s6, s8, s14, s16`: Performed **ScanQRCode**, received **error: -2010 (CLS_1)**, transitioned to **not specified**, causing **attacker inference of previous removal status**.  
        *   `s7, s9, s34`: Performed **ScanQRCode**, received **error: -2011 (CLS_2)**, transitioned to **not specified**, causing **attacker inference of invitation validity issues**.

*   **Issue Description:** Information leakage via uniform garbled error in QuitHome operations, where consistent error code (-30107) confirms non-membership status, compromising confidentiality.  
    **Problematic State(s):**  
        *   `s11, s12, s13, s14, s15, s16, s26, s27`: Performed **QuitHome**, received **{status:-30107, msg:'������������'}**, transitioned to **not specified**, causing **confirmation of attacker's non-membership status**.

*   **Issue Description:** Missing permission checks in critical operation failure paths, creating security gaps where QuitHome and DeviceControl failures lack explicit permission verification.  
    **Problematic State(s):**  
        *   `s12, s13, s14`: Performed **user2|remote|QuitHome**, received **CLS_5 Failure**, transitioned to **not specified**, causing **lack of initial permission verification before processing**.  
        *   `s21`: Performed **user2|remote|DeviceControl**, received **CLS_3 ErrorResponse ('device reset')**, transitioned to **not specified**, causing **no explicit permission check on failure path**.

### Divergent model
*   No issues found.