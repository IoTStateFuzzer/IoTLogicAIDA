### Base model
*   **Issue Description:** Inconsistent device control permissions after user2 quits or is removed from family membership.
    *   **Problematic State(s):**
        *   `s13`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 13**, causing **user2 retains device control despite being removed from family membership**.
        *   `s14`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 14**, causing **user2 retains device control despite being removed from family membership**.
        *   `s18`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 18**, causing **user2 retains device control despite being removed from family membership**.
        *   `s20`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 20**, causing **user2 retains device control despite quitting family membership**.
        *   `s25`: Performed **user2|remote|DeviceControl**, received **Failed**, transitioned to **State 25**, causing **inconsistent behavior compared to state 20 where control was retained**.
        *   `s30`: Performed **user2|remote|DeviceControl**, received **Success**, transitioned to **State 30**, causing **unauthorized device control by non-family member**.

*   **Issue Description:** Inconsistent error handling for `QuitHome` operation when user2 is not a family member.
    *   **Problematic State(s):**
        *   `s11`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 11**, causing **user2 to receive an unclear error message when attempting to quit a non-existent family membership**.
        *   `s12`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 12**, causing **same unclear error message**.
        *   `s13`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 13**, causing **same unclear error message**.
        *   `s14`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 14**, causing **same unclear error message**.
        *   `s15`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 15**, causing **same unclear error message**.
        *   `s16`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 16**, causing **same unclear error message**.
        *   `s21`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 21**, causing **same unclear error message**.
        *   `s22`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 22**, causing **same unclear error message**.
        *   `s26`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 26**, causing **same unclear error message**.
        *   `s31`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 31**, causing **same unclear error message**.
        *   `s32`: Performed **user2|remote|QuitHome**, received **{'status':-30107,'msg':'������������'}**, transitioned to **State 32**, causing **same unclear error message**.

*   **Issue Description:** Information leakage through differential error responses in ScanQRCode operations.
    *   **Problematic State(s):**
        *   `s6`: Performed **user2|remote|ScanQRCode**, received **Failed (error:-2010)**, transitioned to **State 6**, causing **leakage of previous family membership status**.
        *   `s7`: Performed **user2|remote|ScanQRCode**, received **Failed (error:-2011)**, transitioned to **State 7**, causing **leakage of duplicate invitation state**.
