
### Base model
*   **Issue Description:** Unintended state transitions during user invitation processes, violating business logic and permission assignment.
*   **Problematic State(s):**
    *   `s1`: Performed **user1|local|InviteToHome**, received **Success**, transitioned to **s11**, causing **logical inconsistency by transitioning to 'quit family' state instead of 'invited' state**.
    *   `s11`: Performed **user1|local|InviteToHome**, received **Success**, transitioned to **s11** (remained), causing **failure to transition to invited state when re-inviting previously quit user**.

### Divergent model
*   **Vulnerability 1: Unauthorized Device Control After Permission Revocation**  
    *   **Impact:** Attackers (e.g., user2) retain persistent device control capabilities despite revoked family membership or unaccepted invitations, enabling unauthorized device manipulation that violates confidentiality, integrity, and access control policies.
    *   **Problematic State(s):**
        *   `s19`: Performed **user2|remote|DeviceControl**, received **success (CLS_1)**, transitioned to **s19**, causing **retained control after quitting family**.
        *   `s20`: Performed **user2|remote|DeviceControl**, received **success (CLS_1)**, transitioned to **s19**, causing **device control without family membership**.
        *   `s25`: Performed **user2|remote|DeviceControl**, received **success (CLS_1)**, transitioned to **s19**, causing **control without accepting invitation**.
        *   `s31`: Performed **user2|remote|DeviceControl**, received **success (CLS_1)**, transitioned to **s31**, causing **persistent access after permission revocation**.

*   **Vulnerability 2: Device State Inference via Differential Error Messages**  
    *   **Impact:** Error responses disclosing device reset status (CLS_3) enable attackers to infer device lifecycle changes and system state, violating confidentiality through reconnaissance opportunities that reveal owner actions and device availability.
    *   **Problematic State(s):**
        *   `s18`: Performed **user2|remote|DeviceControl**, received **'device reset, please rebind' (CLS_3)**, transitioned to **s18**, causing **leakage of device reset state to unauthorized user**.
        *   `s21`: Performed **user2|remote|DeviceControl**, received **'device reset, please rebind' (CLS_3)**, transitioned to **s18**, causing **inference of device re-initialization**.
        *   `s24`: Performed **user2|remote|DeviceControl**, received **'device reset, please rebind' (CLS_3)**, transitioned to **s18**, causing **exposure of reset event without privileges**.
        *   `s28`: Performed **user2|remote|DeviceControl**, received **'device reset, please rebind' (CLS_3)**, transitioned to **s28**, causing **persistent state leakage across ownership changes**.