
### A04:2021 – **Insecure Design**  

#### Overview
**Insecure Design** is a new category introduced in the 2021 OWASP Top 10, highlighting risks stemming from **design and architectural flaws** in applications. These flaws go beyond implementation mistakes, focusing instead on insufficient forethought during the design phase of application development. 

The category calls for more proactive practices like:
- **Threat Modeling**: Identifying and analyzing potential threats early in the design process.
- **Secure Design Patterns**: Applying proven solutions to common security challenges.
- **Reference Architectures**: Using well-vetted architectural blueprints to guide secure application development.

It emphasizes moving beyond traditional "shift-left" practices, which focus on security in the coding phase, to include **pre-coding activities** that embody the principles of "Secure by Design."

---

### Key Factors and Statistics
1. **Common Weakness Enumerations (CWEs) Mapped**: 40  
   Examples include:
   - **CWE-209**: Generation of Error Message Containing Sensitive Information  
   - **CWE-256**: Unprotected Storage of Credentials  
   - **CWE-501**: Trust Boundary Violation  
   - **CWE-522**: Insufficiently Protected Credentials  

2. **Statistics**:
   - **Max Incidence Rate**: 24.19%  
     Indicates the highest frequency of insecure design occurrences across surveyed applications.
   - **Avg Incidence Rate**: 3.00%  
     The average occurrence rate for this vulnerability type.
   - **Avg Weighted Exploit**: 6.46  
     A measure of how likely these vulnerabilities are to be exploited, averaged across instances.
   - **Avg Weighted Impact**: 6.78  
     Reflects the average severity or damage potential of such exploits.
   - **Max Coverage**: 77.25%  
     The highest proportion of applications in which this issue was detected.
   - **Avg Coverage**: 42.51%  
     The average percentage of applications containing this issue.

3. **Occurrences and CVEs**:
   - **Total Occurrences**: 262,407  
     Total instances of insecure design detected.
   - **Total CVEs**: 2,691  
     Number of publicly disclosed vulnerabilities (Common Vulnerabilities and Exposures) linked to insecure design flaws.

---

### Why This Matters
**Insecure Design** issues often emerge when:
- Threats are not adequately anticipated during the design phase.
- Secure design principles, such as data minimization or secure defaults, are not applied.
- Critical functionalities (like authentication, error handling, or data storage) lack proper design controls.

This category underscores the importance of:
- Investing in **early-phase security activities**, such as architectural risk assessments.
- Reducing the cost of security fixes by preventing flaws **before coding begins**.
- Training developers and architects on secure design practices.

---

### Practical Takeaways
1. **Prevention Strategies**:
   - Conduct **threat modeling sessions** during the design phase.
   - Use **secure design frameworks** and principles.
   - Leverage tools for **design-time validation**, such as automated security architecture analysis.

2. **Examples of Poor Design**:
   - Storing passwords in plaintext instead of hashing them securely.
   - Allowing verbose error messages that leak sensitive information (e.g., stack traces in production).
   - Failing to implement least privilege for sensitive operations or users.

3. **Key Challenges**:
   - Lack of awareness about design risks among teams.
   - Pressure to deliver features quickly, sacrificing security considerations.
   - Over-reliance on downstream testing or security fixes rather than addressing root causes.

---
### **Insecure Design: Description**

**Insecure Design** is a category of vulnerabilities that stems from **missing or ineffective security controls in the design phase** of a system or software. It focuses on weaknesses introduced by flawed architectural decisions rather than coding or implementation errors.

---

### **Key Characteristics**
1. **Not the Source of All Risks**:
   - While many risks in the OWASP Top 10 arise from implementation issues, **Insecure Design** focuses on **flaws in the foundational architecture or design decisions**.
   - Example: A poorly designed user role management system where administrative privileges are granted without proper validation.

2. **Design vs. Implementation**:
   - **Design Flaws**: Issues caused by inadequate planning or consideration during the **architectural phase**.
     - Example: Designing an application without considering secure session management.
   - **Implementation Defects**: Errors made during the **coding phase** that can undermine even a secure design.
     - Example: Incorrectly implementing encryption algorithms in an otherwise securely designed system.

   - **Difference**: 
     - A secure design can result in vulnerabilities due to flawed implementation.
     - An insecure design cannot be rectified even with flawless implementation, as necessary controls were never planned.

3. **Business Risk Profiling**:
   - Many insecure designs result from a **lack of understanding of business risks** during the development process.
   - Example: If a system is built for processing financial transactions but lacks multi-factor authentication, it’s inherently insecure because the **business risk of fraud** wasn’t addressed during design.

4. **Irremediable by Implementation**:
   - Once a security control is omitted during design, no implementation excellence can fix the gap.
   - Example: If no data validation is planned during design, implementing code without any validation will leave the system exposed.

---

### **Factors Leading to Insecure Design**
1. **Lack of Threat Modeling**:
   - Failing to identify potential attack scenarios and design corresponding defenses.
   - Example: Ignoring the possibility of SQL injection attacks during database interaction design.

2. **Absence of Risk-Based Security Requirements**:
   - Neglecting to assess the **impact of a potential breach** and establish corresponding controls.
   - Example: Designing a healthcare system without considering patient privacy regulations like HIPAA.

3. **Failure to Use Secure Design Principles**:
   - Not leveraging proven security frameworks, patterns, or guidelines.
   - Example: Designing a password reset process without proper identity verification.

---

### **Prevention and Remediation**
1. **Incorporate Security in Design**:
   - Use **threat modeling** to predict potential attack vectors and build defenses.
   - Example: During design, simulate a "man-in-the-middle attack" and plan secure communication channels like TLS.

2. **Adopt Secure by Design Principles**:
   - Leverage principles such as **least privilege**, **secure defaults**, and **defense in depth**.
   - Example: Restrict users to only the permissions required for their roles.

3. **Risk Profiling**:
   - Perform a **business risk assessment** to ensure security levels match the risk exposure of the system.
   - Example: For high-value transactions, design for stronger controls such as biometric verification.

4. **Leverage Security Design Frameworks**:
   - Use established patterns like **zero-trust architectures** or secure software development lifecycle (SDLC) practices.
   - Example: Employ security-focused design templates for cloud-based systems.

---

### **Examples of Insecure Design**
1. Designing a web application that does not plan for **session expiration**, allowing attackers to hijack idle sessions.
2. Creating a financial system without **fraud detection mechanisms**, exposing the system to repeated unauthorized transactions.
3. Failing to encrypt sensitive data like user credentials during the design of a storage system.

**Key Insight**: Addressing **Insecure Design** requires organizations to focus on security early in the development lifecycle and continuously integrate security considerations into the architectural process.

### Final Notes
Insecure design vulnerabilities are harder to mitigate post-implementation. By embedding security early in the software development lifecycle, organizations can significantly lower the risks and costs associated with these flaws.
### **Examples of Insecure Design with Detailed Explanations**

---

### **Example 1: Lack of Session Expiration**

#### Scenario:
- A web application for online shopping allows users to log in and shop without properly managing **session expiration**.
- Once a user logs in, their session token remains valid indefinitely until they explicitly log out.

#### Issue:
- **Insecure Design**: The system was designed without considering scenarios where session tokens could be misused if the user closes the browser without logging out.
- Attackers could obtain session tokens (via session fixation, network sniffing, or browser exploits) and use them to impersonate the user.

#### Consequences:
- Unauthorized access to accounts, leading to financial theft, personal data exposure, or fraudulent orders.

#### Prevention:
1. During the design phase, implement a session expiration mechanism:
   - Session tokens should expire after a period of inactivity (e.g., 15 minutes).
   - Use sliding expiration to extend the session for active users.
2. Include session invalidation during logout or when a token is refreshed.

#### Outcome of Secure Design:
- Even if an attacker obtains a session token, it would expire within a short window, reducing the risk of misuse.

---

### **Example 2: Missing Multi-Factor Authentication (MFA)**

#### Scenario:
- A banking application requires only a username and password for login. No additional layer of authentication (e.g., MFA) is implemented.

#### Issue:
- **Insecure Design**: The system design fails to account for the high risks associated with banking systems, such as credential theft.
- A phishing attack could trick users into sharing their login details, allowing attackers to access their accounts.

#### Consequences:
- Unauthorized access to sensitive information and the ability to transfer funds, leading to financial loss and reputational damage.

#### Prevention:
1. During the design phase, integrate **MFA**:
   - Add an additional layer, such as one-time passwords (OTPs) sent via SMS/email or authenticator apps.
   - Use biometric verification for mobile users (e.g., fingerprint or facial recognition).
2. Ensure MFA is required for sensitive actions like adding a new payee or transferring large sums.

#### Outcome of Secure Design:
- Even if an attacker obtains the username and password, the lack of access to the second authentication factor prevents unauthorized access.

---

### **Example 3: Poor Role-Based Access Control (RBAC)**

#### Scenario:
- An enterprise management system provides access to various functionalities (e.g., viewing reports, managing users, and altering financial records).
- All employees, including junior staff, have equal access rights because the system was not designed with granular roles.

#### Issue:
- **Insecure Design**: The system doesn’t enforce the principle of **least privilege**, where users are granted only the minimum access necessary to perform their duties.
- A junior employee could accidentally or maliciously alter financial records, leading to compliance violations or fraud.

#### Consequences:
- Unauthorized access to sensitive operations, accidental data corruption, or deliberate sabotage.

#### Prevention:
1. During the design phase, define clear user roles and their permissions:
   - Example roles: **Admin**, **Manager**, and **Employee**.
   - Admins manage users and configurations; Managers view reports; Employees access their specific tasks.
2. Incorporate role-based access checks at every functionality level.

#### Outcome of Secure Design:
- Employees are limited to their assigned functionalities, reducing the risk of misuse or accidents.

---

### **Example 4: Unencrypted Sensitive Data**

#### Scenario:
- A healthcare system stores patient records, including personal details and medical history, in a database. The system design doesn’t include encryption for stored data.

#### Issue:
- **Insecure Design**: Data is stored in plain text, making it vulnerable to unauthorized access if the database is breached.
- Attackers gaining access to the database can view and misuse sensitive patient information.

#### Consequences:
- Violations of data privacy laws like HIPAA, fines, lawsuits, and reputational damage.

#### Prevention:
1. During the design phase, implement **encryption for sensitive data at rest**:
   - Use strong encryption algorithms like AES-256.
   - Protect encryption keys using secure key management techniques.
2. Enforce **data masking** for non-essential users to reduce unnecessary exposure.

#### Outcome of Secure Design:
- Even if attackers breach the database, encrypted data is unreadable without decryption keys, reducing the risk of sensitive data exposure.

---

### **Example 5: No Rate Limiting on Login Attempts**

#### Scenario:
- An e-commerce platform allows users to log in without any restrictions on the number of failed login attempts.

#### Issue:
- **Insecure Design**: The system fails to mitigate brute force attacks where an attacker repeatedly attempts password guesses.
- An attacker could programmatically try thousands of passwords until they gain access to an account.

#### Consequences:
- Accounts get compromised, leading to fraud, identity theft, and loss of customer trust.

#### Prevention:
1. During the design phase, incorporate rate limiting:
   - Allow only a certain number of failed attempts (e.g., 5) within a specific time frame.
   - Lock the account temporarily or require CAPTCHA after multiple failed attempts.
2. Log and monitor suspicious login attempts for further investigation.

#### Outcome of Secure Design:
- Brute force attempts are thwarted as attackers are locked out after a few failed attempts.

---

### **Example 6: Lack of Secure Default Settings**

#### Scenario:
- A cloud-based document-sharing application is launched with all documents publicly accessible by default.

#### Issue:
- **Insecure Design**: The default settings do not prioritize security. Users might unknowingly expose sensitive documents.
- Attackers could easily search and access public documents using automated tools.

#### Consequences:
- Leakage of intellectual property, sensitive business documents, and customer data.

#### Prevention:
1. During the design phase, configure **secure defaults**:
   - Set documents to private by default.
   - Require explicit user action to make documents public.
2. Provide clear user notifications about the implications of changing default settings.

#### Outcome of Secure Design:
- Sensitive documents remain private unless explicitly shared, reducing accidental data leaks.

---

### **Key Takeaway**:
**Insecure design flaws arise from poor planning and inadequate security measures during the design phase. To prevent these issues, it’s crucial to integrate security considerations early in the software development lifecycle (SDLC), using strategies like threat modeling, secure patterns, and adhering to established security principles.**

### **Requirements and Resource Management**

Effective requirements and resource management is critical to ensure the security, functionality, and sustainability of an application. Below is a breakdown of the key activities involved:

---

### **1. Collecting and Negotiating Business Requirements**

#### **Purpose:**
- Understand the application’s purpose, its interaction with users, and the business’s goals.
- Identify the **security protection requirements** such as:
  - **Confidentiality**: Protecting sensitive data from unauthorized access.
  - **Integrity**: Ensuring data is not altered or tampered with.
  - **Availability**: Ensuring the application is accessible as needed.
  - **Authenticity**: Verifying the legitimacy of users and data sources.

#### **Steps:**
1. Collaborate with stakeholders to identify the core functionality of the application.
2. Highlight sensitive data assets and their protection needs.
3. Identify expected **business logic**, ensuring it aligns with regulatory and compliance standards.
4. Assess the level of exposure of the application:
   - Publicly accessible vs. internal use.
   - Risk posed by malicious actors and potential threats.

#### **Example:**
For a banking app:
- **Confidentiality**: Encrypt user credentials and transaction data.
- **Integrity**: Prevent manipulation of account balances during transactions.
- **Availability**: Ensure the system is online 24/7 to handle global users.
- **Authenticity**: Implement strong authentication (e.g., MFA) for user login.

---

### **2. Tenant Segregation and Access Control**

#### **Purpose:**
- If the application is multi-tenant (used by multiple organizations or users), decide whether each tenant’s data must be isolated or if shared access control suffices.

#### **Steps:**
1. Determine whether strict data segregation is necessary based on sensitivity and regulatory requirements.
2. Evaluate the need for logical or physical separation:
   - Logical: Separate databases or schemas for each tenant.
   - Physical: Separate servers or infrastructure for critical tenants.
3. Define access control policies ensuring users only access data relevant to their role and tenant.

#### **Example:**
For a SaaS HR platform:
- Segregate employee records by company (tenant).
- Ensure that an HR manager from Company A cannot view Company B’s records.

---

### **3. Compiling Technical Requirements**

#### **Functional Security Requirements:**
- Authentication: Methods to verify users, e.g., passwords, MFA.
- Authorization: Rules defining who can access or modify specific data or functionalities.
- Data Encryption: Encrypting data in transit and at rest.
- Secure APIs: Protecting APIs with rate limiting, OAuth2, and input validation.

#### **Non-Functional Security Requirements:**
- Performance: Ensure security controls (e.g., encryption) do not degrade performance.
- Scalability: Design security measures that scale with user demand.
- Compliance: Adhere to standards like GDPR, HIPAA, or PCI-DSS.

#### **Example:**
- Encrypt all database transactions using AES-256.
- Ensure API endpoints respond within 200ms even with input validation and token verification.

---

### **4. Planning and Budgeting**

#### **Purpose:**
- Allocate sufficient resources and finances to meet security and functionality goals across all project stages.

#### **Steps:**
1. **Design Phase:**
   - Conduct threat modeling to identify potential risks early.
   - Include architecture reviews for security considerations.

2. **Build Phase:**
   - Invest in secure coding practices and tools like static application security testing (SAST).
   - Train developers in secure coding principles.

3. **Testing Phase:**
   - Allocate budget for penetration testing, code reviews, and automated testing tools (e.g., dynamic application security testing - DAST).
   - Perform security regression testing for every update.

4. **Operational Phase:**
   - Plan for ongoing maintenance, including vulnerability patching and incident response.
   - Allocate resources for logging, monitoring, and SIEM (Security Information and Event Management) tools.

#### **Example:**
- Budget breakdown for a healthcare app:
  - Design: $20,000 for threat modeling and architecture validation.
  - Build: $50,000 for secure coding tools and developer training.
  - Testing: $30,000 for penetration tests and automated security checks.
  - Operations: $25,000 annually for logging, monitoring, and maintenance.

---

### **Key Takeaways**

- **Proactive Management**: Security must be built into the project lifecycle from the start, not retrofitted later.
- **Stakeholder Collaboration**: Work with business, technical, and security teams to ensure all requirements are identified and prioritized.
- **Resource Allocation**: Ensure security measures are adequately funded and planned for every stage of development and operation.

By addressing these factors comprehensively, you can build applications that are robust, secure, and aligned with business and compliance goals.
