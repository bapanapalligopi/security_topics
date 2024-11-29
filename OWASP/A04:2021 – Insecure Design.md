
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


### **Secure Design**

**Definition:**
Secure design is a proactive approach and methodology for developing applications with robust defenses against known attack methods. It emphasizes continual threat evaluation and integration of security measures from the initial design phase through testing and implementation.

---

### **Key Principles of Secure Design**

1. **Threat Evaluation and Mitigation:**
   - Regularly assess potential threats using **threat modeling**.
   - Identify changes in data flows, access controls, and other security controls to adjust the design.

   **Example:** If a new feature requires sharing user files, analyze how this impacts data flow and apply secure file handling and storage measures (e.g., virus scanning and encryption).

2. **Integration into User Story Development:**
   - Incorporate security into user stories during refinement or planning sessions.
   - Define:
     - **Correct flows:** How data should move and actions should occur in ideal scenarios.
     - **Failure states:** What happens when errors or failures occur.

   **Example:** A user story for a banking app login should:
   - Define the expected process (e.g., validate username/password and implement CAPTCHA after failed attempts).
   - Document failure flows (e.g., lock account after 5 incorrect attempts).

3. **Validation of Assumptions:**
   - Analyze and validate assumptions about how the application will behave.
   - Ensure conditions for proper behavior are explicitly defined and enforced.

   **Example:** If the application assumes all incoming API requests are from authenticated users, implement token-based authentication and validate the token on every request.

4. **Learning from Mistakes:**
   - Review past vulnerabilities and breaches to improve future designs.
   - Create a culture where mistakes are seen as learning opportunities.

   **Example:** If an injection attack was discovered in the previous release, the team should update the design to include parameterized queries and input sanitization for all user inputs.

5. **Documentation of Security in User Stories:**
   - Record security requirements and considerations directly in user stories to ensure they are not overlooked.
   - Clearly document:
     - Expected behaviors.
     - Security controls applied.
     - Failure conditions and their management.

   **Example:**
   - **User Story:** As a user, I want to reset my password securely.
   - **Security Notes:** 
     - Validate email ownership via a one-time token.
     - Ensure tokens expire in 10 minutes.
     - Log all password reset attempts for audit purposes.

---

### **Secure Design is Not an Add-On**

- Secure design must be integrated from the **initial stages** of development.
- It is **not a tool** or feature that can be retrofitted into existing software.
- It requires cultural adoption, continuous refinement, and commitment from all stakeholders.

---

### **Steps to Implement Secure Design**

1. **Adopt a Security-First Culture:**
   - Encourage teams to think about security at every step.
   - Provide training on secure design principles and attack vectors.

2. **Use Threat Modeling Techniques:**
   - Example frameworks: STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
   - Identify weak points in the architecture and address them early.

3. **Build Failure States and Resilience:**
   - Plan for what happens when things go wrong (e.g., a server goes down, credentials are stolen).
   - Implement fallback mechanisms like rate limiting, error logging, and alerting.

4. **Automate Testing and Validation:**
   - Use tools for static code analysis (e.g., SonarQube), dynamic testing, and security scans.
   - Integrate security checks into CI/CD pipelines.

5. **Incentivize Security:**
   - Reward teams for finding and fixing vulnerabilities.
   - Promote learning through workshops and gamified security challenges.

---

### **Example: Secure Design in Practice**

**Scenario:** Building a file upload feature for a healthcare application.

**Correct Flow:**
1. User selects a file to upload.
2. File is scanned for malware.
3. File metadata is validated (e.g., size, type).
4. File is stored in an encrypted format.

**Failure States:**
1. If the file is too large:
   - Reject it and inform the user.
2. If the file contains malware:
   - Reject it and log the incident for investigation.
3. If metadata validation fails:
   - Reject the file with an error message.

**Documented Security Requirements:**
- Only allow specific file types (e.g., .pdf, .jpg).
- Enforce a file size limit of 5MB.
- Encrypt uploaded files with AES-256.
- Log all upload attempts and results.

By incorporating secure design principles, the feature becomes robust against threats like malware injection, excessive resource consumption, and unauthorized access to sensitive files.

---
### **Secure Development Lifecycle (SDLC)**

A **Secure Development Lifecycle** (SDLC) is a structured approach to ensuring that security is considered and integrated at every phase of software development, from the initial design to the final deployment and maintenance. By embedding security practices into the development process, organizations can minimize vulnerabilities, prevent attacks, and ensure software robustness.

---

### **Key Components of Secure Development Lifecycle (SDLC)**

1. **Secure Design Patterns:**
   - Use **design patterns** that have been vetted for security, such as **input validation**, **secure authentication**, and **data encryption**. This helps ensure that security best practices are applied consistently across the software.
   - A **secure design pattern** should address common security concerns like SQL injection, cross-site scripting (XSS), or cross-site request forgery (CSRF).
   - **Example:** Implementing a secure login process using **OAuth** for authentication and **JWT tokens** for session management.

2. **Paved Road Methodology:**
   - The **paved road methodology** ensures that developers follow a well-defined set of **secure paths** and **best practices** for building software.
   - This could involve using secure libraries, adhering to coding standards, and following established development workflows.
   - **Example:** Providing a pre-approved set of secure frameworks and libraries that developers can use, such as a standard encryption library for handling sensitive data.

3. **Secured Component Library:**
   - A **secured component library** contains pre-vetted, secure building blocks (e.g., libraries, frameworks, or services) that are safe to use and well-maintained.
   - These components should undergo rigorous testing for vulnerabilities, and their dependencies must be regularly reviewed and updated.
   - **Example:** Using a cryptography library that has been audited for common vulnerabilities like buffer overflows and side-channel attacks.

4. **Tooling:**
   - Secure development should be supported by **automated tools** that scan code for vulnerabilities, enforce security coding standards, and test for common security flaws.
   - Common tools include **static analysis tools** (e.g., SonarQube), **dynamic analysis tools** (e.g., OWASP ZAP), and **dependency scanning tools** (e.g., Snyk, OWASP Dependency-Check).
   - **Example:** Using an **automated static code analysis tool** that scans for issues like hardcoded credentials or improper access control.

5. **Threat Modeling:**
   - **Threat modeling** should be an integral part of the SDLC, where potential threats are identified early in the development process. This helps in understanding the risks associated with design and implementation choices.
   - A threat modeling exercise identifies threats, attacks, and vulnerabilities, allowing development teams to design mitigations or controls proactively.
   - **Example:** During the design phase, developers conduct a threat modeling session to identify how attackers could exploit data flows, such as using man-in-the-middle attacks or data leakage due to improper access control.

---

### **Incorporating Security Throughout the SDLC**

1. **Planning Phase:**
   - In the planning phase, identify security requirements along with functional ones. Include business risks, compliance standards, and confidentiality concerns.
   - **Example:** Incorporating privacy requirements for GDPR compliance or ensuring the system has logging for auditing purposes.

2. **Design Phase:**
   - **Security by design** means addressing security concerns early in the design process. This includes conducting threat modeling and defining controls (e.g., data encryption, user authentication) based on potential risks.
   - **Example:** Design data access flows ensuring that sensitive data is always encrypted in transit and at rest.

3. **Development Phase:**
   - Developers should write code that follows secure coding practices and make use of the secured component library. This phase should involve automated security checks (e.g., static code analysis tools).
   - **Example:** Using **parameterized queries** to prevent SQL injection vulnerabilities.

4. **Testing Phase:**
   - Security testing should be an integral part of the testing process. This involves vulnerability scanning, penetration testing, and reviewing code for common vulnerabilities (e.g., cross-site scripting, privilege escalation).
   - **Example:** Performing **dynamic testing** using tools like **OWASP ZAP** to check for common vulnerabilities like XSS or insecure API calls.

5. **Deployment Phase:**
   - Ensure secure deployment practices, including securing configuration files, hardening servers, and using appropriate access control mechanisms. Continuous integration/continuous deployment (CI/CD) pipelines should also have security gates.
   - **Example:** Ensure that the application is deployed with HTTPS enabled and that any default credentials are changed.

6. **Maintenance Phase:**
   - Regularly update the software to address new vulnerabilities and incorporate security patches. This phase should also involve monitoring and logging to detect anomalies or security incidents.
   - **Example:** Regularly patch the system’s underlying OS and libraries for vulnerabilities and conduct periodic security audits.

---

### **Leveraging OWASP Software Assurance Maturity Model (SAMM)**

The **OWASP Software Assurance Maturity Model (SAMM)** is a framework that helps organizations assess their **software assurance** and security maturity level. SAMM can guide teams in evaluating their current processes and identifying areas for improvement across the SDLC.

- **Key benefits of SAMM:**
  - Provides a **structured approach** to secure software development.
  - Helps organizations assess their current security practices and maturity.
  - Offers actionable recommendations to enhance security practices over time.
  - Aligns with industry standards and security controls.

**Example:** By using SAMM, an organization may assess its current maturity level in secure coding practices, threat modeling, and security testing. SAMM could highlight gaps in their SDLC, such as the lack of regular security training for developers or the absence of threat modeling during the design phase. The organization can then create a roadmap to implement best practices like regular code reviews or integrating automated security testing into the CI/CD pipeline.

---

### **Conclusion**

A **Secure Development Lifecycle (SDLC)** is essential for building secure software that can withstand evolving threats. By incorporating practices like secure design patterns, threat modeling, and security tooling, and following structured frameworks like **OWASP SAMM**, organizations can ensure that security is an integral part of their development process. Engaging security specialists from the beginning of the project and continuing to involve them throughout the lifecycle of the software is crucial to minimizing vulnerabilities and building resilient systems.
### **Conclusion**

Secure design ensures applications are built with security as a foundation, not an afterthought. By integrating threat modeling, failure analysis, and secure practices into the development process, organizations can reduce vulnerabilities and create trustworthy software.
### **How to Prevent Insecure Design in Software Development**

Preventing insecure design requires a proactive approach to security and privacy from the very beginning of the software development process. By implementing secure design practices, leveraging security tools, and following secure development lifecycles, organizations can create robust software that is resilient to common vulnerabilities.

Here’s a breakdown of how to prevent insecure design with practical steps:

---

### 1. **Establish and Use a Secure Development Lifecycle (SDLC) with AppSec Professionals**

- **What it involves:** Integrating application security (AppSec) professionals into your development lifecycle is critical. These experts will help evaluate, design, and implement security and privacy controls throughout the project.
  
- **How to do it:**
  - **Collaborate early and often** with security professionals throughout all stages of development.
  - **Conduct regular security reviews** during design and implementation phases to identify potential vulnerabilities and mitigate risks before they become issues.
  - **Incorporate secure coding practices** like input validation, secure authentication, and using encryption for sensitive data.
  - Use established **security frameworks and best practices** for secure design (e.g., **OWASP Top 10**, **NIST SP 800-53**, etc.).

- **Example:** During the planning phase, consult AppSec specialists to determine the security controls required for different components of the application, such as authentication mechanisms, encryption protocols, or data storage protections.

---

### 2. **Establish and Use a Library of Secure Design Patterns or Paved Road Ready-to-Use Components**

- **What it involves:** Create and maintain a library of **pre-approved secure components** and **design patterns**. This helps standardize secure practices and ensures that developers are using secure, tested components.

- **How to do it:**
  - Establish a library of **secure design patterns** for common security problems (e.g., input validation, proper session management, secure APIs).
  - Use **well-vetted libraries** and **secure frameworks** that are continuously updated and reviewed for vulnerabilities.
  - Encourage developers to **reuse components** from the library to avoid reinventing the wheel and making common security mistakes.

- **Example:** Develop a **secure authentication pattern** (e.g., using OAuth2.0 or JWT for authorization) that can be reused across multiple applications or services within your organization.

---

### 3. **Use Threat Modeling for Critical Authentication, Access Control, Business Logic, and Key Flows**

- **What it involves:** **Threat modeling** helps identify potential security risks early in the development process. Focus on critical aspects like **authentication**, **access control**, **business logic**, and other key flows to evaluate possible attack vectors and mitigate them.

- **How to do it:**
  - **Identify critical flows**: Pinpoint critical business logic (e.g., payment processing) and user access flows (e.g., login, account management) for each application tier.
  - **Model threats**: Use tools like **STRIDE** or **PASTA** to assess potential threats such as unauthorized access, privilege escalation, data leakage, and others.
  - **Mitigate risks**: For each identified threat, plan mitigations like **strong encryption**, **multi-factor authentication (MFA)**, and **least privilege access**.

- **Example:** During threat modeling, identify that a failure to encrypt user credentials could allow attackers to intercept and use them. As a result, the team decides to enforce **end-to-end encryption** for all data exchanges involving sensitive information.

---

### 4. **Integrate Security Language and Controls into User Stories**

- **What it involves:** Incorporating security requirements directly into **user stories** ensures that security concerns are addressed as part of the functionality being developed.

- **How to do it:**
  - **Integrate security acceptance criteria** into user stories. For example, a user story for logging in could include a requirement to use **MFA** and **limit brute force attempts**.
  - **Collaborate with stakeholders** to ensure that security is aligned with business needs.
  - **Educate developers** on security requirements for the user stories they are implementing.

- **Example:** A user story about **password reset** might include security requirements such as ensuring that **passwords are hashed** and **secure communication channels (SSL/TLS)** are used to send reset links.

---

### 5. **Integrate Plausibility Checks at Each Tier of Your Application**

- **What it involves:** **Plausibility checks** are used to ensure that data flowing through each application tier is valid, expected, and secure. This applies to both frontend (client-side) and backend (server-side) components.

- **How to do it:**
  - Validate **user inputs** on both the client and server sides to ensure they conform to expected formats (e.g., proper email format, no special characters that could lead to SQL injection).
  - Check that data flows between tiers are consistent with **business logic** and don’t reveal sensitive information.
  - **Implement strict validation** for both expected and **unexpected inputs** to prevent exploitation.

- **Example:** On the frontend, validate that user inputs, such as email addresses, conform to the correct format. On the backend, check that all input data is sanitized before querying the database.

---

### 6. **Write Unit and Integration Tests to Validate Critical Flows Against the Threat Model**

- **What it involves:** **Unit tests** and **integration tests** should be written to ensure that critical application flows are secure and resistant to known threats.

- **How to do it:**
  - Write **unit tests** for key components to ensure proper data handling and processing.
  - Create **integration tests** to validate interactions between different tiers of the application (e.g., frontend, API, database) under various attack scenarios (e.g., SQL injection, cross-site scripting).
  - Ensure that **threat model assumptions** are tested, particularly those related to security, such as **user authentication** and **data confidentiality**.

- **Example:** Write a test for a user login flow that checks whether invalid login attempts are appropriately blocked after a set number of retries (defending against brute force attacks).

---

### 7. **Segregate Tier Layers on the System and Network Layers Depending on Exposure and Protection Needs**

- **What it involves:** **Segregating system and network layers** ensures that sensitive components are protected and isolated from lower-risk areas.

- **How to do it:**
  - **Separate critical components** (e.g., databases, authentication systems) from less sensitive components using network segmentation or virtual private networks (VPNs).
  - Use **firewalls**, **network access controls**, and **microservices** to ensure that only authorized traffic can access sensitive parts of your application.

- **Example:** Place the **database** in a private subnet, accessible only by backend services, and expose only the API layer to the public network.

---

### 8. **Segregate Tenants Robustly by Design Throughout All Tiers**

- **What it involves:** **Tenant segregation** ensures that data and logic for different users or organizations (tenants) are securely isolated from one another.

- **How to do it:**
  - Use **role-based access control (RBAC)** to enforce proper separation of tenants.
  - Ensure that each tenant's data is isolated at both the application layer (e.g., separate databases or schemas) and the infrastructure layer (e.g., separate network segments).
  - Implement **multi-tenancy architecture** that is designed with isolation in mind.

- **Example:** For a SaaS platform, ensure that data from different customers (tenants) is stored in separate databases or at least different schemas, so that data leakage between tenants is prevented.

---

### 9. **Limit Resource Consumption by User or Service**

- **What it involves:** To prevent **denial-of-service (DoS)** attacks and abuse, limit the resources (CPU, memory, bandwidth, etc.) a single user or service can consume.

- **How to do it:**
  - Use **rate limiting** and **throttling** to limit the number of requests a user or service can make in a given period.
  - Implement **resource quotas** to restrict the amount of resources each user or service can consume.
  - Use **load balancing** to distribute traffic evenly and avoid overloading any single resource.

- **Example:** Implement an API rate limit that restricts users to 100 requests per minute to prevent a DoS attack.

---

### **Conclusion**

By implementing the above practices, you can proactively reduce the risk of insecure design in your applications. The key is to integrate security throughout the software development lifecycle, leveraging secure design patterns, threat modeling, secure coding practices, and security testing at every stage. Secure design should not be an afterthought, but a core part of your development process, ensuring that applications are both functional and secure from the outset.
### **Example Attack Scenarios: Insecure Design and Flaws**

#### **Scenario #1: Insecure Credential Recovery Process**
**Description:**
A typical example of insecure design in credential recovery involves the use of **security questions and answers**. While they may seem convenient for verifying a user’s identity, they are **easily guessable or discoverable**. Often, users’ answers to common security questions (e.g., "What is your mother’s maiden name?") can be found through social engineering, public information, or simple guessing.

**Vulnerability:**
This practice violates several industry standards and guidelines, including **NIST 800-63b** (Digital Identity Guidelines) and the **OWASP ASVS** (Application Security Verification Standard). The core issue is that such questions cannot be relied upon as trustworthy indicators of identity because answers to security questions are often **predictable** or **publicly accessible** (e.g., via social media profiles).

**How This Could Be Exploited:**
An attacker can attempt to compromise an account by answering security questions, potentially using information gathered from public sources (e.g., a user’s social media). If an attacker gains access to the user’s account, they can potentially change sensitive details, such as the password, and access confidential information.

**Mitigation:**
- **Remove security questions** entirely and replace them with more secure authentication mechanisms such as **multi-factor authentication (MFA)**, where something the user knows (e.g., a password) is combined with something the user has (e.g., a phone for OTP or a hardware token).
- **Use email or SMS-based password recovery** instead of relying on user knowledge-based answers.

---

#### **Scenario #2: Exploiting Group Booking Discounts and Deposit Requirement**
**Description:**
Imagine a cinema chain offers **group booking discounts** where customers booking more than fifteen seats are required to pay a deposit. The business logic of this system is intended to prevent large-scale abuse by requiring deposits when booking large quantities of tickets. However, the system does not account for multiple simultaneous requests or attacks targeting the booking flow.

**Vulnerability:**
Attackers could **threat model** this flow and attempt to book hundreds or even thousands of seats across multiple cinemas using a few fast and coordinated requests. The vulnerability arises from the system **not enforcing proper checks** on the volume of bookings, especially when the threshold for deposit triggering is bypassed.

**How This Could Be Exploited:**
An attacker might send multiple booking requests, bypassing the deposit requirement by splitting the booking into several requests of 15 seats or fewer. By doing so, they could effectively book hundreds of tickets without triggering any preventive checks (like deposit requirements), resulting in significant financial loss for the cinema chain.

**Mitigation:**
- Implement **rate limiting** and **transaction throttling** to prevent bulk booking by a single user or entity.
- Integrate **business logic checks** that analyze the booking pattern, such as monitoring for rapid and repeated bookings from the same user or IP address.
- Add **fraud detection mechanisms** that check for abnormal booking behavior (e.g., unusually high numbers of tickets bought in a short period) and flag these transactions for review.

---

#### **Scenario #3: Scalper Bot Attacks on E-commerce Website**
**Description:**
A retail chain’s e-commerce website is plagued by **scalper bots**. These bots are used by attackers to rapidly purchase high-demand products, such as high-end video cards, in bulk. The attackers then resell these items on auction sites at a higher price, taking advantage of the limited availability and demand. This leads to **disgruntled customers** and **negative publicity** for the retailer.

**Vulnerability:**
In this case, the e-commerce website does not have **bot protection mechanisms** in place. Scalpers use automated tools to bypass purchase limits, defeat CAPTCHA tests, and complete transactions far faster than human users could. Without proper **anti-bot measures**, such as rate limiting or behavioral analysis, the retailer is unable to protect its inventory from being hijacked by bots.

**How This Could Be Exploited:**
- **Scalper bots** could continuously monitor product availability, automatically completing purchases as soon as high-demand products like video cards are released.
- This results in **rapid inventory depletion**, leaving legitimate customers unable to purchase the items they need.
- The high-demand products are then resold at inflated prices, negatively affecting both the brand's reputation and customer trust.

**Mitigation:**
- Implement **bot detection systems** that use techniques such as **behavioral analysis**, where actions like mouse movements, click patterns, and page interactions are analyzed to distinguish between bots and human users.
- Introduce **rate limiting** to prevent excessive requests from the same user or IP address in a short time frame.
- Apply **CAPTCHA** or other challenge-response tests (e.g., **JavaScript fingerprinting**) to verify that users are human.
- **Introduce purchase limits** for high-demand items (e.g., a maximum of 1 or 2 per customer).
- Use **machine learning algorithms** to detect and block unusual buying patterns or transactions made in seconds.
  
---

### **Conclusion**
Each of the attack scenarios highlighted here represents a **design flaw** that makes the system vulnerable to exploitation. While secure coding and implementation are essential, the foundation for preventing many of these attacks starts in the **design phase**. To prevent such vulnerabilities:

- **Early threat modeling** should be integrated into the development lifecycle to assess and mitigate risks before they can be exploited.
- **Security controls** like rate limiting, CAPTCHA, and fraud detection should be part of the design from the beginning, not bolted on later.
- Regular review and updates to the **business logic** and **security controls** will help identify potential attack vectors before they are exploited.

By focusing on secure design practices, businesses can significantly reduce the likelihood of these types of attack scenarios and build applications that are resilient against common security threats.
