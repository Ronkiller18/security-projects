# Authentication Vulnerability Lab

## Overview

This project is an educational cybersecurity lab demonstrating insecure authentication and authorization patterns commonly found in poorly designed frontend applications.

The lab intentionally contains vulnerable implementations for learning and portfolio demonstration purposes.

---

# Features

* Client-side authentication simulation
* Session fixation vulnerability
* Broken access control
* Privilege escalation
* JWT trust demonstration
* Session expiration simulation
* Password strength analyzer
* Route protection simulation
* Secure vs vulnerable modes
* Role-based access visualization

---

# Vulnerabilities Demonstrated

## Weak Client-Side Authentication

Authentication logic is handled entirely on the frontend and can be bypassed.

## Insecure Session Storage

Authentication state is stored in localStorage and can be modified manually.

## Session Fixation

The application may reuse attacker-controlled session identifiers.

## Broken Access Control

Protected routes can be accessed directly without proper validation.

## Privilege Escalation

User roles stored in localStorage can be manipulated.

## Insecure JWT Trust

JWT payloads are trusted client-side without proper signature validation.

---

# Secure Mitigations

* Regenerate sessions after authentication
* Validate sessions server-side
* Enforce server-side authorization
* Use HttpOnly secure cookies
* Verify JWT signatures
* Implement proper route protection
* Never trust client-controlled storage

---

# Tech Stack

* HTML
* CSS
* JavaScript (ES Modules)
* localStorage
* DOM APIs

---

# Learning Goals

This project was built to:

* Understand authentication vulnerabilities
* Learn session management concepts
* Practice frontend security visualization
* Demonstrate offensive and defensive security concepts
* Build practical cybersecurity portfolio projects

---

# Future Improvements

* Real JWT implementation
* Backend authentication server
* CSRF demonstrations
* Secure cookie simulation
* Refresh token handling
* Role-based dashboard restrictions
* Audit logging
* Session revocation system

---

# Disclaimer

This project intentionally contains insecure patterns for educational purposes only.
Do not use these authentication methods in production applications.