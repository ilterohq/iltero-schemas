"""Redaction: what a credential looks like, the policy that says what is hidden, and the function that hides it.

Shared code is in ``common``; what reads one IaC tool's output is in ``iac``. Import each name from the module that
defines it: this package and its folders hold no imports, so ``common.credentials`` loads the standard library only.
"""
