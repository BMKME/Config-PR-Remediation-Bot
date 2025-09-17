"""
Compliance rules definitions for various standards
"""

from .aws_cis import AWSCISRules
from .nist import NISTRules

__all__ = ['AWSCISRules', 'NISTRules']

