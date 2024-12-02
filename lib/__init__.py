# File: /stuff/laura/gitlab/infosec_ip_lookup/lib/__init__.py

from .formatters import ResultFormatter

# For backward compatibility
def display_results(results):
    formatter = ResultFormatter()
    formatter.display_results(results)

__all__ = ['ResultFormatter', 'display_results']