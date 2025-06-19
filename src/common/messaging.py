"""
Unified messaging system for malwi.

This module provides a centralized way to handle all console output and logging
throughout the malwi codebase, ensuring consistent formatting and proper
respect for quiet mode settings.
"""

import sys
import logging

from pathlib import Path
from typing import Optional, Any


class TqdmLoggingHandler(logging.StreamHandler):
    """A logging handler that uses tqdm.write() to avoid interfering with progress bars."""

    def emit(self, record):
        try:
            msg = self.format(record)
            # Try to use tqdm.write() if available, otherwise fall back to standard stream
            try:
                from tqdm import tqdm

                tqdm.write(msg, file=self.stream)
            except ImportError:
                self.stream.write(msg + self.terminator)
                self.flush()
        except Exception:
            self.handleError(record)


class MessageManager:
    """
    Centralized message manager that unifies print() and logging calls.

    Provides consistent formatting and respects quiet mode across the entire application.
    """

    def __init__(self, quiet: bool = False, logger_name: str = "malwi"):
        """
        Initialize the message manager.

        Args:
            quiet: If True, suppresses info and progress messages
            logger_name: Name of the logger to use
        """
        self.quiet = quiet
        self.logger = logging.getLogger(logger_name)

        # Set up logging format if not already configured
        if not self.logger.handlers:
            handler = TqdmLoggingHandler()  # Use default stderr
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        # Adjust log level based on quiet mode
        if quiet:
            self.logger.setLevel(logging.WARNING)
        else:
            self.logger.setLevel(logging.INFO)

    def set_quiet(self, quiet: bool) -> None:
        """Update quiet mode setting."""
        self.quiet = quiet
        if quiet:
            self.logger.setLevel(logging.WARNING)
        else:
            self.logger.setLevel(logging.INFO)

    def info(self, message: str, *args: Any) -> None:
        """Print informational message (respects quiet mode)."""
        if not self.quiet:
            formatted_message = message.format(*args) if args else message
            self.logger.info(formatted_message)

    def success(self, message: str, *args: Any) -> None:
        """Print success message with green indicator (respects quiet mode)."""
        if not self.quiet:
            formatted_message = message.format(*args) if args else message
            self.logger.info(f"🟢 {formatted_message}")

    def warning(self, message: str, *args: Any) -> None:
        """Print warning message (always shown, even in quiet mode)."""
        formatted_message = message.format(*args) if args else message
        self.logger.warning(f"⚠️  Warning: {formatted_message}")

    def error(self, message: str, *args: Any) -> None:
        """Print error message (always shown)."""
        formatted_message = message.format(*args) if args else message
        self.logger.error(f"❌ Error: {formatted_message}")

    def critical(self, message: str, *args: Any) -> None:
        """Print critical error message (always shown)."""
        formatted_message = message.format(*args) if args else message
        self.logger.critical(f"🚨 Critical: {formatted_message}")

    def progress(self, message: str, *args: Any) -> None:
        """Print progress message (respects quiet mode)."""
        if not self.quiet:
            formatted_message = message.format(*args) if args else message
            self.logger.info(f"📈 {formatted_message}")

    def result(self, message: str, *args: Any, force: bool = False) -> None:
        """
        Print result/output message.

        Args:
            message: The message to print
            *args: Arguments for string formatting
            force: If True, prints even in quiet mode (for final results)
        """
        formatted_message = message.format(*args) if args else message
        if force or not self.quiet:
            # Check if tqdm is available and use its write method to avoid interference
            try:
                from tqdm import tqdm

                tqdm.write(formatted_message, file=sys.stdout)
            except ImportError:
                print(formatted_message)

    def banner(self, message: str) -> None:
        """Print banner message (respects quiet mode)."""
        if not self.quiet:
            # Use tqdm.write for banner to maintain proper ordering
            import sys

            try:
                from tqdm import tqdm

                tqdm.write(message, file=sys.stderr)
            except ImportError:
                self.logger.info(message)
            sys.stderr.flush()

    def debug(self, message: str, *args: Any) -> None:
        """Print debug message (only when debug logging is enabled)."""
        formatted_message = message.format(*args) if args else message
        self.logger.debug(formatted_message)

    def file_error(self, file_path: Path, error: Exception, context: str = "") -> None:
        """Print standardized file processing error."""
        context_str = f" ({context})" if context else ""
        self.error(
            f"Failed to process {file_path}{context_str}: {type(error).__name__}: {error}"
        )

    def path_error(self, path: Path, reason: str = "does not exist") -> None:
        """Print standardized path error."""
        self.error(f"Path {reason}: {path}")

    def model_warning(self, model_type: str, error: Exception) -> None:
        """Print standardized model loading warning."""
        self.warning(
            f"Could not initialize {model_type} model: {error}. Functionality will be limited."
        )


# Global message manager instance
_global_manager: Optional[MessageManager] = None


def get_message_manager() -> MessageManager:
    """Get the global message manager instance."""
    global _global_manager
    if _global_manager is None:
        _global_manager = MessageManager()
    return _global_manager


def set_quiet_mode(quiet: bool) -> None:
    """Set quiet mode for the global message manager."""
    get_message_manager().set_quiet(quiet)


def configure_messaging(
    quiet: bool = False, logger_name: str = "malwi"
) -> MessageManager:
    """
    Configure the global messaging system.

    Args:
        quiet: Enable quiet mode
        logger_name: Logger name to use

    Returns:
        The configured MessageManager instance
    """
    global _global_manager
    _global_manager = MessageManager(quiet=quiet, logger_name=logger_name)
    return _global_manager


# Convenience functions that use the global manager
def info(message: str, *args: Any) -> None:
    """Print informational message using global manager."""
    get_message_manager().info(message, *args)


def success(message: str, *args: Any) -> None:
    """Print success message using global manager."""
    get_message_manager().success(message, *args)


def warning(message: str, *args: Any) -> None:
    """Print warning message using global manager."""
    get_message_manager().warning(message, *args)


def error(message: str, *args: Any) -> None:
    """Print error message using global manager."""
    get_message_manager().error(message, *args)


def critical(message: str, *args: Any) -> None:
    """Print critical error message using global manager."""
    get_message_manager().critical(message, *args)


def progress(message: str, *args: Any) -> None:
    """Print progress message using global manager."""
    get_message_manager().progress(message, *args)


def result(message: str, *args: Any, force: bool = False) -> None:
    """Print result message using global manager."""
    get_message_manager().result(message, *args, force=force)


def banner(message: str) -> None:
    """Print banner message using global manager."""
    get_message_manager().banner(message)


def debug(message: str, *args: Any) -> None:
    """Print debug message using global manager."""
    get_message_manager().debug(message, *args)


def file_error(file_path: Path, error: Exception, context: str = "") -> None:
    """Print standardized file processing error using global manager."""
    get_message_manager().file_error(file_path, error, context)


def path_error(path: Path, reason: str = "does not exist") -> None:
    """Print standardized path error using global manager."""
    get_message_manager().path_error(path, reason)


def model_warning(model_type: str, error: Exception) -> None:
    """Print standardized model loading warning using global manager."""
    get_message_manager().model_warning(model_type, error)
