"""
Secure Store Interface for Python

This module provides secure storage interfaces for sensitive data like secrets,
certificates, and tokens. Supports multiple backends including Azure KeyVault,
HashiCorp Vault, and local encrypted storage.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional, Any, List, Union
import asyncio


class SecureStoreMode(Enum):
    """Secure store operating modes"""
    MOCK = "mock"
    DEBUG = "debug" 
    REAL = "real"
    AZURE_KEYVAULT = "azure_keyvault"
    HASHICORP_VAULT = "hashicorp_vault"
    LOCAL_ENCRYPTED = "local_encrypted"


class SecretType(Enum):
    """Types of secrets that can be stored"""
    CLIENT_SECRET = "client_secret"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    API_KEY = "api_key"
    CUSTOM = "custom"


@dataclass
class SecureStoreConfig:
    """Configuration for secure store clients"""
    mode: SecureStoreMode = SecureStoreMode.REAL
    vault_url: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    certificate_path: Optional[str] = None
    
    # Local encrypted storage settings
    local_store_path: Optional[str] = None
    encryption_key_path: Optional[str] = None
    
    # Connection settings
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Security settings
    enable_logging: bool = False
    log_secret_access: bool = False  # Should be False in production
    cache_secrets: bool = True
    cache_ttl_seconds: int = 300  # 5 minutes


@dataclass
class SecretMetadata:
    """Metadata for stored secrets"""
    name: str
    secret_type: SecretType
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None
    version: str = "1.0"
    tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}
    
    def is_expired(self) -> bool:
        """Check if secret is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at


@dataclass
class SecretValue:
    """Container for secret values with metadata"""
    value: str
    metadata: SecretMetadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'value': self.value,
            'metadata': {
                'name': self.metadata.name,
                'secret_type': self.metadata.secret_type.value,
                'created_at': self.metadata.created_at.isoformat(),
                'updated_at': self.metadata.updated_at.isoformat(),
                'expires_at': self.metadata.expires_at.isoformat() if self.metadata.expires_at else None,
                'version': self.metadata.version,
                'tags': self.metadata.tags
            }
        }


class SecureStoreResult:
    """Result container for secure store operations"""
    
    def __init__(self, success: bool, value: Optional[SecretValue] = None, 
                 error_code: Optional[str] = None, error_message: Optional[str] = None):
        self.success = success
        self.value = value
        self.error_code = error_code
        self.error_message = error_message
    
    @classmethod
    def success_result(cls, value: SecretValue) -> 'SecureStoreResult':
        """Create success result"""
        return cls(success=True, value=value)
    
    @classmethod
    def error_result(cls, error_code: str, error_message: str) -> 'SecureStoreResult':
        """Create error result"""
        return cls(success=False, error_code=error_code, error_message=error_message)


class SecureStoreInterface(ABC):
    """Abstract interface for secure storage implementations"""
    
    @abstractmethod
    async def store_secret_async(self, name: str, value: str, secret_type: SecretType = SecretType.CUSTOM,
                                expires_at: Optional[datetime] = None, tags: Optional[Dict[str, str]] = None) -> bool:
        """Store a secret asynchronously"""
        pass
    
    @abstractmethod
    def store_secret(self, name: str, value: str, secret_type: SecretType = SecretType.CUSTOM,
                    expires_at: Optional[datetime] = None, tags: Optional[Dict[str, str]] = None) -> bool:
        """Store a secret synchronously"""
        pass
    
    @abstractmethod
    async def get_secret_async(self, name: str) -> SecureStoreResult:
        """Retrieve a secret asynchronously"""
        pass
    
    @abstractmethod
    def get_secret(self, name: str) -> SecureStoreResult:
        """Retrieve a secret synchronously"""
        pass
    
    @abstractmethod
    async def delete_secret_async(self, name: str) -> bool:
        """Delete a secret asynchronously"""
        pass
    
    @abstractmethod
    def delete_secret(self, name: str) -> bool:
        """Delete a secret synchronously"""
        pass
    
    @abstractmethod
    async def list_secrets_async(self, secret_type: Optional[SecretType] = None) -> List[SecretMetadata]:
        """List all secrets asynchronously"""
        pass
    
    @abstractmethod
    def list_secrets(self, secret_type: Optional[SecretType] = None) -> List[SecretMetadata]:
        """List all secrets synchronously"""
        pass
    
    @abstractmethod
    async def secret_exists_async(self, name: str) -> bool:
        """Check if secret exists asynchronously"""
        pass
    
    @abstractmethod
    def secret_exists(self, name: str) -> bool:
        """Check if secret exists synchronously"""
        pass
    
    @abstractmethod
    async def update_secret_async(self, name: str, value: str, tags: Optional[Dict[str, str]] = None) -> bool:
        """Update an existing secret asynchronously"""
        pass
    
    @abstractmethod
    def update_secret(self, name: str, value: str, tags: Optional[Dict[str, str]] = None) -> bool:
        """Update an existing secret synchronously"""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close synchronous resources"""
        pass
    
    @abstractmethod
    async def aclose(self) -> None:
        """Close asynchronous resources"""
        pass


class SecureStoreLogger(ABC):
    """Logger interface for secure store operations"""
    
    @abstractmethod
    def log_info(self, message: str) -> None:
        """Log information message"""
        pass
    
    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""
        pass
    
    @abstractmethod
    def log_debug(self, message: str) -> None:
        """Log debug message"""
        pass
    
    @abstractmethod
    def log_security_event(self, event: str, secret_name: str, operation: str) -> None:
        """Log security-related events"""
        pass


class NullSecureStoreLogger(SecureStoreLogger):
    """No-op logger implementation"""
    
    def log_info(self, message: str) -> None:
        pass
    
    def log_error(self, message: str) -> None:
        pass
    
    def log_debug(self, message: str) -> None:
        pass
    
    def log_security_event(self, event: str, secret_name: str, operation: str) -> None:
        pass


class ConsoleSecureStoreLogger(SecureStoreLogger):
    """Console logger implementation"""
    
    def __init__(self, prefix: str = "SecureStore"):
        self.prefix = prefix
    
    def log_info(self, message: str) -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] INFO: {message}")
    
    def log_error(self, message: str) -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] ERROR: {message}")
    
    def log_debug(self, message: str) -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] DEBUG: {message}")
    
    def log_security_event(self, event: str, secret_name: str, operation: str) -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] SECURITY: {event} - Secret: {secret_name}, Operation: {operation}")
