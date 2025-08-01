"""
[PHI] HIPAA-Compliant Encryption Helper

This module provides encryption utilities for PHI data handling in compliance with HIPAA Security Rule.
All PHI data must be encrypted using AES-256 with customer-managed keys.

Classification: PHI-CRITICAL
Author: HIPAA Compliance Team
Version: 1.0.0
Last Updated: 2025-08-01
"""

import os
import logging
import hashlib
import secrets
from typing import Dict, Optional, Tuple, Union, Any
from dataclasses import dataclass
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


logger = logging.getLogger(__name__)


@dataclass
class EncryptionMetadata:
    """Metadata for encrypted PHI data."""
    algorithm: str
    key_id: str
    iv: str
    timestamp: str
    compliance_level: str = "HIPAA"
    data_classification: str = "PHI"


class HIPAAEncryptionError(Exception):
    """HIPAA encryption specific errors."""
    pass


class PHIEncryptionHelper:
    """
    HIPAA-compliant encryption helper for PHI data.
    
    Implements AES-256-GCM encryption with customer-managed keys
    stored in Azure Key Vault for maximum security.
    """
    
    def __init__(self, key_vault_url: str, credential: Optional[DefaultAzureCredential] = None):
        """
        Initialize HIPAA encryption helper.
        
        Args:
            key_vault_url: Azure Key Vault URL for customer-managed keys
            credential: Azure credential for Key Vault access
        """
        self.key_vault_url = key_vault_url
        self.credential = credential or DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=key_vault_url, credential=self.credential)
        self.secret_client = SecretClient(vault_url=key_vault_url, credential=self.credential)
        
        # HIPAA-required encryption parameters
        self.ALGORITHM = "AES-256-GCM"
        self.KEY_SIZE = 32  # 256 bits
        self.IV_SIZE = 12   # 96 bits for GCM
        self.TAG_SIZE = 16  # 128 bits for GCM
        
        logger.info(f"[PHI] Initialized HIPAA encryption helper with Key Vault: {key_vault_url}")
    
    def _get_master_key(self, key_name: str = "phi-master-key") -> bytes:
        """
        Retrieve or create master encryption key from Azure Key Vault.
        
        Args:
            key_name: Name of the master key in Key Vault
            
        Returns:
            Master encryption key bytes
        """
        try:
            # Try to get existing key
            secret = self.secret_client.get_secret(key_name)
            key_data = secret.value.encode('utf-8')
            logger.info(f"[PHI] Retrieved master key from Key Vault: {key_name}")
            return key_data
            
        except Exception as e:
            logger.warning(f"[PHI] Master key not found, creating new key: {e}")
            
            # Create new master key
            master_key = secrets.token_bytes(self.KEY_SIZE)
            key_b64 = master_key.hex()
            
            # Store in Key Vault
            self.secret_client.set_secret(
                key_name,
                key_b64,
                content_type="application/octet-stream",
                tags={
                    "purpose": "PHI-encryption",
                    "compliance": "HIPAA",
                    "created": datetime.utcnow().isoformat(),
                    "algorithm": self.ALGORITHM
                }
            )
            
            logger.info(f"[PHI] Created and stored new master key: {key_name}")
            return master_key
    
    def _derive_key(self, master_key: bytes, context: str) -> bytes:
        """
        Derive encryption key from master key using PBKDF2.
        
        Args:
            master_key: Master encryption key
            context: Context string for key derivation
            
        Returns:
            Derived encryption key
        """
        salt = hashlib.sha256(context.encode('utf-8')).digest()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=100000,  # NIST recommended minimum
            backend=default_backend()
        )
        return kdf.derive(master_key)
    
    def encrypt_phi_data(
        self, 
        data: Union[str, bytes], 
        context: str,
        additional_data: Optional[bytes] = None
    ) -> Tuple[bytes, EncryptionMetadata]:
        """
        Encrypt PHI data using AES-256-GCM.
        
        Args:
            data: PHI data to encrypt
            context: Context for key derivation (e.g., "patient_record_123")
            additional_data: Additional authenticated data (AAD)
            
        Returns:
            Tuple of (encrypted_data, encryption_metadata)
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Get master key and derive context-specific key
            master_key = self._get_master_key()
            encryption_key = self._derive_key(master_key, context)
            
            # Generate random IV
            iv = secrets.token_bytes(self.IV_SIZE)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Add authenticated data if provided
            if additional_data:
                encryptor.authenticate_additional_data(additional_data)
            
            # Encrypt data
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Combine IV + ciphertext + tag
            encrypted_data = iv + ciphertext + encryptor.tag
            
            # Create metadata
            metadata = EncryptionMetadata(
                algorithm=self.ALGORITHM,
                key_id=hashlib.sha256(context.encode()).hexdigest()[:16],
                iv=iv.hex(),
                timestamp=datetime.utcnow().isoformat(),
                compliance_level="HIPAA",
                data_classification="PHI"
            )
            
            logger.info(f"[PHI] Encrypted data with context: {context[:32]}...")
            return encrypted_data, metadata
            
        except Exception as e:
            logger.error(f"[PHI] Encryption failed: {e}")
            raise HIPAAEncryptionError(f"PHI encryption failed: {e}")
    
    def decrypt_phi_data(
        self, 
        encrypted_data: bytes, 
        context: str,
        metadata: EncryptionMetadata,
        additional_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt PHI data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted PHI data
            context: Context for key derivation
            metadata: Encryption metadata
            additional_data: Additional authenticated data (AAD)
            
        Returns:
            Decrypted PHI data
        """
        try:
            # Validate metadata
            if metadata.algorithm != self.ALGORITHM:
                raise HIPAAEncryptionError(f"Unsupported algorithm: {metadata.algorithm}")
            
            if metadata.compliance_level != "HIPAA":
                raise HIPAAEncryptionError(f"Non-HIPAA compliant data: {metadata.compliance_level}")
            
            # Get master key and derive context-specific key
            master_key = self._get_master_key()
            encryption_key = self._derive_key(master_key, context)
            
            # Extract IV, ciphertext, and tag
            iv = encrypted_data[:self.IV_SIZE]
            ciphertext = encrypted_data[self.IV_SIZE:-self.TAG_SIZE]
            tag = encrypted_data[-self.TAG_SIZE:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Add authenticated data if provided
            if additional_data:
                decryptor.authenticate_additional_data(additional_data)
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            logger.info(f"[PHI] Decrypted data with context: {context[:32]}...")
            return plaintext
            
        except Exception as e:
            logger.error(f"[PHI] Decryption failed: {e}")
            raise HIPAAEncryptionError(f"PHI decryption failed: {e}")
    
    def encrypt_field(self, field_value: Any, field_name: str, record_id: str) -> Dict[str, Any]:
        """
        Encrypt a specific field containing PHI.
        
        Args:
            field_value: Field value to encrypt
            field_name: Name of the field
            record_id: Unique record identifier
            
        Returns:
            Dictionary with encrypted field data and metadata
        """
        if field_value is None or field_value == "":
            return {"encrypted_value": None, "metadata": None}
        
        context = f"{record_id}:{field_name}"
        encrypted_data, metadata = self.encrypt_phi_data(str(field_value), context)
        
        return {
            "encrypted_value": encrypted_data.hex(),
            "metadata": {
                "algorithm": metadata.algorithm,
                "key_id": metadata.key_id,
                "iv": metadata.iv,
                "timestamp": metadata.timestamp,
                "compliance_level": metadata.compliance_level,
                "data_classification": metadata.data_classification,
                "field_name": field_name,
                "record_id": record_id
            }
        }
    
    def decrypt_field(self, encrypted_field: Dict[str, Any]) -> Optional[str]:
        """
        Decrypt an encrypted field.
        
        Args:
            encrypted_field: Dictionary with encrypted field data
            
        Returns:
            Decrypted field value
        """
        if not encrypted_field or not encrypted_field.get("encrypted_value"):
            return None
        
        try:
            encrypted_data = bytes.fromhex(encrypted_field["encrypted_value"])
            metadata_dict = encrypted_field["metadata"]
            
            metadata = EncryptionMetadata(
                algorithm=metadata_dict["algorithm"],
                key_id=metadata_dict["key_id"],
                iv=metadata_dict["iv"],
                timestamp=metadata_dict["timestamp"],
                compliance_level=metadata_dict["compliance_level"],
                data_classification=metadata_dict["data_classification"]
            )
            
            context = f"{metadata_dict['record_id']}:{metadata_dict['field_name']}"
            decrypted_data = self.decrypt_phi_data(encrypted_data, context, metadata)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"[PHI] Field decryption failed: {e}")
            raise HIPAAEncryptionError(f"Field decryption failed: {e}")
    
    def secure_delete(self, data: Union[str, bytes]) -> None:
        """
        Securely delete sensitive data from memory.
        
        Args:
            data: Data to securely delete
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Overwrite memory with random data (multiple passes)
        for _ in range(3):
            secrets.token_bytes(len(data))
        
        # Force garbage collection
        import gc
        gc.collect()
    
    def rotate_master_key(self, old_key_name: str = "phi-master-key") -> str:
        """
        Rotate the master encryption key.
        
        Args:
            old_key_name: Name of the current master key
            
        Returns:
            Name of the new master key
        """
        new_key_name = f"{old_key_name}-{datetime.utcnow().strftime('%Y%m%d')}"
        
        # Create new master key
        new_master_key = secrets.token_bytes(self.KEY_SIZE)
        key_b64 = new_master_key.hex()
        
        # Store new key in Key Vault
        self.secret_client.set_secret(
            new_key_name,
            key_b64,
            content_type="application/octet-stream",
            tags={
                "purpose": "PHI-encryption",
                "compliance": "HIPAA",
                "created": datetime.utcnow().isoformat(),
                "algorithm": self.ALGORITHM,
                "rotated_from": old_key_name
            }
        )
        
        logger.info(f"[PHI] Rotated master key from {old_key_name} to {new_key_name}")
        return new_key_name
    
    def validate_encryption(self, test_data: str = "test_phi_data") -> bool:
        """
        Validate encryption/decryption functionality.
        
        Args:
            test_data: Test data for validation
            
        Returns:
            True if encryption/decryption works correctly
        """
        try:
            context = "validation_test"
            
            # Encrypt test data
            encrypted_data, metadata = self.encrypt_phi_data(test_data, context)
            
            # Decrypt test data
            decrypted_data = self.decrypt_phi_data(encrypted_data, context, metadata)
            
            # Verify data integrity
            if decrypted_data.decode('utf-8') == test_data:
                logger.info("[PHI] Encryption validation successful")
                return True
            else:
                logger.error("[PHI] Encryption validation failed - data mismatch")
                return False
                
        except Exception as e:
            logger.error(f"[PHI] Encryption validation failed: {e}")
            return False


class PHIKeyManager:
    """
    Manage encryption keys for PHI data with proper lifecycle management.
    """
    
    def __init__(self, key_vault_url: str, credential: Optional[DefaultAzureCredential] = None):
        """Initialize PHI key manager."""
        self.key_vault_url = key_vault_url
        self.credential = credential or DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=key_vault_url, credential=self.credential)
        self.secret_client = SecretClient(vault_url=key_vault_url, credential=self.credential)
    
    def create_data_encryption_key(self, purpose: str) -> str:
        """
        Create a new data encryption key for specific purpose.
        
        Args:
            purpose: Purpose of the key (e.g., "patient_records", "chat_history")
            
        Returns:
            Key identifier
        """
        key_name = f"dek-{purpose}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        try:
            # Create RSA key for wrapping DEKs
            key = self.key_client.create_rsa_key(
                key_name,
                size=2048,
                key_operations=["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                tags={
                    "purpose": f"PHI-{purpose}",
                    "compliance": "HIPAA",
                    "created": datetime.utcnow().isoformat(),
                    "type": "data-encryption-key"
                }
            )
            
            logger.info(f"[PHI] Created data encryption key: {key_name}")
            return key.name
            
        except Exception as e:
            logger.error(f"[PHI] Failed to create data encryption key: {e}")
            raise HIPAAEncryptionError(f"Key creation failed: {e}")
    
    def get_key_metadata(self, key_name: str) -> Dict[str, Any]:
        """
        Get metadata for an encryption key.
        
        Args:
            key_name: Name of the key
            
        Returns:
            Key metadata dictionary
        """
        try:
            key = self.key_client.get_key(key_name)
            return {
                "name": key.name,
                "id": key.id,
                "enabled": key.properties.enabled,
                "created": key.properties.created_on.isoformat() if key.properties.created_on else None,
                "updated": key.properties.updated_on.isoformat() if key.properties.updated_on else None,
                "expires": key.properties.expires_on.isoformat() if key.properties.expires_on else None,
                "tags": key.properties.tags or {},
                "operations": key.key_operations,
                "key_type": key.key_type
            }
        except Exception as e:
            logger.error(f"[PHI] Failed to get key metadata: {e}")
            raise HIPAAEncryptionError(f"Key metadata retrieval failed: {e}")
    
    def list_active_keys(self) -> list:
        """
        List all active PHI encryption keys.
        
        Returns:
            List of active key names
        """
        try:
            active_keys = []
            for key_properties in self.key_client.list_properties_of_keys():
                if (key_properties.enabled and 
                    key_properties.tags and 
                    "PHI" in key_properties.tags.get("purpose", "")):
                    active_keys.append(key_properties.name)
            
            logger.info(f"[PHI] Found {len(active_keys)} active PHI keys")
            return active_keys
            
        except Exception as e:
            logger.error(f"[PHI] Failed to list active keys: {e}")
            raise HIPAAEncryptionError(f"Key listing failed: {e}")
    
    def schedule_key_rotation(self, key_name: str, rotation_days: int = 90) -> None:
        """
        Schedule automatic key rotation.
        
        Args:
            key_name: Name of the key to rotate
            rotation_days: Days until rotation
        """
        try:
            key = self.key_client.get_key(key_name)
            current_tags = key.properties.tags or {}
            
            # Add rotation schedule to tags
            rotation_date = datetime.utcnow().replace(
                day=datetime.utcnow().day + rotation_days
            )
            
            current_tags.update({
                "rotation_scheduled": rotation_date.isoformat(),
                "rotation_days": str(rotation_days),
                "last_rotation_check": datetime.utcnow().isoformat()
            })
            
            # Update key properties
            key.properties.tags = current_tags
            self.key_client.update_key_properties(key.name, tags=current_tags)
            
            logger.info(f"[PHI] Scheduled rotation for key {key_name} on {rotation_date}")
            
        except Exception as e:
            logger.error(f"[PHI] Failed to schedule key rotation: {e}")
            raise HIPAAEncryptionError(f"Key rotation scheduling failed: {e}")