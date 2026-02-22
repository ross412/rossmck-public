# API Code

The backend of this project is built on 5 FastAPI microservices. The identity service handles authentication and user management. The bucket service handles encrypted file transfers. The signing service and verification service handle cryptographic operations. The admin service provides a management dashboard. All services share a common database layer, JWT session auth, and an audit trail.

## Identity API

The identity service is the entry point for all users. It handles OIDC login, session management, MFA, and key registration.

1. OIDC callback exchanges the provider code for user info, creates a session, and issues a single use auth code instead of putting the JWT in the URL.

```
@app.get("/auth/oidc/{provider}/callback")
async def oidc_callback(request: Request, provider: str, db: Session = Depends(get_db)):
    """Handle OIDC callback: exchange code, create/find user, issue JWT."""
    userinfo = await exchange_code_for_userinfo(
        provider=provider, client_id=client_id, client_secret=client_secret,
        redirect_uri=redirect_uri,
        authorization_response_url=str(request.url),
    )

    user = get_or_create_oidc_user(
        db=db, oidc_provider=userinfo.provider, oidc_subject=userinfo.subject,
        email=userinfo.email, username=userinfo.name, admin_emails=admin_list,
    )

    session_id, token = create_session(
        db=db, user_id=user.user_id, jwt_secret=settings.jwt_secret,
        ip_address=get_client_ip(request), role=user.role,
    )

    # Store session data under a short lived auth code (JWT never in URL)
    code = _store_auth_code({
        "token": token, "user_id": user.user_id,
        "username": user.username, "email": user.email or "", "role": user.role,
    })
    response = RedirectResponse(url=f"{settings.frontend_url}/app?code={code}")
```

2. Session based JWT validation. Every API request validates the JWT signature, checks expiry, and confirms the session hasn't been revoked in the database.

```
def validate_jwt(token: str, jwt_secret: str, db: DBSession) -> dict | None:
    """Validate JWT: signature, expiry, and session not revoked."""
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    session_id = payload.get("sid")
    user_id = payload.get("sub")
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    session = db.query(Session).filter(
        Session.session_id == session_id,
        Session.token_hash == token_hash,
        Session.revoked_at.is_(None),
    ).first()

    if not session:
        return None

    return {
        "user_id": session.user_id,
        "session_id": session.session_id,
        "role": payload.get("role", "user"),
        "mfa_verified": session.mfa_verified,
    }
```

3. TOTP MFA verification with brute force lockout. Failed attempts are tracked per user and the account locks after too many failures.

```
async def mfa_verify(request: Request, body: MFAVerifyRequest, db: Session = Depends(get_db)):
    # Check lockout
    if user.mfa_locked_until:
        if user.mfa_locked_until > datetime.now(UTC):
            return _error(429, "Account locked due to too many failed attempts.")
        user.mfa_failed_attempts = 0
        user.mfa_locked_until = None

    # Decrypt TOTP secret (Fernet) and verify code
    secret = decrypt_secret(user.mfa_secret_encrypted, settings.mfa_encryption_key)
    if not verify_totp_code(secret, body.code):
        user.mfa_failed_attempts += 1
        if user.mfa_failed_attempts >= settings.mfa_max_attempts:
            user.mfa_locked_until = datetime.now(UTC) + timedelta(
                minutes=settings.mfa_lockout_minutes
            )
        db.commit()
        return MFAVerifyResponse(
            verified=False,
            message=f"Invalid code. {remaining} attempts remaining.",
        )

    # Valid — reset lockout, mark session as MFA verified
    user.mfa_failed_attempts = 0
    session.mfa_verified = True
    session.mfa_verified_at = datetime.now(UTC)
    db.commit()
```

## Bucket API

The bucket service handles encrypted file transfers. Files are encrypted client side before upload so the server never sees plaintext. It also has the largest attack surface as it supports file uploads. To combat this, upload routes must include strict data validation.

1. Set limits on file size, name and type.

```
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024
MAX_FILENAME_LENGTH = 255
SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]")

ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "text/plain",
    "image/png",
    "image/jpeg",
}

MAGIC_BYTES = {
    "application/pdf": b"%PDF",
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
}

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}
```

2. Validate the upload by checking input values against limits. Checks file size in bytes and the content type. Content type is validated with magic bytes.

```
def validate_upload(
    content: bytes,
    content_type: Optional[str],
) -> Optional[Tuple[int, str, str]]:
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        return (
            413,
            ErrorCodes.PAYLOAD_TOO_LARGE,
            f"File too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB",
        )

    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        allowed = ", ".join(sorted(ALLOWED_CONTENT_TYPES))
        return (
            ...
        )

    expected_magic = MAGIC_BYTES.get(content_type)
    if expected_magic and not content.startswith(expected_magic):
        return (
            ...
        )
    if content_type == "text/plain":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return (
                ...
            )
        if b"\x00" in content:
            return (
                ...
            )
    return None
```

3. Check filename isn't maliciously hiding extensions, for example test.exe.png, which becomes test_exe.png

```
def sanitize_filename(filename: str) -> str:
    sanitized = SAFE_FILENAME_RE.sub("_", filename)
    parts = sanitized.rsplit(".", 1)
    if len(parts) == 2:
        stem, ext = parts
        ext = f".{ext.lower()}"
        stem = stem.replace(".", "_")
        if ext not in ALLOWED_EXTENSIONS:
            ext = ""
        sanitized = f"{stem}{ext}"
    sanitized = sanitized[:MAX_FILENAME_LENGTH]
    return sanitized if sanitized else "document"
```

4. Claiming a bucket. Only the designated recipient can claim. Validates ownership, checks expiry, and returns the encrypted file along with the sealed key and sender signature for client side decryption.

```
@app.post("/buckets/{bucket_id}/claim", response_model=BucketClaimResponse)
async def claim_bucket(request: Request, bucket_id: str, db: Session = Depends(get_db)):
    if bucket.recipient_user_id != user.user_id:
        return _error(403, "Only the designated recipient can claim this bucket")
    if _check_expired(bucket, db):
        return _error(410, "This bucket has expired")
    if bucket.status not in ("pending",):
        return _error(400, f"Bucket cannot be claimed (status: {bucket.status})")

    file_content = await storage.download(bucket.storage_key)
    sender_key = db.query(UserKey).filter(UserKey.key_id == bucket.sender_key_id).first()

    bucket.status = "claimed"
    bucket.claimed_at = datetime.now(UTC)
    record_event(db, "bucket_claimed", {"bucket_id": bucket_id}, ...)

    return BucketClaimResponse(
        encrypted_bucket_key=bucket.encrypted_bucket_key,    # sealed box for recipient
        sender_signature=bucket.sender_signature,             # Ed25519 sig of plaintext hash
        sender_public_key_b64=sender_key.public_key_b64,     # for client side verification
        plaintext_sha256=bucket.plaintext_sha256,             # expected hash after decryption
        encrypted_file_b64=base64.urlsafe_b64encode(file_content).decode().rstrip("="),
    )
```

## Signing API

The signing service encrypts the uploaded file hash using ED25519 algorithm. Encryption and hashing are the most important features of this service.

1. Signing the hash of the document passed from the bucket service using Python's cryptography library.

```
def sign_hash(sha256_hex: str, document_id: str, user_id: Optional[str] = None) -> Tuple[str, str, str]:
    private_key, key_id = get_private_key(user_id)

    hash_bytes = bytes.fromhex(sha256_hex)
    signature = private_key.sign(hash_bytes)
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    key_manager = get_key_manager()
    signature_id = key_manager.record_signature(
        document_id=document_id,
        user_id=user_id,
        key_id=key_id,
        signature=signature_b64,
        metadata=f'{{"sha256": "{sha256_hex}"}}'
    )

    logger.info(
        f"Created signature: {signature_id[:8]}... for hash: {sha256_hex[:16]}... (user: {user_id if user_id else 'system'})"
    )

    return signature_id, signature_b64, key_id
```

## Verification API

The verification service is the simplest of the services as it is read only. Its only function is to load keys and verify signatures.

1. Verify the signature by loading public key and using Python's cryptography library.

```
def verify_signature(
    sha256_hex: str,
    signature_b64: str,
    key_id: str
) -> Tuple[bool, bool, str, Optional[datetime]]:
    key_manager = get_key_manager()
    key_info = key_manager.get_signing_key_by_id(key_id)

    if key_info is None:
        logger.warning(f"Unknown key_id: {key_id}")
        return False, False, f"Unknown key_id: {key_id}", None

    public_key = get_public_key(key_id)
    if public_key is None:
        ...

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        return False, False, "Invalid signature format: not valid base64", None

    try:
        hash_bytes = bytes.fromhex(sha256_hex)
    except ValueError:
        return False, False, "Invalid SHA-256 hash: not valid hex", None

    try:
        public_key.verify(signature, hash_bytes)
        crypto_valid = True
    except InvalidSignature:
        return False, False, "Signature verification failed: signature does not match", None

    is_trusted = bool(key_info["trusted"])
    ...

    if crypto_valid and is_trusted:
        return True, True, "Signature is valid and signing key is trusted", None
    elif crypto_valid and not is_trusted:
        return True, False, "Signature is cryptographically valid but signing key has been revoked", revoked_at
    else:
        return False, False, "Signature verification failed", None
```

## Shared — Audit Trail

All services share an audit trail. Every action is recorded in a SHA-256 hash chain where each entry links to the previous. The platform counter-signs each entry with its Ed25519 key as a neutral witness.

1. Recording an audit event. Computes the hash chain link and counter signs it with the platform key.

```
def record_event(db, event_type, event_data, actor_user_id=None, ...):
    # Get previous entry's hash (or genesis "000...000")
    last_entry = db.query(AuditTrail).order_by(AuditTrail.entry_id.desc()).first()
    prev_hash = last_entry.event_hash if last_entry else GENESIS_HASH

    # Compute chain link: SHA-256(prev_hash | event_type | event_data | timestamp)
    event_hash = _compute_event_hash(prev_hash, event_type, event_data_json, timestamp_str)

    # Platform counter-signs with Ed25519
    platform_sig, platform_key_id = _sign_hash(event_hash)

    entry = AuditTrail(
        event_type=event_type, event_data=event_data_json,
        event_hash=event_hash, prev_hash=prev_hash,
        platform_signature=platform_sig, platform_key_id=platform_key_id,
        timestamp=now, ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
```

2. Verifying the chain. Goes through every entry from the start, recomputes each hash, and checks the platform counter signatures.

```
def verify_chain(db: Session) -> dict:
    entries = db.query(AuditTrail).order_by(AuditTrail.entry_id.asc()).all()
    expected_prev = GENESIS_HASH

    for entry in entries:
        # Check prev_hash links correctly
        if entry.prev_hash != expected_prev:
            return {"valid": False, "error": f"Entry {entry.entry_id}: prev_hash mismatch"}

        # Recompute event_hash and verify
        computed_hash = _compute_event_hash(
            entry.prev_hash, entry.event_type, entry.event_data, timestamp_str
        )
        if computed_hash != entry.event_hash:
            return {"valid": False, "error": f"Entry {entry.entry_id}: data tampered"}

        # Verify platform counter-signature
        if entry.platform_signature and platform_pub_key:
            sig_bytes = base64.b64decode(entry.platform_signature)
            platform_pub_key.verify(sig_bytes, bytes.fromhex(entry.event_hash))

        expected_prev = entry.event_hash

    return {"valid": True, "total_entries": len(entries), "verified_entries": len(entries)}
```
