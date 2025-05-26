import uuid
from datetime import datetime
from flask import request
from supabase_client.supabaseClient import supabase, supabase_create_client
#from passwords.password_hasher import hash_password  # ✅ New import for hashing
from security_protocols.passwords.password_hasher import hash_password
from security_protocols.passwords.password_hasher import hash_password
from security_protocols.passwords.hibp_checker import check_pwned_password  # ✅ Added for HIBP breach checking

from security_protocols.jwt.auth import jwt_required
from security_protocols.mfa.mfa import mfa_required


# Step 1: Create an invite token
@jwt_required
@mfa_required
def create_invite_token(email: str, role: str) -> str:
    token = str(uuid.uuid4())
    user_id = request.headers.get("X-User-ID")

    response = supabase.table("invite_tokens").insert({
        "email": email,
        "role": role,
        "token": token,
        "used": False,
        "created_at": datetime.utcnow().isoformat(),
        "user_id": user_id
    }).execute()

    if hasattr(response, 'error') and response.error:
        raise Exception(f"Failed to store invite token: {response.error.message}")

    return token


# Step 2: Verify the invite token
@jwt_required
@mfa_required
def verify_invite_token(token: str):
    response = supabase.table("invite_tokens").select("*").eq("token", token).eq("used", False).execute()
    if not response.data:
        return None
    return response.data[0]


# Step 3: Complete registration with Supabase Auth
@jwt_required
@mfa_required
def complete_registration(token: str, password: str):
    from security_protocols.passwords.password_policy import enforce_password_policy
    
    invite = verify_invite_token(token)
    if not invite:
        raise Exception("Invalid or expired invite token")

    email = invite['email']
    role = invite['role']
    
    try:
        enforce_password_policy(password)
    except ValueError as e:
        raise Exception(str(e))

    try:
        # Create Auth user - let Supabase handle password hashing
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password
        })

        if not auth_response.user:
            error_msg = auth_response.error.message if auth_response.error else "Unknown auth error"
            raise Exception(f"Auth registration failed: {error_msg}")

        # Insert into users table WITHOUT local password hash
        user_response = supabase.table("users").insert({
            "id": auth_response.user.id,
            "email": email,
            "role": role,
            # Remove this line: "hashed_pw": hashed_pw,
            "created_at": datetime.utcnow().isoformat(),
        }).execute()

        if not user_response.data:
            raise Exception("Failed to create user profile in database")

        mark_token_used(token)

        return {
            "success": True,
            "user_id": auth_response.user.id,
            "email": email,
            "role": role
        }

    except Exception as e:
        if 'auth_response' in locals() and auth_response.user:
            try:
                supabase.auth.admin.delete_user(auth_response.user.id)
            except Exception as cleanup_error:
                print(f"Cleanup failed: {cleanup_error}")

        raise Exception(f"Registration failed: {str(e)}") from e
@jwt_required
@mfa_required
def register_user(email: str, name: str, role: str, jwt_token: str):
    scoped_client = supabase_create_client(supabase_key=jwt_token)


    response = scoped_client.table("users").insert({
        "email": email,
        "name": name,
        "role": role
    }).execute()

    if hasattr(response, "error") and response.error:
        raise Exception("Failed to insert user")

    return True


# Step 5: Mark invite as used (manual)
@jwt_required
@mfa_required
def mark_token_used(token: str):
    response = supabase.table("invite_tokens").update({"used": True}).eq("token", token).execute()

    if hasattr(response, "error") and response.error:
        raise Exception("Failed to mark invite as used")

    return True